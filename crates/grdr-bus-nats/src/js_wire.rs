// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors

use std::collections::BTreeSet;

use grdr_model::CodedError;
use grdr_ports::{
    BusAppendMessage, BusLag, BusMessage, BusOffsetRange, OrgId, SingleCtx, TenantCtx,
};

use crate::config::{CODE_NATS_WIRE, JetStreamStreamSpec, encode_subject_token};
use crate::js_api::{
    JetStreamPullResult, JsApiErrorEnvelope, JsConsumerInfoResp, JsPubAck, JsStreamInfoResp,
    durable_consumer_name, parse_ack_stream_seq, resolve_org_from_msg,
};
use crate::wire::NatsWireConnection;
use crate::wire_codec::{
    NatsInboundFrame, NatsInboundMessage, encode_hpub_with_reply, encode_pub_cmd,
    encode_stream_create_payload, header_ci, jetstream_stream_create_subject,
    strip_reserved_grdr_headers,
};

const MAX_PULL_WAIT_FRAMES: usize = 4_096;

pub(crate) struct JsPullParams<'a> {
    pub(crate) spec: &'a JetStreamStreamSpec,
    pub(crate) consumer_group: &'a str,
    pub(crate) stream: &'a str,
    pub(crate) partition: u32,
    pub(crate) ctx: Option<&'a TenantCtx>,
    pub(crate) after_offset: Option<u64>,
    pub(crate) limit: usize,
}

struct NamedPullArgs<'a> {
    spec: &'a JetStreamStreamSpec,
    consumer_name: &'a str,
    stream: &'a str,
    partition: u32,
    ctx: Option<&'a TenantCtx>,
    after_offset: Option<u64>,
    limit: usize,
}

pub(crate) fn ensure_js_stream(
    conn: &mut NatsWireConnection,
    spec: &JetStreamStreamSpec,
) -> Result<(), CodedError> {
    let info_subj = format!("$JS.API.STREAM.INFO.{}", spec.stream_name);
    let reply = conn.request(&info_subj, b"")?;
    let info: JsApiErrorEnvelope = serde_json::from_slice(&reply.payload).unwrap_or_default();
    if let Some(err) = info.error {
        if err.code == 404 {
            let create_subj = jetstream_stream_create_subject(&spec.stream_name);
            let create_body = encode_stream_create_payload(spec)?;
            let create_reply = conn.request(&create_subj, &create_body)?;
            let create_env: JsApiErrorEnvelope =
                serde_json::from_slice(&create_reply.payload).unwrap_or_default();
            if let Some(cerr) = create_env.error {
                return Err(CodedError::new(
                    CODE_NATS_WIRE,
                    format!(
                        "JetStream stream creation failed ({}): {}",
                        cerr.code, cerr.description
                    ),
                    "Verify JetStream stream configuration and storage limits.",
                ));
            }
        } else {
            return Err(CodedError::new(
                CODE_NATS_WIRE,
                format!(
                    "JetStream stream info failed ({}): {}",
                    err.code, err.description
                ),
                "Verify JetStream stream configuration.",
            ));
        }
    }
    Ok(())
}

pub(crate) fn publish_js_batch(
    conn: &mut NatsWireConnection,
    spec: &JetStreamStreamSpec,
    ctx: &SingleCtx,
    subject: &str,
    prepared: &[(String, &BusAppendMessage)],
    now_ms: i64,
) -> Result<BusOffsetRange, CodedError> {
    ensure_js_stream(conn, spec)?;
    let mut first_seq: Option<u64> = None;
    let mut last_seq: Option<u64> = None;

    for (msg_id, msg) in prepared {
        let mut headers = strip_reserved_grdr_headers(&msg.headers);
        headers.insert(
            "x-grdr-org-id".into(),
            ctx.organisation_id().as_str().to_string(),
        );
        if let Some(del_id) = ctx.delegation_id() {
            headers.insert("x-grdr-delegation-id".into(), del_id.to_string());
        }
        if let Some(del_epoch) = ctx.delegation_epoch() {
            headers.insert("x-grdr-delegation-epoch".into(), del_epoch.to_string());
        }
        headers.insert("x-grdr-key".into(), msg.key.clone());
        headers.insert("x-grdr-appended-ms".into(), now_ms.to_string());

        let sid = conn.next_sid();
        let inbox = format!("_INBOX.grdr.pub.{sid}");
        let sub_cmd = format!("SUB {inbox} {sid}\r\nUNSUB {sid} 1\r\n");
        conn.write_bytes(sub_cmd.as_bytes())?;
        let hpub = encode_hpub_with_reply(subject, Some(&inbox), msg_id, &headers, &msg.payload)?;
        conn.write_all_flushed(&hpub)?;

        let ack_msg = await_inbox_reply(conn, &sid, subject)?;
        let ack: JsPubAck = serde_json::from_slice(&ack_msg.payload).map_err(|e| {
            CodedError::new(
                CODE_NATS_WIRE,
                format!("Invalid JetStream PubAck payload: {e}"),
                "Verify NATS JetStream cluster health.",
            )
        })?;
        if let Some(err) = ack.error {
            return Err(CodedError::new(
                CODE_NATS_WIRE,
                format!(
                    "JetStream publish rejected ({}): {}",
                    err.code, err.description
                ),
                "Inspect stream quotas and subject configuration.",
            ));
        }
        let offset = ack.seq.saturating_sub(1);
        first_seq.get_or_insert(offset);
        last_seq = Some(offset);
    }

    Ok(BusOffsetRange {
        first_offset: first_seq.unwrap_or(0),
        last_offset: last_seq.unwrap_or(0),
    })
}

pub(crate) fn ensure_js_consumer(
    conn: &mut NatsWireConnection,
    spec: &JetStreamStreamSpec,
    consumer_group: &str,
    stream: &str,
    partition: u32,
) -> Result<String, CodedError> {
    let durable = durable_consumer_name(consumer_group, partition);
    let clean_stream = encode_subject_token(stream);
    let filter_subject = format!("grdr.*.{clean_stream}.p{partition}");
    create_js_consumer(conn, spec, &durable, &filter_subject, None, true)?;
    Ok(durable)
}

fn create_js_consumer(
    conn: &mut NatsWireConnection,
    spec: &JetStreamStreamSpec,
    consumer_name: &str,
    filter_subject: &str,
    start_seq: Option<u64>,
    durable: bool,
) -> Result<(), CodedError> {
    ensure_js_stream(conn, spec)?;
    let create_subj = format!(
        "$JS.API.CONSUMER.CREATE.{}.{consumer_name}",
        spec.stream_name
    );
    let mut cfg = serde_json::Map::new();
    if durable {
        cfg.insert("durable_name".into(), serde_json::json!(consumer_name));
    } else {
        cfg.insert(
            "inactive_threshold".into(),
            serde_json::json!(10_000_000_000u64),
        );
    }
    if let Some(seq) = start_seq {
        cfg.insert(
            "deliver_policy".into(),
            serde_json::json!("by_start_sequence"),
        );
        cfg.insert("opt_start_seq".into(), serde_json::json!(seq.max(1)));
    } else {
        cfg.insert("deliver_policy".into(), serde_json::json!("all"));
    }
    cfg.insert("ack_policy".into(), serde_json::json!("explicit"));
    cfg.insert("replay_policy".into(), serde_json::json!("instant"));
    cfg.insert("filter_subject".into(), serde_json::json!(filter_subject));
    cfg.insert("max_ack_pending".into(), serde_json::json!(1024));
    let payload = serde_json::json!({
        "stream_name": spec.stream_name,
        "config": cfg,
    });
    let body = serde_json::to_vec(&payload).map_err(|e| {
        CodedError::new(
            CODE_NATS_WIRE,
            format!("Failed encoding JetStream consumer create request: {e}"),
            "Check consumer configuration.",
        )
    })?;
    let reply = conn.request(&create_subj, &body)?;
    let env: JsApiErrorEnvelope = serde_json::from_slice(&reply.payload).unwrap_or_default();
    if let Some(err) = env.error {
        return Err(CodedError::new(
            CODE_NATS_WIRE,
            format!(
                "JetStream consumer create failed ({}): {}",
                err.code, err.description
            ),
            "Verify JetStream stream and consumer permissions.",
        ));
    }
    Ok(())
}

pub(crate) fn pull_js_messages(
    conn: &mut NatsWireConnection,
    params: &JsPullParams<'_>,
) -> Result<JetStreamPullResult, CodedError> {
    let spec = params.spec;
    let stream = params.stream;
    let partition = params.partition;
    let after_offset = params.after_offset;
    let limit = params.limit;

    if let Some(tenant_ctx) = params.ctx {
        let orgs = tenant_ctx.organisation_ids();
        if orgs.is_empty() {
            return Ok(JetStreamPullResult {
                messages: Vec::new(),
                ack_subjects: Vec::new(),
            });
        }
        let clean_stream = encode_subject_token(stream);
        let start_seq = after_offset.map_or(1, |off| off.saturating_add(2));
        let mut combined_msgs = Vec::new();
        let mut seen_offsets = BTreeSet::new();

        for org in orgs {
            let ephemeral = format!("grdr_fetch_{}", conn.next_sid());
            let filter = format!(
                "grdr.{}.{clean_stream}.p{partition}",
                encode_subject_token(org.as_str())
            );
            create_js_consumer(conn, spec, &ephemeral, &filter, Some(start_seq), false)?;
            let pull_res = pull_from_named_consumer(
                conn,
                &NamedPullArgs {
                    spec,
                    consumer_name: &ephemeral,
                    stream,
                    partition,
                    ctx: Some(tenant_ctx),
                    after_offset,
                    limit,
                },
            );
            let del_subj = format!("$JS.API.CONSUMER.DELETE.{}.{ephemeral}", spec.stream_name);
            let _ = conn.request(&del_subj, b"");
            let org_res = pull_res?;
            for msg in org_res.messages {
                if seen_offsets.insert(msg.offset) {
                    combined_msgs.push(msg);
                }
            }
        }
        combined_msgs.sort_by_key(|m| m.offset);
        combined_msgs.truncate(limit);
        return Ok(JetStreamPullResult {
            messages: combined_msgs,
            ack_subjects: Vec::new(),
        });
    }

    let durable = ensure_js_consumer(conn, spec, params.consumer_group, stream, partition)?;
    pull_from_named_consumer(
        conn,
        &NamedPullArgs {
            spec,
            consumer_name: &durable,
            stream,
            partition,
            ctx: None,
            after_offset,
            limit,
        },
    )
}

fn pull_from_named_consumer(
    conn: &mut NatsWireConnection,
    args: &NamedPullArgs<'_>,
) -> Result<JetStreamPullResult, CodedError> {
    let sid = conn.next_sid();
    let inbox = format!("_INBOX.grdr.pull.{sid}");
    conn.write_bytes(format!("SUB {inbox} {sid}\r\n").as_bytes())?;

    let next_subj = format!(
        "$JS.API.CONSUMER.MSG.NEXT.{}.{}",
        args.spec.stream_name, args.consumer_name
    );
    let req_json = serde_json::json!({
        "batch": args.limit.max(1),
        "no_wait": true,
    });
    let req_bytes = serde_json::to_vec(&req_json).unwrap_or_else(|_| b"{}".to_vec());
    let pub_cmd = encode_pub_cmd(&next_subj, Some(&inbox), &req_bytes)?;
    conn.write_all_flushed(&pub_cmd)?;

    let mut messages = Vec::new();
    let mut ack_subjects = Vec::new();
    let mut completed = false;

    for _ in 0..MAX_PULL_WAIT_FRAMES {
        if messages.len() >= args.limit {
            completed = true;
            break;
        }
        match conn.read_frame()? {
            NatsInboundFrame::Ok | NatsInboundFrame::Pong => continue,
            NatsInboundFrame::Ping => conn.write_all_flushed(b"PONG\r\n")?,
            NatsInboundFrame::Err(err) => {
                let _ = conn.write_all_flushed(format!("UNSUB {sid}\r\n").as_bytes());
                return Err(CodedError::new(
                    CODE_NATS_WIRE,
                    format!("JetStream pull failed: {err}"),
                    "Verify JetStream pull consumer state.",
                ));
            }
            NatsInboundFrame::Msg(msg) => {
                if msg.sid != sid {
                    continue;
                }
                if matches!(msg.status_code, Some(404 | 408 | 409)) {
                    completed = true;
                    break;
                }
                if let Some(code) = msg.status_code
                    && code >= 400
                {
                    let _ = conn.write_all_flushed(format!("UNSUB {sid}\r\n").as_bytes());
                    return Err(CodedError::new(
                        CODE_NATS_WIRE,
                        format!("JetStream pull returned status {code}."),
                        "Inspect JetStream pull consumer.",
                    ));
                }
                let seq = msg
                    .reply_to
                    .as_deref()
                    .and_then(parse_ack_stream_seq)
                    .unwrap_or_else(|| {
                        u64::try_from(messages.len().saturating_add(1)).unwrap_or(1)
                    });
                let offset = seq.saturating_sub(1);
                if let Some(reply_subj) = msg.reply_to.clone() {
                    ack_subjects.push((offset, reply_subj));
                }
                if args.after_offset.is_some_and(|prev| offset <= prev) {
                    continue;
                }
                let org_raw = resolve_org_from_msg(&msg.subject, &msg.headers)?;
                let org_id = OrgId::new(org_raw)?;
                if let Some(tenant_ctx) = args.ctx
                    && !tenant_ctx.contains(&org_id)
                {
                    continue;
                }
                let delegation_id =
                    header_ci(&msg.headers, "x-grdr-delegation-id")?.map(ToString::to_string);
                let delegation_epoch = header_ci(&msg.headers, "x-grdr-delegation-epoch")?
                    .and_then(|s| s.parse::<u64>().ok());
                let key = header_ci(&msg.headers, "x-grdr-key")?
                    .map_or_else(|| msg.subject.clone(), ToString::to_string);
                let appended_at_ms = header_ci(&msg.headers, "x-grdr-appended-ms")?
                    .and_then(|s| s.parse::<i64>().ok())
                    .unwrap_or(0);

                messages.push(BusMessage {
                    stream: args.stream.to_string(),
                    partition: args.partition,
                    offset,
                    organisation_id: org_id,
                    delegation_id,
                    delegation_epoch,
                    key,
                    headers: msg.headers,
                    payload: msg.payload,
                    appended_at_ms,
                });
            }
        }
    }

    conn.write_all_flushed(format!("UNSUB {sid}\r\n").as_bytes())?;
    conn.drain_until_pong(&sid)?;
    if !completed {
        return Err(CodedError::new(
            CODE_NATS_WIRE,
            format!("JetStream pull exceeded {MAX_PULL_WAIT_FRAMES} frames without completion."),
            "Inspect JetStream server responsiveness or reduce pull batch size.",
        ));
    }
    Ok(JetStreamPullResult {
        messages,
        ack_subjects,
    })
}

pub(crate) fn ack_js_message(
    conn: &mut NatsWireConnection,
    ack_subject: &str,
) -> Result<(), CodedError> {
    let ack_cmd = encode_pub_cmd(ack_subject, None, b"+ACK")?;
    conn.write_bytes(&ack_cmd)?;
    conn.ping_pong()
}

pub(crate) fn query_js_head_offset(
    conn: &mut NatsWireConnection,
    spec: &JetStreamStreamSpec,
) -> Result<Option<u64>, CodedError> {
    let info_subj = format!("$JS.API.STREAM.INFO.{}", spec.stream_name);
    let reply = conn.request(&info_subj, b"")?;
    let info: JsStreamInfoResp = serde_json::from_slice(&reply.payload).map_err(|e| {
        CodedError::new(
            CODE_NATS_WIRE,
            format!("Invalid JetStream STREAM.INFO response: {e}"),
            "Check JetStream cluster status.",
        )
    })?;
    if let Some(err) = info.error {
        if err.code == 404 {
            return Ok(None);
        }
        return Err(CodedError::new(
            CODE_NATS_WIRE,
            format!(
                "JetStream STREAM.INFO failed ({}): {}",
                err.code, err.description
            ),
            "Inspect JetStream stream state.",
        ));
    }
    if info.state.messages == 0 || info.state.last_seq == 0 {
        Ok(None)
    } else {
        Ok(Some(info.state.last_seq.saturating_sub(1)))
    }
}

pub(crate) fn query_js_lag(
    conn: &mut NatsWireConnection,
    spec: &JetStreamStreamSpec,
    consumer_group: &str,
    stream: &str,
    partition: u32,
) -> Result<BusLag, CodedError> {
    let head_offset = query_js_head_offset(conn, spec)?;
    let durable = durable_consumer_name(consumer_group, partition);
    let cons_subj = format!("$JS.API.CONSUMER.INFO.{}.{}", spec.stream_name, durable);
    let reply = conn.request(&cons_subj, b"")?;
    let info: JsConsumerInfoResp = serde_json::from_slice(&reply.payload).unwrap_or_default();
    let committed_offset = if info.error.is_none() && info.ack_floor.stream_seq > 0 {
        Some(info.ack_floor.stream_seq.saturating_sub(1))
    } else {
        None
    };
    let pending_messages =
        if info.error.is_none() && (info.num_pending > 0 || info.num_ack_pending > 0) {
            info.num_pending.saturating_add(info.num_ack_pending)
        } else {
            match (head_offset, committed_offset) {
                (None, _) => 0,
                (Some(head), None) => head.saturating_add(1),
                (Some(head), Some(comm)) => head.saturating_sub(comm),
            }
        };
    Ok(BusLag {
        stream: stream.to_string(),
        partition,
        head_offset,
        committed_offset,
        pending_messages,
    })
}

fn await_inbox_reply(
    conn: &mut NatsWireConnection,
    sid: &str,
    context: &str,
) -> Result<NatsInboundMessage, CodedError> {
    for _ in 0..MAX_PULL_WAIT_FRAMES {
        match conn.read_frame()? {
            NatsInboundFrame::Ok | NatsInboundFrame::Pong => continue,
            NatsInboundFrame::Ping => conn.write_all_flushed(b"PONG\r\n")?,
            NatsInboundFrame::Err(err) => {
                return Err(CodedError::new(
                    CODE_NATS_WIRE,
                    format!("NATS error during `{context}`: {err}"),
                    "Check JetStream stream permissions.",
                ));
            }
            NatsInboundFrame::Msg(msg) => {
                if msg.sid == sid {
                    return Ok(msg);
                }
            }
        }
    }
    Err(CodedError::new(
        CODE_NATS_WIRE,
        format!("Timed out waiting for JetStream reply on `{context}`."),
        "Verify NATS JetStream cluster responsiveness.",
    ))
}
