// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors

use std::collections::BTreeMap;

use serde::Deserialize;

use grdr_model::CodedError;
use grdr_ports::{BusMessage, CODE_BUS_IO};

use crate::config::decode_subject_token;
use crate::config::encode_subject_token;
use crate::wire_codec::header_ci;

#[derive(Debug, Clone)]
pub(crate) struct JetStreamPullResult {
    pub(crate) messages: Vec<BusMessage>,
    pub(crate) ack_subjects: Vec<(u64, String)>,
}

#[derive(Debug, Default, Deserialize)]
pub(crate) struct JsApiErrorEnvelope {
    #[serde(default)]
    pub(crate) error: Option<JsApiError>,
}

#[derive(Debug, Default, Deserialize)]
pub(crate) struct JsApiError {
    #[serde(default)]
    pub(crate) code: u16,
    #[serde(default)]
    pub(crate) description: String,
}

#[derive(Debug, Default, Deserialize)]
pub(crate) struct JsPubAck {
    #[serde(default)]
    pub(crate) seq: u64,
    #[serde(default)]
    pub(crate) error: Option<JsApiError>,
}

#[derive(Debug, Default, Deserialize)]
pub(crate) struct JsStreamInfoResp {
    #[serde(default)]
    pub(crate) state: JsStreamState,
    #[serde(default)]
    pub(crate) error: Option<JsApiError>,
}

#[derive(Debug, Default, Deserialize)]
pub(crate) struct JsStreamState {
    #[serde(default)]
    pub(crate) messages: u64,
    #[serde(default)]
    pub(crate) last_seq: u64,
}

#[derive(Debug, Default, Deserialize)]
pub(crate) struct JsConsumerInfoResp {
    #[serde(default)]
    pub(crate) ack_floor: JsSequencePair,
    #[serde(default)]
    pub(crate) num_pending: u64,
    #[serde(default)]
    pub(crate) num_ack_pending: u64,
    #[serde(default)]
    pub(crate) error: Option<JsApiError>,
}

#[derive(Debug, Default, Deserialize)]
pub(crate) struct JsSequencePair {
    #[serde(default)]
    pub(crate) stream_seq: u64,
}

pub(crate) fn durable_consumer_name(consumer_group: &str, partition: u32) -> String {
    format!("{}_p{partition}", encode_subject_token(consumer_group))
}

pub(crate) fn parse_ack_stream_seq(ack_subject: &str) -> Option<u64> {
    if !ack_subject.starts_with("$JS.ACK.") {
        return None;
    }
    let mut rev = ack_subject.rsplit('.');
    let _pending = rev.next()?;
    let _ts = rev.next()?;
    let _consumer_seq = rev.next()?;
    let stream_seq = rev.next()?;
    stream_seq.parse::<u64>().ok()
}

pub(crate) fn resolve_org_from_msg(
    subject: &str,
    headers: &BTreeMap<String, String>,
) -> Result<String, CodedError> {
    let parts: Vec<&str> = subject.split('.').collect();
    let subj_org = match parts.as_slice() {
        ["grdr", enc_org, _stream, _part] => decode_subject_token(enc_org).ok_or_else(|| {
            CodedError::new(
                CODE_BUS_IO,
                format!("Malformed encoded tenant token in NATS subject `{subject}`."),
                "Publish strictly via canonical grdr.<org>.<stream>.p<partition> subjects.",
            )
        })?,
        _ => {
            return Err(CodedError::new(
                CODE_BUS_IO,
                format!("NATS message on `{subject}` did not match tenant subject format."),
                "Publish strictly via grdr.<org>.<stream>.p<partition> subjects.",
            ));
        }
    };

    if let Some(hdr_org) = header_ci(headers, "x-grdr-org-id")? {
        let trimmed = hdr_org.trim();
        if trimmed.is_empty() || trimmed != subj_org {
            return Err(CodedError::new(
                CODE_BUS_IO,
                format!(
                    "NATS tenant mismatch between subject `{subj_org}` and x-grdr-org-id `{trimmed}`."
                ),
                "Reject messages whose x-grdr-org-id header disagrees with subject tenant.",
            ));
        }
    }
    Ok(subj_org)
}
