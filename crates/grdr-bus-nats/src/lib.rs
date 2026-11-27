// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors
#![forbid(unsafe_code)]
#![deny(clippy::arithmetic_side_effects)]

mod bus;
mod bus_mem;
pub mod config;
mod js_api;
mod js_wire;
pub mod nkey;
mod tls;
pub mod wire;
pub mod wire_codec;

pub use bus::NatsJetStreamBus;
pub use config::{
    CODE_NATS_CONFIG, CODE_NATS_IO, CODE_NATS_STREAM_FULL, CODE_NATS_WIRE, JetStreamStreamSpec,
    ListenerPolicy, NatsAuthConfig, NatsConfig, NatsDiscardPolicy, NatsListenerGuard,
    NatsTlsHandshake, NatsTransportMode, jetstream_stream_name, subject_for,
};
pub use nkey::{NKeyCredentialBundle, encode_user_seed, parse_nats_creds, public_nkey_from_seed};
pub use wire_codec::NatsWireState;

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;
    use std::io::{BufRead, BufReader, Read, Write};
    use std::net::TcpListener;
    use std::thread;

    use grdr_ports::{BusAppendMessage, BusPort, CODE_BUS_INVALID_INPUT, OrgId, SingleCtx};

    use super::*;

    #[test]
    fn nats_jetstream_embedded_passes_bus_port_contract() {
        let bus = NatsJetStreamBus::open_embedded().unwrap();
        grdr_ports_testkit::assert_bus_port_contract(&bus).unwrap();
    }

    #[test]
    fn nats_subject_naming_stream_specs_and_listener_guard() {
        let org_dot = OrgId::new("org.nats.1").unwrap();
        let org_under = OrgId::new("org_nats_1").unwrap();
        assert_eq!(
            subject_for(&org_dot, "events", 9),
            "grdr.org_2enats_2e1.events.p9"
        );
        assert_eq!(
            subject_for(&org_under, "events", 9),
            "grdr.org_5fnats_5f1.events.p9"
        );
        assert_ne!(
            subject_for(&org_dot, "events", 9),
            subject_for(&org_under, "events", 9)
        );
        assert_eq!(jetstream_stream_name("events", 9), "GRDR_EVENTS_1");
        assert_eq!(jetstream_stream_name("decision", 0), "GRDR_DECISION");

        assert_eq!(
            NatsConfig::parse_url("nats://nats.prod.internal:4222")
                .unwrap_err()
                .code,
            CODE_NATS_CONFIG
        );
        let mut mutated_url = NatsConfig::parse_url("tls://nats.prod.internal:4222").unwrap();
        mutated_url.transport = NatsTransportMode::JetStreamTcp {
            server_url: "nats://10.0.0.8:4222".into(),
        };
        assert_eq!(mutated_url.validate().unwrap_err().code, CODE_NATS_CONFIG);

        for bad_mutator in [
            |g: &mut NatsListenerGuard| g.mqtt = ListenerPolicy::Enabled,
            |g: &mut NatsListenerGuard| g.leafnode = ListenerPolicy::Enabled,
            |g: &mut NatsListenerGuard| g.websocket = ListenerPolicy::Enabled,
        ] {
            let mut bad_cfg = NatsConfig::embedded_default();
            bad_mutator(&mut bad_cfg.listener_guard);
            let err = NatsJetStreamBus::connect(bad_cfg).unwrap_err();
            assert_eq!(err.code, CODE_NATS_CONFIG);
        }

        let cfg = NatsConfig::embedded_default();
        let spec = cfg.stream_spec("events", 3);
        assert_eq!(spec.stream_name, "GRDR_EVENTS_3");
        assert_eq!(spec.discard_policy, NatsDiscardPolicy::New);
        let payload = wire::encode_stream_create_payload(&spec).unwrap();
        assert!(String::from_utf8_lossy(&payload).contains("GRDR_EVENTS_3"));
    }

    #[test]
    fn nats_wire_hpub_roundtrip_and_dedup_against_mock_tcp_listener() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();

        let server = thread::spawn(move || {
            let (mut sock, _) = listener.accept().unwrap();
            sock.write_all(
                b"INFO {\"server_id\":\"mock\",\"version\":\"2.15.2\",\"jetstream\":true,\"headers\":true}\r\n",
            )
            .unwrap();
            let mut reader = BufReader::new(sock.try_clone().unwrap());
            let mut connect_line = String::new();
            reader.read_line(&mut connect_line).unwrap();
            assert!(connect_line.starts_with("CONNECT "));

            let mut ping = String::new();
            reader.read_line(&mut ping).unwrap();
            assert_eq!(ping.trim(), "PING");
            sock.write_all(b"PONG\r\n").unwrap();

            let mut sids = BTreeMap::new();
            let mut line = String::new();
            while reader.read_line(&mut line).is_ok_and(|n| n > 0) {
                let trimmed = line.trim_end_matches(['\r', '\n']);
                if let Some(rest) = trimmed.strip_prefix("SUB ") {
                    let mut it = rest.split_whitespace();
                    if let (Some(subj), Some(sid)) = (it.next(), it.next()) {
                        sids.insert(subj.to_string(), sid.to_string());
                    }
                } else if let Some(rest) = trimmed.strip_prefix("PUB ") {
                    let parts: Vec<&str> = rest.split_whitespace().collect();
                    let (subj, reply, len) = match parts.as_slice() {
                        [s, r, l] => (*s, Some(*r), l.parse::<usize>().unwrap()),
                        [s, l] => (*s, None, l.parse::<usize>().unwrap()),
                        _ => break,
                    };
                    let mut payload = vec![0u8; len + 2];
                    reader.read_exact(&mut payload).unwrap();
                    if subj.starts_with("$JS.API.STREAM.INFO.")
                        && let Some(r_subj) = reply
                        && let Some(sid) = sids.get(r_subj)
                    {
                        let resp = br#"{"config":{"name":"GRDR_EVENTS_2"},"state":{"messages":0,"last_seq":0}}"#;
                        let hdr = format!("MSG {r_subj} {sid} {}\r\n", resp.len());
                        sock.write_all(hdr.as_bytes()).unwrap();
                        sock.write_all(resp).unwrap();
                        sock.write_all(b"\r\n").unwrap();
                        sock.flush().unwrap();
                    }
                } else if let Some(rest) = trimmed.strip_prefix("HPUB ") {
                    assert!(rest.starts_with("grdr.org-wire.events.p2 "));
                    let parts: Vec<&str> = rest.split_whitespace().collect();
                    let (reply, total_len) = match parts.as_slice() {
                        [_s, r, _h, t] => (*r, t.parse::<usize>().unwrap()),
                        _ => break,
                    };
                    let mut body = vec![0u8; total_len + 2];
                    reader.read_exact(&mut body).unwrap();
                    let body_str = String::from_utf8_lossy(&body);
                    assert_eq!(body_str.matches("Nats-Msg-Id:").count(), 1);
                    assert!(body_str.contains("Nats-Msg-Id: msg-dedup-1"));
                    assert!(body_str.contains("wire-payload"));
                    if let Some(sid) = sids.get(reply) {
                        let ack = br#"{"stream":"GRDR_EVENTS_2","seq":1}"#;
                        let hdr = format!("MSG {reply} {sid} {}\r\n", ack.len());
                        sock.write_all(hdr.as_bytes()).unwrap();
                        sock.write_all(ack).unwrap();
                        sock.write_all(b"\r\n").unwrap();
                        sock.flush().unwrap();
                    }
                } else if trimmed == "PING" {
                    sock.write_all(b"PONG\r\n").unwrap();
                }
                line.clear();
            }
        });

        let cfg = NatsConfig::parse_url(&format!("nats://{addr}")).unwrap();
        let bus = NatsJetStreamBus::connect(cfg).unwrap();
        let org = OrgId::new("org-wire").unwrap();
        let ctx = SingleCtx::new(org);
        let mut headers = BTreeMap::new();
        headers.insert("Nats-Msg-Id".into(), "msg-dedup-1".into());
        let msg = BusAppendMessage {
            key: "dev-9".into(),
            headers,
            payload: b"wire-payload".to_vec(),
        };
        let range = bus
            .append(&ctx, "events", 2, std::slice::from_ref(&msg), 1_000)
            .unwrap();
        assert_eq!(range.first_offset, 0);
        assert_eq!(range.last_offset, 0);

        // Re-sending all-duplicate batch must not hit wire or return out-of-range offset.
        let dup_range = bus.append(&ctx, "events", 2, &[msg], 1_001).unwrap();
        assert_eq!(dup_range.first_offset, 0);
        assert_eq!(dup_range.last_offset, 0);

        let hist = bus.subject_history("events", 2).unwrap();
        assert_eq!(hist[0].0, "grdr.org-wire.events.p2");
        drop(bus);
        server.join().unwrap();
    }

    #[test]
    fn nats_adversarial_injection_tls_and_capacity_guards() {
        for bad_subject in ["grdr.*.events.p0", "grdr.org.>", "grdr.org.ev\r\n", "a b"] {
            let err = wire::encode_hpub_cmd(bad_subject, "m1", &BTreeMap::new(), b"x").unwrap_err();
            assert_eq!(err.code, CODE_NATS_WIRE);
        }

        let crlf_err = wire::encode_hpub_cmd(
            "grdr.org.events.p0",
            "id\r\nInjected: yes",
            &BTreeMap::new(),
            b"x",
        )
        .unwrap_err();
        assert_eq!(crlf_err.code, CODE_NATS_WIRE);

        let mut bad_hdrs = BTreeMap::new();
        bad_hdrs.insert("X-Evil".into(), "val\r\nEvil: 1".into());
        assert_eq!(
            wire::encode_hpub_cmd("grdr.org.events.p0", "id1", &bad_hdrs, b"x")
                .unwrap_err()
                .code,
            CODE_NATS_WIRE
        );

        let tls_cfg = NatsConfig::parse_url("tls://127.0.0.1:4222").unwrap();
        let tls_bus = NatsJetStreamBus::connect(tls_cfg).unwrap();
        let ctx = SingleCtx::new(OrgId::new("org-tls").unwrap());
        let tls_err = tls_bus
            .append(
                &ctx,
                "events",
                0,
                &[BusAppendMessage {
                    key: "k".into(),
                    headers: BTreeMap::new(),
                    payload: b"hello".to_vec(),
                }],
                1_000,
            )
            .unwrap_err();
        assert_eq!(tls_err.code, CODE_NATS_WIRE);

        let crlf_key_err = tls_bus
            .append(
                &ctx,
                "events",
                0,
                &[BusAppendMessage {
                    key: "bad\r\nkey".into(),
                    headers: BTreeMap::new(),
                    payload: b"hello".to_vec(),
                }],
                1_000,
            )
            .unwrap_err();
        assert_eq!(crlf_key_err.code, CODE_BUS_INVALID_INPUT);

        let mut cap_cfg = NatsConfig::parse_url("nats://127.0.0.1:1").unwrap();
        cap_cfg.max_bytes_per_stream = 4;
        let cap_bus = NatsJetStreamBus::connect(cap_cfg).unwrap();
        let full_err = cap_bus
            .append(
                &ctx,
                "events",
                0,
                &[BusAppendMessage {
                    key: "k".into(),
                    headers: BTreeMap::new(),
                    payload: b"12345".to_vec(),
                }],
                1_000,
            )
            .unwrap_err();
        assert_eq!(full_err.code, CODE_NATS_STREAM_FULL);

        // Server returning -ERR must fail wire publish.
        let err_listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let err_addr = err_listener.local_addr().unwrap();
        let err_srv = thread::spawn(move || {
            let (mut sock, _) = err_listener.accept().unwrap();
            sock.write_all(b"INFO {\"server_id\":\"mock\"}\r\n")
                .unwrap();
            let mut r = BufReader::new(sock.try_clone().unwrap());
            let mut tmp = String::new();
            let _ = r.read_line(&mut tmp);
            let _ = r.read_line(&mut tmp);
            sock.write_all(b"-ERR 'Permissions Violation'\r\n").unwrap();
        });
        let err_res = wire::publish_batch_wire(
            &format!("nats://{err_addr}"),
            "grdr-test",
            1_000,
            &[wire::encode_hpub_cmd("grdr.a.b.p0", "id", &BTreeMap::new(), b"ok").unwrap()],
        )
        .unwrap_err();
        assert_eq!(err_res.code, CODE_NATS_WIRE);
        let _ = err_srv.join();
    }
}
