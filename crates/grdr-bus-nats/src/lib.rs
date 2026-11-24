// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors
#![forbid(unsafe_code)]
#![deny(clippy::arithmetic_side_effects)]

mod bus;
pub mod config;
pub mod wire;

pub use bus::NatsJetStreamBus;
pub use config::{
    CODE_NATS_CONFIG, CODE_NATS_IO, CODE_NATS_STREAM_FULL, CODE_NATS_WIRE, JetStreamStreamSpec,
    ListenerPolicy, NatsConfig, NatsDiscardPolicy, NatsListenerGuard, NatsTransportMode,
    jetstream_stream_name, subject_for,
};
pub use wire::NatsWireState;

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;
    use std::io::{BufRead, BufReader, Read, Write};
    use std::net::TcpListener;
    use std::thread;

    use grdr_ports::{BusAppendMessage, BusPort, OrgId, SingleCtx};

    use super::*;

    #[test]
    fn nats_jetstream_embedded_passes_bus_port_contract() {
        let bus = NatsJetStreamBus::open_embedded().unwrap();
        grdr_ports_testkit::assert_bus_port_contract(&bus).unwrap();
    }

    #[test]
    fn nats_subject_naming_stream_specs_and_listener_guard() {
        let org = OrgId::new("org-nats-1").unwrap();
        assert_eq!(subject_for(&org, "events", 9), "grdr.org-nats-1.events.p9");
        assert_eq!(jetstream_stream_name("events", 9), "GRDR_EVENTS_1");
        assert_eq!(jetstream_stream_name("decision", 0), "GRDR_DECISION");

        let mut bad_cfg = NatsConfig::embedded_default();
        bad_cfg.listener_guard.mqtt = ListenerPolicy::Enabled;
        let err = NatsJetStreamBus::connect(bad_cfg).unwrap_err();
        assert_eq!(err.code, CODE_NATS_CONFIG);

        let cfg = NatsConfig::embedded_default();
        let spec = cfg.stream_spec("events", 3);
        assert_eq!(spec.stream_name, "GRDR_EVENTS_3");
        assert_eq!(spec.discard_policy, NatsDiscardPolicy::New);
        let payload = wire::encode_stream_create_payload(&spec).unwrap();
        assert!(String::from_utf8_lossy(&payload).contains("GRDR_EVENTS_3"));
    }

    #[test]
    fn nats_wire_hpub_roundtrip_against_mock_tcp_listener() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();

        let server = thread::spawn(move || {
            let (mut sock, _) = listener.accept().unwrap();
            sock.write_all(
                b"INFO {\"server_id\":\"mock\",\"version\":\"2.15.2\",\"headers\":true}\r\n",
            )
            .unwrap();
            let mut reader = BufReader::new(sock.try_clone().unwrap());
            let mut connect_line = String::new();
            reader.read_line(&mut connect_line).unwrap();
            assert!(connect_line.starts_with("CONNECT "));

            let mut hpub_line = String::new();
            reader.read_line(&mut hpub_line).unwrap();
            assert!(hpub_line.starts_with("HPUB grdr.org-wire.events.p2 "));
            let parts: Vec<&str> = hpub_line.split_whitespace().collect();
            let total_len: usize = parts[3].parse().unwrap();
            let mut body = vec![0u8; total_len + 2];
            reader.read_exact(&mut body).unwrap();
            let body_str = String::from_utf8_lossy(&body);
            assert!(body_str.contains("Nats-Msg-Id: msg-dedup-1"));
            assert!(body_str.contains("wire-payload"));

            let mut ping = String::new();
            reader.read_line(&mut ping).unwrap();
            assert_eq!(ping.trim(), "PING");
            sock.write_all(b"PONG\r\n").unwrap();
        });

        let cfg = NatsConfig::parse_url(&format!("nats://{addr}")).unwrap();
        let bus = NatsJetStreamBus::connect(cfg).unwrap();
        let org = OrgId::new("org-wire").unwrap();
        let ctx = SingleCtx::new(org);
        let mut headers = BTreeMap::new();
        headers.insert("Nats-Msg-Id".into(), "msg-dedup-1".into());
        let range = bus
            .append(
                &ctx,
                "events",
                2,
                &[BusAppendMessage {
                    key: "dev-9".into(),
                    headers,
                    payload: b"wire-payload".to_vec(),
                }],
                1_000,
            )
            .unwrap();
        assert_eq!(range.first_offset, 0);
        let hist = bus.subject_history("events", 2).unwrap();
        assert_eq!(hist[0].0, "grdr.org-wire.events.p2");
        server.join().unwrap();
    }
}
