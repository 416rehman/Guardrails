// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors
#![forbid(unsafe_code)]
#![deny(clippy::arithmetic_side_effects)]

mod bus;
mod schema;

pub use bus::SqliteLogBus;

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;

    use grdr_ports::{BusAppendMessage, BusPort, OrgId, SingleCtx, TenantCtx};

    #[test]
    fn sqlite_log_bus_passes_port_contract() {
        let bus = SqliteLogBus::open_in_memory().unwrap();
        grdr_ports_testkit::assert_bus_port_contract(&bus).unwrap();
    }

    #[test]
    fn sqlite_log_bus_persists_wal_across_reopen() {
        let dir = std::env::temp_dir().join(format!("grdr-bus-log-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let db_path = dir.join("bus.sqlite3");

        let org = OrgId::new("org-bus-persist").unwrap();
        let ctx = SingleCtx::new(org);
        let read_ctx = TenantCtx::Single(ctx.clone());

        {
            let bus = SqliteLogBus::open(&db_path).unwrap();
            let range = bus
                .append(
                    &ctx,
                    "events",
                    0,
                    &[BusAppendMessage {
                        key: "dev-1".into(),
                        headers: BTreeMap::new(),
                        payload: b"persisted-event".to_vec(),
                    }],
                    4_200,
                )
                .unwrap();
            assert_eq!(range.first_offset, 0);
        }

        let reopened = SqliteLogBus::open(&db_path).unwrap();
        let msgs = reopened.fetch(&read_ctx, "events", 0, None, 10).unwrap();
        assert_eq!(msgs.len(), 1);
        assert_eq!(msgs[0].payload, b"persisted-event");

        let _ = std::fs::remove_dir_all(&dir);
    }
}
