// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors

//! Registered `grdr-schema` error codes (`contracts/codes/registry.toml`, `ARCH-017`).

pub const CODE_SCHEMA_NOT_OBJECT: &str = "GRDR-SCHEMA-0001";
pub const CODE_SCHEMA_MISSING_FIELD: &str = "GRDR-SCHEMA-0002";
pub const CODE_SCHEMA_TYPE_MISMATCH: &str = "GRDR-SCHEMA-0003";
pub const CODE_SCHEMA_EMPTY_STRING: &str = "GRDR-SCHEMA-0004";
pub const CODE_SCHEMA_CEDAR_SCHEMA_PARSE: &str = "GRDR-SCHEMA-0005";
pub const CODE_SCHEMA_CEDAR_POLICY_PARSE: &str = "GRDR-SCHEMA-0006";
pub const CODE_SCHEMA_CEDAR_POLICY_VALIDATION: &str = "GRDR-SCHEMA-0007";

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn schema_codes_and_registry_entries_are_well_formed() {
        let reg = include_str!("../../../contracts/codes/registry.toml");
        for code in [
            CODE_SCHEMA_NOT_OBJECT,
            CODE_SCHEMA_MISSING_FIELD,
            CODE_SCHEMA_TYPE_MISMATCH,
            CODE_SCHEMA_EMPTY_STRING,
            CODE_SCHEMA_CEDAR_SCHEMA_PARSE,
            CODE_SCHEMA_CEDAR_POLICY_PARSE,
            CODE_SCHEMA_CEDAR_POLICY_VALIDATION,
        ] {
            assert!(
                reg.contains(&format!("{code} =")),
                "{code} missing from contracts/codes/registry.toml"
            );
        }

        let mut seen = std::collections::BTreeSet::new();
        for line in reg.lines() {
            let trimmed = line.trim();
            if trimmed.is_empty() || trimmed.starts_with('#') || trimmed.starts_with('[') {
                continue;
            }
            if let Some((lhs, _)) = trimmed.split_once('=') {
                let key = lhs.trim();
                if key == "schema" {
                    continue;
                }
                assert!(
                    key.starts_with("GRDR-"),
                    "unexpected key `{key}` in registry.toml"
                );
                let suffix = key.rsplit('-').next().unwrap_or("");
                assert_eq!(suffix.len(), 4, "code `{key}` must end with 4 digits");
                assert!(
                    suffix.bytes().all(|b| b.is_ascii_digit()),
                    "code `{key}` suffix must be numeric"
                );
                assert!(seen.insert(key.to_owned()), "duplicate code `{key}`");
            }
        }
        assert!(seen.len() >= 450);
    }
}
