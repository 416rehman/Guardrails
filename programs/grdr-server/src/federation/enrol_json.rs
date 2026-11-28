// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors

use std::collections::{BTreeMap, BTreeSet};

use super::enrol::HardwareAttestationPayload;

pub(super) const MAX_HARDWARE_ATTESTATION_BYTES: usize = 16_384;
pub(super) const MAX_MDM_ARTIFACT_BYTES: usize = 65_536;
pub(super) const MAX_FLEET_PROFILE_KEYS: usize = 64;
pub(super) const MAX_FLEET_SCALAR_BYTES: usize = 4_096;

#[derive(Debug, PartialEq, Eq)]
pub(super) struct FleetMdmPayload {
    pub(super) team_id: Option<String>,
    pub(super) profile: Option<FleetProfileField>,
}

#[derive(Debug, PartialEq, Eq)]
pub(super) enum FleetProfileField {
    Str(String),
    Map(BTreeMap<String, FleetScalar>),
}

#[derive(Debug, PartialEq, Eq)]
pub(super) enum FleetScalar {
    Str(String),
    Bool,
    Int,
}

struct FlatJsonParser<'a> {
    bytes: &'a [u8],
    pos: usize,
}

#[derive(Default)]
struct HardwarePayloadFields {
    device_id: Option<String>,
    boot_id: Option<String>,
    hardware_vendor: Option<String>,
    device_pubkey_b64: Option<String>,
    nonce: Option<String>,
    iat: Option<i64>,
    exp: Option<i64>,
}

impl<'a> FlatJsonParser<'a> {
    fn new(raw: &'a str) -> Self {
        Self {
            bytes: raw.as_bytes(),
            pos: 0,
        }
    }

    fn peek(&self) -> Option<u8> {
        self.bytes.get(self.pos).copied()
    }

    fn skip_ws(&mut self) {
        while let Some(b) = self.peek() {
            if matches!(b, b' ' | b'\t' | b'\r' | b'\n') {
                self.pos = self.pos.saturating_add(1);
            } else {
                break;
            }
        }
    }

    fn expect_byte(&mut self, expected: u8, err: &str) -> Result<(), String> {
        if self.peek() != Some(expected) {
            return Err(err.to_owned());
        }
        self.pos = self.pos.saturating_add(1);
        Ok(())
    }

    fn expect_eof(&mut self) -> Result<(), String> {
        self.skip_ws();
        if self.pos < self.bytes.len() {
            return Err("trailing characters after JSON object".into());
        }
        Ok(())
    }

    fn check_token_boundary(&self) -> Result<(), String> {
        match self.peek() {
            None => Ok(()),
            Some(b',' | b'}' | b' ' | b'\t' | b'\r' | b'\n') => Ok(()),
            _ => Err("unexpected trailing token characters after JSON primitive".into()),
        }
    }

    fn parse_object_entries<F>(
        &mut self,
        max_keys: Option<usize>,
        mut on_entry: F,
    ) -> Result<(), String>
    where
        F: FnMut(&str, &mut Self) -> Result<(), String>,
    {
        self.skip_ws();
        self.expect_byte(b'{', "expected JSON object")?;
        self.skip_ws();
        if self.peek() == Some(b'}') {
            self.pos = self.pos.saturating_add(1);
            return Ok(());
        }
        let mut seen = BTreeSet::new();
        loop {
            self.skip_ws();
            if self.peek() != Some(b'"') {
                return Err("expected string key in JSON object".into());
            }
            let key = self.parse_string()?;
            if !seen.insert(key.clone()) {
                return Err(format!("duplicate JSON key `{key}` rejected"));
            }
            if max_keys.is_some_and(|cap| seen.len() > cap) {
                return Err("JSON object key limit exceeded".into());
            }
            self.skip_ws();
            self.expect_byte(b':', "expected `:` after JSON key")?;
            self.skip_ws();
            on_entry(&key, self)?;
            self.skip_ws();
            match self.peek() {
                Some(b',') => self.pos = self.pos.saturating_add(1),
                Some(b'}') => {
                    self.pos = self.pos.saturating_add(1);
                    return Ok(());
                }
                _ => return Err("expected `,` or `}` in JSON object".into()),
            }
        }
    }

    fn parse_string(&mut self) -> Result<String, String> {
        self.expect_byte(b'"', "expected JSON string")?;
        let mut out = Vec::new();
        while let Some(b) = self.peek() {
            self.pos = self.pos.saturating_add(1);
            match b {
                b'"' => {
                    let decoded = String::from_utf8(out)
                        .map_err(|_| "invalid UTF-8 inside JSON string".to_owned())?;
                    if has_forbidden_control_bytes(&decoded) {
                        return Err("JSON string contains forbidden control bytes".into());
                    }
                    return Ok(decoded);
                }
                b'\\' => {
                    let Some(esc) = self.peek() else {
                        return Err("unterminated JSON string escape".into());
                    };
                    self.pos = self.pos.saturating_add(1);
                    match esc {
                        b'"' | b'\\' | b'/' => out.push(esc),
                        b'b' => out.push(0x08),
                        b'f' => out.push(0x0c),
                        b'n' => out.push(b'\n'),
                        b'r' => out.push(b'\r'),
                        b't' => out.push(b'\t'),
                        b'u' => {
                            let cp = self.parse_hex4()?;
                            let ch = if (0xD800..=0xDBFF).contains(&cp) {
                                if self.bytes.get(self.pos) != Some(&b'\\')
                                    || self.bytes.get(self.pos.saturating_add(1)) != Some(&b'u')
                                {
                                    return Err("unpaired high UTF-16 surrogate in JSON".into());
                                }
                                self.pos = self.pos.saturating_add(2);
                                let low = self.parse_hex4()?;
                                if !(0xDC00..=0xDFFF).contains(&low) {
                                    return Err("invalid low UTF-16 surrogate in JSON".into());
                                }
                                let combined = 0x1_0000_u32
                                    .saturating_add(u32::from(cp.saturating_sub(0xD800)) << 10)
                                    .saturating_add(u32::from(low.saturating_sub(0xDC00)));
                                char::from_u32(combined)
                                    .ok_or_else(|| "invalid Unicode scalar in JSON".to_owned())?
                            } else {
                                char::from_u32(u32::from(cp))
                                    .ok_or_else(|| "invalid Unicode scalar in JSON".to_owned())?
                            };
                            let mut buf = [0u8; 4];
                            out.extend_from_slice(ch.encode_utf8(&mut buf).as_bytes());
                        }
                        _ => return Err("invalid JSON string escape".into()),
                    }
                }
                c if c < 0x20 => return Err("unescaped control byte in JSON string".into()),
                c => out.push(c),
            }
        }
        Err("unterminated JSON string".into())
    }

    fn parse_hex4(&mut self) -> Result<u16, String> {
        let mut val: u16 = 0;
        for _ in 0..4 {
            let Some(b) = self.peek() else {
                return Err("truncated JSON unicode escape".into());
            };
            self.pos = self.pos.saturating_add(1);
            let nib = match b {
                b'0'..=b'9' => u16::from(b.saturating_sub(b'0')),
                b'a'..=b'f' => u16::from(b.saturating_sub(b'a')).saturating_add(10),
                b'A'..=b'F' => u16::from(b.saturating_sub(b'A')).saturating_add(10),
                _ => return Err("invalid hex digit in JSON unicode escape".into()),
            };
            val = (val << 4) | nib;
        }
        Ok(val)
    }

    fn parse_integer_token(&mut self) -> Result<&'a str, String> {
        let start = self.pos;
        if self.peek() == Some(b'-') {
            self.pos = self.pos.saturating_add(1);
        }
        match self.peek() {
            Some(b'0') => {
                self.pos = self.pos.saturating_add(1);
                if matches!(self.peek(), Some(b'0'..=b'9')) {
                    return Err("leading zeros in JSON integer are rejected".into());
                }
            }
            Some(b'1'..=b'9') => {
                while matches!(self.peek(), Some(b'0'..=b'9')) {
                    self.pos = self.pos.saturating_add(1);
                }
            }
            _ => return Err("expected JSON integer".into()),
        }
        if matches!(self.peek(), Some(b'.' | b'e' | b'E')) {
            return Err("floating-point and scientific JSON numbers are rejected".into());
        }
        self.check_token_boundary()?;
        let slice = self
            .bytes
            .get(start..self.pos)
            .ok_or_else(|| "internal JSON integer slice bounds error".to_owned())?;
        std::str::from_utf8(slice).map_err(|_| "invalid UTF-8 in JSON integer".to_owned())
    }

    fn parse_i64(&mut self) -> Result<i64, String> {
        let token = self.parse_integer_token()?;
        token
            .parse::<i64>()
            .map_err(|_| "JSON integer out of signed 64-bit range".to_owned())
    }

    fn parse_bool(&mut self) -> Result<FleetScalar, String> {
        let rest = self.bytes.get(self.pos..).unwrap_or_default();
        if rest.starts_with(b"true") {
            self.pos = self.pos.saturating_add(4);
            self.check_token_boundary()?;
            return Ok(FleetScalar::Bool);
        }
        if rest.starts_with(b"false") {
            self.pos = self.pos.saturating_add(5);
            self.check_token_boundary()?;
            return Ok(FleetScalar::Bool);
        }
        Err("expected JSON boolean".into())
    }

    fn parse_fleet_scalar(&mut self) -> Result<FleetScalar, String> {
        self.skip_ws();
        match self.peek() {
            Some(b'"') => {
                let s = self.parse_string()?;
                if s.len() > MAX_FLEET_SCALAR_BYTES {
                    return Err("Fleet profile scalar string exceeds size limit".into());
                }
                Ok(FleetScalar::Str(s))
            }
            Some(b't' | b'f') => self.parse_bool(),
            Some(b'-' | b'0'..=b'9') => {
                let token = self.parse_integer_token()?;
                if token.parse::<i64>().is_ok()
                    || (!token.starts_with('-') && token.parse::<u64>().is_ok())
                {
                    Ok(FleetScalar::Int)
                } else {
                    Err("Fleet profile integer out of 64-bit range".into())
                }
            }
            _ => Err("Fleet profile value must be string, boolean, or integer".into()),
        }
    }
}

pub(super) fn has_forbidden_control_bytes(input: &str) -> bool {
    input
        .bytes()
        .any(|b| b == 0 || (b < 0x20 && !matches!(b, b'\t' | b'\n' | b'\r')))
}

pub(super) fn parse_hardware_attestation_payload(
    raw: &str,
) -> Result<HardwareAttestationPayload, String> {
    if raw.trim().is_empty() || raw.len() > MAX_HARDWARE_ATTESTATION_BYTES {
        return Err("hardware attestation payload must be non-empty within 16 KiB".into());
    }
    if has_forbidden_control_bytes(raw) {
        return Err("hardware attestation payload contains forbidden control bytes".into());
    }
    let mut parser = FlatJsonParser::new(raw);
    let mut fields = HardwarePayloadFields::default();
    parser.parse_object_entries(None, |key, p| match key {
        "device_id" => {
            fields.device_id = Some(p.parse_string()?);
            Ok(())
        }
        "boot_id" => {
            fields.boot_id = Some(p.parse_string()?);
            Ok(())
        }
        "hardware_vendor" => {
            fields.hardware_vendor = Some(p.parse_string()?);
            Ok(())
        }
        "device_pubkey_b64" => {
            fields.device_pubkey_b64 = Some(p.parse_string()?);
            Ok(())
        }
        "nonce" => {
            fields.nonce = Some(p.parse_string()?);
            Ok(())
        }
        "iat" => {
            fields.iat = Some(p.parse_i64()?);
            Ok(())
        }
        "exp" => {
            fields.exp = Some(p.parse_i64()?);
            Ok(())
        }
        _ => Err(format!("unknown hardware attestation field `{key}`")),
    })?;
    parser.expect_eof()?;

    Ok(HardwareAttestationPayload {
        device_id: fields
            .device_id
            .ok_or("missing required field `device_id`")?,
        boot_id: fields.boot_id.ok_or("missing required field `boot_id`")?,
        hardware_vendor: fields
            .hardware_vendor
            .ok_or("missing required field `hardware_vendor`")?,
        device_pubkey_b64: fields
            .device_pubkey_b64
            .ok_or("missing required field `device_pubkey_b64`")?,
        nonce: fields.nonce.ok_or("missing required field `nonce`")?,
        iat: fields.iat.ok_or("missing required field `iat`")?,
        exp: fields.exp.ok_or("missing required field `exp`")?,
    })
}

pub(super) fn parse_fleet_mdm_payload(raw: &str) -> Result<FleetMdmPayload, String> {
    if raw.trim().is_empty() || raw.len() > MAX_MDM_ARTIFACT_BYTES {
        return Err("Fleet payload must be non-empty JSON within 64 KiB".into());
    }
    if has_forbidden_control_bytes(raw) {
        return Err("Fleet payload contains forbidden control bytes".into());
    }
    let mut parser = FlatJsonParser::new(raw);
    let mut team_id = None;
    let mut profile = None;
    parser.parse_object_entries(None, |key, p| match key {
        "team_id" => {
            team_id = Some(p.parse_string()?);
            Ok(())
        }
        "profile" => {
            p.skip_ws();
            match p.peek() {
                Some(b'"') => {
                    profile = Some(FleetProfileField::Str(p.parse_string()?));
                    Ok(())
                }
                Some(b'{') => {
                    let mut map = BTreeMap::new();
                    p.parse_object_entries(Some(MAX_FLEET_PROFILE_KEYS), |k, inner| {
                        let scalar = inner.parse_fleet_scalar()?;
                        map.insert(k.to_owned(), scalar);
                        Ok(())
                    })?;
                    profile = Some(FleetProfileField::Map(map));
                    Ok(())
                }
                _ => Err("Fleet `profile` must be string or flat JSON object".into()),
            }
        }
        _ => Err(format!("unknown Fleet payload field `{key}`")),
    })?;
    parser.expect_eof()?;
    Ok(FleetMdmPayload { team_id, profile })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn valid_hw_json() -> &'static str {
        r#"{"device_id":"dev-1","boot_id":"boot-1","hardware_vendor":"tpm2","device_pubkey_b64":"AQID","nonce":"n-1","iat":1700000000,"exp":1700000300}"#
    }

    #[test]
    fn parses_valid_hardware_and_fleet_payloads() {
        let hw = parse_hardware_attestation_payload(valid_hw_json()).expect("valid hardware");
        assert_eq!(hw.device_id, "dev-1");
        assert_eq!(hw.iat, 1_700_000_000);
        assert_eq!(hw.exp, 1_700_000_300);

        let fleet_str = parse_fleet_mdm_payload(r#"{"team_id":"eng","profile":"cGxpc3Q="}"#)
            .expect("fleet string profile");
        assert_eq!(fleet_str.team_id.as_deref(), Some("eng"));
        assert_eq!(
            fleet_str.profile,
            Some(FleetProfileField::Str("cGxpc3Q=".into()))
        );

        let fleet_map = parse_fleet_mdm_payload(
            r#"{"team_id":"eng","profile":{"name":"grdr","enabled":true,"ver":1,"neg":-7}}"#,
        )
        .expect("fleet flat map");
        match fleet_map.profile {
            Some(FleetProfileField::Map(map)) => {
                assert_eq!(map.get("name"), Some(&FleetScalar::Str("grdr".into())));
                assert_eq!(map.get("enabled"), Some(&FleetScalar::Bool));
                assert_eq!(map.get("ver"), Some(&FleetScalar::Int));
                assert_eq!(map.get("neg"), Some(&FleetScalar::Int));
            }
            other => panic!("expected map profile, got {other:?}"),
        }
    }

    #[test]
    fn handles_escaped_strings_and_surrogate_pairs_and_rejects_bad_escapes() {
        let json = r#"{"device_id":"d\"a\\b\/c","boot_id":"line\n\t\r","hardware_vendor":"tpm2","device_pubkey_b64":"AQID","nonce":"hi-\uD83D\uDE00-\u0041","iat":-10,"exp":10}"#;
        let hw = parse_hardware_attestation_payload(json).expect("valid escapes and surrogate");
        assert_eq!(hw.device_id, "d\"a\\b/c");
        assert_eq!(hw.boot_id, "line\n\t\r");
        assert_eq!(hw.nonce, "hi-\u{1F600}-A");
        assert_eq!(hw.iat, -10);

        let bad_high = r#"{"device_id":"d\uD800","boot_id":"b","hardware_vendor":"tpm2","device_pubkey_b64":"AQID","nonce":"n","iat":1,"exp":2}"#;
        assert!(parse_hardware_attestation_payload(bad_high).is_err());

        let escaped_nul = r#"{"device_id":"d\u0000","boot_id":"b","hardware_vendor":"tpm2","device_pubkey_b64":"AQID","nonce":"n","iat":1,"exp":2}"#;
        assert!(parse_hardware_attestation_payload(escaped_nul).is_err());
    }

    #[test]
    fn rejects_duplicate_unknown_missing_trailing_and_invalid_types() {
        let dup_hw = r#"{"device_id":"a","device_id":"b","boot_id":"b","hardware_vendor":"tpm2","device_pubkey_b64":"AQID","nonce":"n","iat":1,"exp":2}"#;
        assert!(parse_hardware_attestation_payload(dup_hw).is_err());

        let unk_hw = r#"{"device_id":"a","boot_id":"b","hardware_vendor":"tpm2","device_pubkey_b64":"AQID","nonce":"n","iat":1,"exp":2,"extra":true}"#;
        assert!(parse_hardware_attestation_payload(unk_hw).is_err());

        let missing_hw = r#"{"device_id":"a","boot_id":"b","hardware_vendor":"tpm2","device_pubkey_b64":"AQID","nonce":"n","iat":1}"#;
        assert!(parse_hardware_attestation_payload(missing_hw).is_err());

        let float_iat = r#"{"device_id":"a","boot_id":"b","hardware_vendor":"tpm2","device_pubkey_b64":"AQID","nonce":"n","iat":1.5,"exp":2}"#;
        assert!(parse_hardware_attestation_payload(float_iat).is_err());

        let trailing_hw = format!("{} trailing", valid_hw_json());
        assert!(parse_hardware_attestation_payload(&trailing_hw).is_err());

        let trailing_fleet = r#"{"team_id":"eng"} extra"#;
        assert!(parse_fleet_mdm_payload(trailing_fleet).is_err());

        let dup_fleet = r#"{"team_id":"a","team_id":"b"}"#;
        assert!(parse_fleet_mdm_payload(dup_fleet).is_err());

        let dup_profile_key = r#"{"profile":{"k":1,"k":2}}"#;
        assert!(parse_fleet_mdm_payload(dup_profile_key).is_err());

        let unk_fleet = r#"{"team_id":"a","unknown":1}"#;
        assert!(parse_fleet_mdm_payload(unk_fleet).is_err());
    }

    #[test]
    fn rejects_nested_arrays_floats_nulls_key_caps_oversize_and_control_bytes() {
        assert!(parse_fleet_mdm_payload(r#"{"profile":{"n":{"deep":1}}}"#).is_err());
        assert!(parse_fleet_mdm_payload(r#"{"profile":{"a":[1,2]}}"#).is_err());
        assert!(parse_fleet_mdm_payload(r#"{"profile":{"f":1.25}}"#).is_err());
        assert!(parse_fleet_mdm_payload(r#"{"profile":{"x":null}}"#).is_err());
        assert!(parse_fleet_mdm_payload(r#"{"team_id":null}"#).is_err());

        let too_many_keys: Vec<String> = (0..65).map(|i| format!("\"k{i}\":{i}")).collect();
        let fleet_65 = format!(r#"{{"profile":{{{}}}}}"#, too_many_keys.join(","));
        assert!(parse_fleet_mdm_payload(&fleet_65).is_err());

        let big_hw = format!(
            r#"{{"device_id":"{}","boot_id":"b","hardware_vendor":"tpm2","device_pubkey_b64":"AQID","nonce":"n","iat":1,"exp":2}}"#,
            "a".repeat(16_500)
        );
        assert!(parse_hardware_attestation_payload(&big_hw).is_err());

        let big_fleet = format!(r#"{{"team_id":"eng","profile":"{}"}}"#, "a".repeat(66_000));
        assert!(parse_fleet_mdm_payload(&big_fleet).is_err());

        assert!(parse_hardware_attestation_payload("{\"device_id\":\"a\u{0000}\"}").is_err());
        assert!(parse_fleet_mdm_payload("{\"team_id\":\"a\u{0001}\"}").is_err());
    }
}
