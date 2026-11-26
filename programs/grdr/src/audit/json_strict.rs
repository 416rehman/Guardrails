// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors

use std::collections::BTreeMap;
use std::fmt;
use std::fs::{self, OpenOptions};
use std::io::Read;
use std::path::Path;

use serde::de::{DeserializeSeed, Deserializer, Error as DeError, MapAccess, SeqAccess, Visitor};
use serde_json::{Map, Number, Value};

use grdr_core::audit::AuditVerifyError;

use crate::fs_safe::{FsSafeError, reject_symlinks_on_existing_prefixes};

use super::malformed;

const MAX_JSON_DEPTH: usize = 64;

struct StrictJsonSeed {
    depth: usize,
}

struct StrictJsonVisitor {
    depth: usize,
}

impl<'de> DeserializeSeed<'de> for StrictJsonSeed {
    type Value = Value;

    fn deserialize<D: Deserializer<'de>>(self, deserializer: D) -> Result<Self::Value, D::Error> {
        if self.depth > MAX_JSON_DEPTH {
            return Err(D::Error::custom("JSON depth exceeded"));
        }
        deserializer.deserialize_any(StrictJsonVisitor { depth: self.depth })
    }
}

impl<'de> Visitor<'de> for StrictJsonVisitor {
    type Value = Value;

    fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("a strict JSON value without duplicate keys")
    }

    fn visit_bool<E: DeError>(self, v: bool) -> Result<Value, E> {
        Ok(Value::Bool(v))
    }

    fn visit_i64<E: DeError>(self, v: i64) -> Result<Value, E> {
        Ok(Value::Number(Number::from(v)))
    }

    fn visit_u64<E: DeError>(self, v: u64) -> Result<Value, E> {
        Ok(Value::Number(Number::from(v)))
    }

    fn visit_f64<E: DeError>(self, v: f64) -> Result<Value, E> {
        Number::from_f64(v)
            .map(Value::Number)
            .ok_or_else(|| DeError::custom("non-finite JSON number"))
    }

    fn visit_str<E: DeError>(self, v: &str) -> Result<Value, E> {
        Ok(Value::String(v.to_owned()))
    }

    fn visit_string<E: DeError>(self, v: String) -> Result<Value, E> {
        Ok(Value::String(v))
    }

    fn visit_none<E: DeError>(self) -> Result<Value, E> {
        Ok(Value::Null)
    }

    fn visit_unit<E: DeError>(self) -> Result<Value, E> {
        Ok(Value::Null)
    }

    fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> Result<Value, A::Error> {
        let mut out = Vec::new();
        let next_depth = self.depth.saturating_add(1);
        while let Some(elem) = seq.next_element_seed(StrictJsonSeed { depth: next_depth })? {
            out.push(elem);
        }
        Ok(Value::Array(out))
    }

    fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<Value, A::Error> {
        let mut out = Map::new();
        let next_depth = self.depth.saturating_add(1);
        while let Some(k) = map.next_key::<String>()? {
            if out.contains_key(&k) {
                return Err(A::Error::custom("duplicate JSON object key"));
            }
            let v = map.next_value_seed(StrictJsonSeed { depth: next_depth })?;
            out.insert(k, v);
        }
        Ok(Value::Object(out))
    }
}

pub(crate) fn parse_line_obj_strict(
    line: usize,
    text: &str,
) -> Result<Map<String, Value>, AuditVerifyError> {
    let mut de = serde_json::Deserializer::from_str(text);
    let val = StrictJsonSeed { depth: 0 }
        .deserialize(&mut de)
        .map_err(|_| malformed(line, "invalid JSON syntax or duplicate object key"))?;
    de.end()
        .map_err(|_| malformed(line, "trailing data after JSON object"))?;
    match val {
        Value::Object(map) => Ok(map),
        _ => Err(malformed(line, "entry must be a JSON object")),
    }
}

pub(crate) fn canonical_json_bytes(
    line: usize,
    value: &Value,
) -> Result<Vec<u8>, AuditVerifyError> {
    serde_json::to_vec(&sort_json_keys(value))
        .map_err(|_| malformed(line, "failed canonicalizing JSON payload"))
}

fn sort_json_keys(value: &Value) -> Value {
    match value {
        Value::Object(map) => Value::Object(
            map.iter()
                .map(|(k, v)| (k.clone(), sort_json_keys(v)))
                .collect::<BTreeMap<_, _>>()
                .into_iter()
                .collect(),
        ),
        Value::Array(items) => Value::Array(items.iter().map(sort_json_keys).collect()),
        other => other.clone(),
    }
}

pub(crate) fn read_bounded_audit_utf8(
    path: &Path,
    max_bytes: u64,
) -> Result<String, AuditVerifyError> {
    reject_symlinks_on_existing_prefixes(path).map_err(map_fs_err)?;
    let pre_meta = match fs::symlink_metadata(path) {
        Ok(m) => m,
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => {
            return Err(AuditVerifyError::NotFound {
                path: path.display().to_string(),
            });
        }
        Err(_) => return Err(malformed(0, "failed inspecting audit log path")),
    };
    if is_symlink_or_reparse(&pre_meta) || !pre_meta.is_file() {
        return Err(malformed(
            0,
            "audit log path must be a regular non-symlink file",
        ));
    }
    if pre_meta.len() > max_bytes {
        return Err(malformed(0, "audit log exceeds maximum allowed byte size"));
    }

    let mut open_opts = OpenOptions::new();
    open_opts.read(true);
    apply_audit_open_flags(&mut open_opts);
    let file = open_opts
        .open(path)
        .map_err(|_| malformed(0, "failed reading audit log file"))?;
    let handle_meta = file
        .metadata()
        .map_err(|_| malformed(0, "failed inspecting opened audit handle"))?;
    if is_symlink_or_reparse(&handle_meta) || !handle_meta.is_file() {
        return Err(malformed(
            0,
            "opened audit handle is not a regular non-symlink file",
        ));
    }
    verify_same_handle(path, &pre_meta, &handle_meta)?;
    reject_symlinks_on_existing_prefixes(path).map_err(map_fs_err)?;

    let mut raw = Vec::new();
    file.take(max_bytes.saturating_add(1))
        .read_to_end(&mut raw)
        .map_err(|_| malformed(0, "failed reading audit log file"))?;
    if u64::try_from(raw.len()).unwrap_or(u64::MAX) > max_bytes {
        return Err(malformed(0, "audit log exceeds maximum allowed byte size"));
    }
    String::from_utf8(raw).map_err(|_| malformed(0, "audit log must be valid UTF-8"))
}

fn map_fs_err(err: FsSafeError) -> AuditVerifyError {
    match err {
        FsSafeError::SymlinkForbidden(_) => malformed(0, "symlink or unsafe audit path refused"),
        FsSafeError::PolicyViolation { .. } => {
            malformed(0, "audit log exceeds maximum allowed byte size")
        }
        FsSafeError::Io { .. } | FsSafeError::Crypto { .. } => {
            malformed(0, "failed inspecting audit log path")
        }
    }
}

pub(crate) fn is_symlink_or_reparse(meta: &fs::Metadata) -> bool {
    if meta.file_type().is_symlink() {
        return true;
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::MetadataExt;
        const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x0400;
        (meta.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT) != 0
    }
    #[cfg(not(windows))]
    {
        false
    }
}

fn verify_same_handle(
    _path: &Path,
    pre: &fs::Metadata,
    handle: &fs::Metadata,
) -> Result<(), AuditVerifyError> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        if pre.dev() != handle.dev() || pre.ino() != handle.ino() {
            return Err(malformed(0, "audit file swapped during open"));
        }
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::MetadataExt;
        if pre.len() != handle.len()
            || pre.creation_time() != handle.creation_time()
            || pre.last_write_time() != handle.last_write_time()
            || pre.file_attributes() != handle.file_attributes()
        {
            return Err(malformed(0, "audit file swapped during open"));
        }
    }
    Ok(())
}

fn apply_audit_open_flags(opts: &mut OpenOptions) {
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.custom_flags(unix_open_flags());
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::OpenOptionsExt;
        const FILE_FLAG_OPEN_REPARSE_POINT: u32 = 0x0020_0000;
        opts.custom_flags(FILE_FLAG_OPEN_REPARSE_POINT);
    }
}

#[cfg(unix)]
const fn unix_open_flags() -> i32 {
    #[cfg(all(
        target_os = "linux",
        any(
            target_arch = "arm",
            target_arch = "aarch64",
            target_arch = "powerpc",
            target_arch = "powerpc64"
        )
    ))]
    {
        0o100_000 | 0o4000
    }
    #[cfg(all(target_os = "linux", any(target_arch = "mips", target_arch = "mips64")))]
    {
        0x20000 | 0x0080
    }
    #[cfg(all(
        target_os = "linux",
        any(target_arch = "sparc", target_arch = "sparc64")
    ))]
    {
        0x20000 | 0x4000
    }
    #[cfg(all(
        target_os = "linux",
        not(any(
            target_arch = "arm",
            target_arch = "aarch64",
            target_arch = "powerpc",
            target_arch = "powerpc64",
            target_arch = "mips",
            target_arch = "mips64",
            target_arch = "sparc",
            target_arch = "sparc64"
        ))
    ))]
    {
        0o400_000 | 0o4000
    }
    #[cfg(any(
        target_os = "macos",
        target_os = "ios",
        target_os = "freebsd",
        target_os = "openbsd",
        target_os = "dragonfly",
        target_os = "netbsd"
    ))]
    {
        0x0100 | 0x0004
    }
}
