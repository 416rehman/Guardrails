// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors

use serde::{Deserialize, Serialize};

use crate::ServiceError;

pub const PIPE_FLAG_FIRST_PIPE_INSTANCE: u32 = 0x0008_0000;
pub const PIPE_REJECT_REMOTE_CLIENTS: u32 = 0x0000_0008;
pub const PIPE_ACCESS_DUPLEX: u32 = 0x0000_0003;
const WINDOWS_PIPE_PREFIX: &str = r"\\.\pipe\";
const MAX_PIPE_LEAF_LEN: usize = 240;
const WINDOWS_SID_MAX_AUTHORITY: u64 = 0x0000_FFFF_FFFF_FFFF;
const WINDOWS_SID_MAX_SUBAUTHORITIES: usize = 15;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NamedPipeAccessRight {
    FileReadData,
    FileWriteData,
    FileReadAttributes,
    ReadControl,
    Synchronize,
    FileCreatePipeInstance,
    FileGenericWrite,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PipeSecurityProfile {
    ProtectedService { service_sid: String },
    UserSession { user_sid: String },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NamedPipeDaclSpec {
    pub pipe_name: String,
    pub owner_sid: String,
    pub open_mode_flags: u32,
    pub pipe_mode_flags: u32,
    pub client_rights: Vec<NamedPipeAccessRight>,
    pub sddl: String,
}

impl NamedPipeAccessRight {
    pub const fn access_mask_bit(self) -> u32 {
        match self {
            Self::FileReadData => 0x0000_0001,
            Self::FileWriteData => 0x0000_0002,
            Self::FileReadAttributes => 0x0000_0080,
            Self::ReadControl => 0x0002_0000,
            Self::Synchronize => 0x0010_0000,
            Self::FileCreatePipeInstance => 0x0000_0004,
            Self::FileGenericWrite => 0x4000_0000,
        }
    }

    pub const fn sddl_code(self) -> &'static str {
        match self {
            Self::FileReadData => "FR",
            Self::FileWriteData => "FW",
            Self::FileReadAttributes => "FA",
            Self::ReadControl => "RC",
            Self::Synchronize => "SY",
            Self::FileCreatePipeInstance => "FC",
            Self::FileGenericWrite => "GW",
        }
    }

    pub const fn is_forbidden_for_clients(self) -> bool {
        matches!(self, Self::FileCreatePipeInstance | Self::FileGenericWrite)
    }
}

pub fn validate_windows_sid(raw_sid: &str) -> Result<&str, ServiceError> {
    let sid = raw_sid.trim();
    let rest = sid.strip_prefix("S-1-").ok_or_else(|| {
        ServiceError::DaclViolation(format!(
            "invalid Windows SID `{raw_sid}`: must start with S-1-"
        ))
    })?;
    let mut parts = rest.split('-');
    let Some(first) = parts.next() else {
        return Err(ServiceError::DaclViolation("SID missing authority".into()));
    };
    let auth_ok = !first.is_empty()
        && first.bytes().all(|b| b.is_ascii_digit())
        && first
            .parse::<u64>()
            .is_ok_and(|val| val <= WINDOWS_SID_MAX_AUTHORITY);
    if !auth_ok {
        return Err(ServiceError::DaclViolation(format!(
            "invalid 48-bit Windows SID authority in `{raw_sid}`"
        )));
    }
    let mut subauth_count = 0usize;
    for part in parts {
        if part.is_empty()
            || !part.bytes().all(|b| b.is_ascii_digit())
            || part.parse::<u32>().is_err()
        {
            return Err(ServiceError::DaclViolation(format!(
                "invalid 32-bit Windows SID subauthority in `{raw_sid}`"
            )));
        }
        subauth_count = subauth_count.saturating_add(1);
    }
    if subauth_count == 0 || subauth_count > WINDOWS_SID_MAX_SUBAUTHORITIES {
        return Err(ServiceError::DaclViolation(format!(
            "Windows SID `{raw_sid}` must contain 1..={WINDOWS_SID_MAX_SUBAUTHORITIES} subauthorities"
        )));
    }
    Ok(sid)
}

pub fn build_named_pipe_dacl(
    pipe_name: &str,
    profile: &PipeSecurityProfile,
    requested_client_rights: &[NamedPipeAccessRight],
) -> Result<NamedPipeDaclSpec, ServiceError> {
    validate_pipe_name(pipe_name)?;
    for right in requested_client_rights {
        if right.is_forbidden_for_clients() {
            return Err(ServiceError::DaclViolation(format!(
                "client right {:?} is forbidden on endpoint pipes (RFC 0003)",
                right
            )));
        }
    }

    let rights = if requested_client_rights.is_empty() {
        vec![
            NamedPipeAccessRight::FileReadData,
            NamedPipeAccessRight::FileWriteData,
            NamedPipeAccessRight::FileReadAttributes,
            NamedPipeAccessRight::ReadControl,
            NamedPipeAccessRight::Synchronize,
        ]
    } else {
        requested_client_rights.to_vec()
    };

    let access_mask: u32 = rights.iter().fold(0u32, |acc, r| acc | r.access_mask_bit());

    let raw_owner_sid = match profile {
        PipeSecurityProfile::ProtectedService { service_sid } => service_sid,
        PipeSecurityProfile::UserSession { user_sid } => user_sid,
    };
    let owner_sid = validate_windows_sid(raw_owner_sid)?;

    let client_ace_target = match profile {
        PipeSecurityProfile::ProtectedService { .. } => "AU",
        PipeSecurityProfile::UserSession { user_sid } => validate_windows_sid(user_sid)?,
    };
    let sddl = format!(
        "O:{owner_sid}D:P(A;;GA;;;SY)(A;;GA;;;{owner_sid})(A;;0x{access_mask:08x};;;{client_ace_target})"
    );

    Ok(NamedPipeDaclSpec {
        pipe_name: pipe_name.to_string(),
        owner_sid: owner_sid.to_string(),
        open_mode_flags: PIPE_ACCESS_DUPLEX | PIPE_FLAG_FIRST_PIPE_INSTANCE,
        pipe_mode_flags: PIPE_REJECT_REMOTE_CLIENTS,
        client_rights: rights,
        sddl,
    })
}

fn validate_pipe_name(pipe_name: &str) -> Result<(), ServiceError> {
    let Some(leaf) = pipe_name.strip_prefix(WINDOWS_PIPE_PREFIX) else {
        return Err(ServiceError::DaclViolation(format!(
            "invalid Windows named pipe path `{pipe_name}`"
        )));
    };
    if leaf.is_empty()
        || leaf.len() > MAX_PIPE_LEAF_LEN
        || leaf.contains("..")
        || leaf
            .chars()
            .any(|c| c == '\\' || c == '/' || c == '\0' || c.is_control() || c.is_whitespace())
    {
        return Err(ServiceError::DaclViolation(format!(
            "invalid Windows named pipe leaf `{leaf}`"
        )));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_sddl_injection_bad_pipe_names_and_derives_exact_mask() {
        let injected = PipeSecurityProfile::ProtectedService {
            service_sid: "S-1-5-80-1)(A;;GA;;;WD".into(),
        };
        assert!(matches!(
            build_named_pipe_dacl(r"\\.\pipe\grdr-decide", &injected, &[]),
            Err(ServiceError::DaclViolation(_))
        ));

        let profile = PipeSecurityProfile::ProtectedService {
            service_sid: "S-1-5-80-12345".into(),
        };
        assert!(matches!(
            build_named_pipe_dacl(r"\\.\pipe\..\evil", &profile, &[]),
            Err(ServiceError::DaclViolation(_))
        ));

        assert!(matches!(
            build_named_pipe_dacl(
                r"\\.\pipe\grdr-decide",
                &profile,
                &[NamedPipeAccessRight::FileGenericWrite],
            ),
            Err(ServiceError::DaclViolation(_))
        ));

        let ro_spec = build_named_pipe_dacl(
            r"\\.\pipe\grdr-decide",
            &profile,
            &[
                NamedPipeAccessRight::FileReadData,
                NamedPipeAccessRight::ReadControl,
                NamedPipeAccessRight::Synchronize,
            ],
        )
        .unwrap();
        assert!(ro_spec.sddl.contains("0x00120001"));

        assert!(validate_windows_sid("S-1-281474976710656-1").is_err());
        assert!(validate_windows_sid("S-1-5-4294967296").is_err());
        assert!(validate_windows_sid("S-1-5-1-2-3-4-5-6-7-8-9-10-11-12-13-14-15-16").is_err());

        let default_spec = build_named_pipe_dacl(r"\\.\pipe\grdr-decide", &profile, &[]).unwrap();
        assert_eq!(default_spec.client_rights.len(), 5);
        assert!(default_spec.sddl.contains("0x00120083"));
        assert_ne!(
            default_spec.open_mode_flags & PIPE_FLAG_FIRST_PIPE_INSTANCE,
            0
        );
        assert_ne!(default_spec.pipe_mode_flags & PIPE_REJECT_REMOTE_CLIENTS, 0);
    }
}
