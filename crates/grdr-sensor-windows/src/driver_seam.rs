// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors

use serde::{Deserialize, Serialize};

use grdr_fastpath::{FastActionClass, FastVerdict, FloorRuleRef, evaluate_floor_entries};

use crate::WindowsSensorError;

pub const DRIVER_PROTOCOL_MAGIC: [u8; 8] = *b"GRDRWM01";
pub const DRIVER_PROTOCOL_VERSION: u32 = 1;
pub const DRIVER_REPLY_DEADLINE_MS: u64 = 50;
pub const MAX_DRIVER_PAYLOAD_LEN: u32 = 64 * 1024;
pub const MAX_DRIVER_REPLY_DEADLINE_MS: u32 = 1_000;
pub const MAX_EARLY_BUGCHECKS: u32 = 2;

#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DriverProtocolHeader {
    pub magic: [u8; 8],
    pub version: u32,
    pub message_kind: u32,
    pub payload_len: u32,
    pub reply_deadline_ms: u32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DriverAttachmentKind {
    UserModeOnly,
    OptionalKernelDriver,
    WespPartner,
    HostEdrEmbedded,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DriverFloorVerdict {
    Matched {
        rule_id: String,
        verdict: FastVerdict,
    },
    NoFloorHit,
}

pub trait WindowsDriverBackend: Send + Sync {
    fn attachment_kind(&self) -> DriverAttachmentKind;
    fn reply_deadline_ms(&self) -> u64;
    fn evaluate_kernel_floor(
        &self,
        floor: &[FloorRuleRef<'_>],
        action: FastActionClass,
        agent: &str,
        target: &str,
    ) -> Result<DriverFloorVerdict, WindowsSensorError>;
}

#[derive(Debug, Clone, Copy, Default)]
pub struct FallbackUserModeDriverSeam;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct DriverBootGuard {
    early_bugchecks: u32,
    driver_disabled: bool,
}

impl Default for DriverProtocolHeader {
    fn default() -> Self {
        Self {
            magic: DRIVER_PROTOCOL_MAGIC,
            version: DRIVER_PROTOCOL_VERSION,
            message_kind: 1,
            payload_len: 0,
            reply_deadline_ms: u32::try_from(DRIVER_REPLY_DEADLINE_MS).unwrap_or(50),
        }
    }
}

impl DriverProtocolHeader {
    pub fn validate(&self) -> Result<(), WindowsSensorError> {
        if self.magic != DRIVER_PROTOCOL_MAGIC {
            return Err(WindowsSensorError::Driver(
                "invalid Windows driver protocol magic".into(),
            ));
        }
        if self.version != DRIVER_PROTOCOL_VERSION {
            return Err(WindowsSensorError::Driver(format!(
                "unsupported Windows driver protocol version {}",
                self.version
            )));
        }
        if self.message_kind == 0 {
            return Err(WindowsSensorError::Driver(
                "driver message_kind must be non-zero".into(),
            ));
        }
        if self.payload_len > MAX_DRIVER_PAYLOAD_LEN {
            return Err(WindowsSensorError::Driver(format!(
                "driver payload_len {} exceeds cap {}",
                self.payload_len, MAX_DRIVER_PAYLOAD_LEN
            )));
        }
        if self.reply_deadline_ms == 0 || self.reply_deadline_ms > MAX_DRIVER_REPLY_DEADLINE_MS {
            return Err(WindowsSensorError::Driver(format!(
                "driver reply_deadline_ms {} must be in 1..={}",
                self.reply_deadline_ms, MAX_DRIVER_REPLY_DEADLINE_MS
            )));
        }
        Ok(())
    }
}

impl WindowsDriverBackend for FallbackUserModeDriverSeam {
    fn attachment_kind(&self) -> DriverAttachmentKind {
        DriverAttachmentKind::UserModeOnly
    }

    fn reply_deadline_ms(&self) -> u64 {
        DRIVER_REPLY_DEADLINE_MS
    }

    fn evaluate_kernel_floor(
        &self,
        floor: &[FloorRuleRef<'_>],
        action: FastActionClass,
        agent: &str,
        target: &str,
    ) -> Result<DriverFloorVerdict, WindowsSensorError> {
        match evaluate_floor_entries(floor, action, agent, target) {
            Some(hit) => Ok(DriverFloorVerdict::Matched {
                rule_id: hit.rule_id.to_string(),
                verdict: hit.verdict,
            }),
            None => Ok(DriverFloorVerdict::NoFloorHit),
        }
    }
}

impl DriverBootGuard {
    pub fn is_driver_disabled(&self) -> bool {
        self.driver_disabled
    }

    pub fn record_early_bugcheck(&mut self) -> bool {
        self.early_bugchecks = self.early_bugchecks.saturating_add(1);
        if self.early_bugchecks >= MAX_EARLY_BUGCHECKS {
            self.driver_disabled = true;
        }
        self.driver_disabled
    }

    pub fn clear_on_healthy_uptime(&mut self) {
        self.early_bugchecks = 0;
        self.driver_disabled = false;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn driver_seam_validates_header_evaluates_floor_and_disables_after_two_bugchecks() {
        let mut hdr = DriverProtocolHeader::default();
        assert!(hdr.validate().is_ok());
        hdr.magic = *b"BADMAGIC";
        assert!(hdr.validate().is_err());

        let zero_deadline = DriverProtocolHeader {
            reply_deadline_ms: 0,
            ..Default::default()
        };
        assert!(zero_deadline.validate().is_err());

        let huge_deadline = DriverProtocolHeader {
            reply_deadline_ms: MAX_DRIVER_REPLY_DEADLINE_MS + 1,
            ..Default::default()
        };
        assert!(huge_deadline.validate().is_err());

        let huge_payload = DriverProtocolHeader {
            payload_len: MAX_DRIVER_PAYLOAD_LEN + 1,
            ..Default::default()
        };
        assert!(huge_payload.validate().is_err());

        let seam = FallbackUserModeDriverSeam;
        assert_eq!(seam.attachment_kind(), DriverAttachmentKind::UserModeOnly);
        assert_eq!(seam.reply_deadline_ms(), DRIVER_REPLY_DEADLINE_MS);

        let rules = [FloorRuleRef {
            rule_id: "floor.cred",
            action_mask: FastActionClass::FileRead.bit(),
            prefixes: &[],
            contains: &[".ssh/"],
            agents: &[],
            verdict: FastVerdict::Deny,
        }];
        let verdict = seam
            .evaluate_kernel_floor(
                &rules,
                FastActionClass::FileRead,
                "claude-code",
                r"C:\Users\dev\.ssh\id_rsa",
            )
            .unwrap();
        assert_eq!(
            verdict,
            DriverFloorVerdict::Matched {
                rule_id: "floor.cred".into(),
                verdict: FastVerdict::Deny,
            }
        );

        let mut guard = DriverBootGuard::default();
        assert!(!guard.record_early_bugcheck());
        assert!(guard.record_early_bugcheck());
        assert!(guard.is_driver_disabled());
    }
}
