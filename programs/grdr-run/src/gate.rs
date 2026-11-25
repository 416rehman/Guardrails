// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors

//! Pre-launch authorization gate using `grdr-daemon` or verified signed `CompiledFloorTable`.

use std::future::Future;
use std::net::{IpAddr, Ipv4Addr};
use std::pin::Pin;
use std::time::Duration;

use jiff::Timestamp;
use uuid::Uuid;

use grdr_core::compile::evaluate_compiled_floor;
use grdr_core::policy::{essentials_pack, evaluate};
use grdr_crypto::verify_floor_table;
use grdr_model::{
    ActionAttempt, ActionClass, CompiledFloorTable, ControlPoint, DecideInput, DecisionReceipt,
    KillSwitchState, ProvenanceSource, SignatureStatus, TrustedKeyInfo, Verdict,
};

use crate::RunError;
use crate::planner::LaunchRequestSpec;

pub const DEFAULT_DAEMON_PORT: u16 = 8765;
pub const DEFAULT_GATE_TIMEOUT_MS: u64 = 1_500;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GateVerdict {
    Allow {
        source: GateDecisionSource,
    },
    Deny {
        source: GateDecisionSource,
        reason: String,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GateDecisionSource {
    Daemon,
    SignedCompiledFloor { degraded: bool },
}

pub type GateFuture<'a> =
    Pin<Box<dyn Future<Output = Result<DecisionReceipt, RunError>> + Send + 'a>>;

pub trait LaunchGateClient: Send + Sync {
    fn authorize<'a>(&'a self, attempt: &'a ActionAttempt) -> GateFuture<'a>;
}

#[derive(Debug, Clone)]
pub struct LoopbackGateClient {
    http: reqwest::Client,
    endpoint_url: String,
    timeout: Duration,
}

impl LoopbackGateClient {
    pub fn from_loopback_port(port: u16, timeout_ms: u64) -> Result<Self, RunError> {
        let host = IpAddr::V4(Ipv4Addr::LOCALHOST);
        let endpoint_url = format!("http://{host}:{port}/local/v1/decide");
        let bounded_ms = timeout_ms.clamp(50, 15_000);
        let http = reqwest::Client::builder()
            .timeout(Duration::from_millis(bounded_ms))
            .no_proxy()
            .build()
            .map_err(|e| RunError::GateUnavailable(e.to_string()))?;
        Ok(Self {
            http,
            endpoint_url,
            timeout: Duration::from_millis(bounded_ms),
        })
    }
}

impl LaunchGateClient for LoopbackGateClient {
    fn authorize<'a>(&'a self, attempt: &'a ActionAttempt) -> GateFuture<'a> {
        Box::pin(async move {
            let input = DecideInput {
                session_id: Some(attempt.session_id.clone()),
                device_id: Some(attempt.device_id.clone()),
                device_name: Some(attempt.device_name.clone()),
                agent_name: attempt.agent_name.clone(),
                action_class: attempt.action_class,
                control_point: Some(attempt.control_point),
                target: attempt.target.clone(),
                summary: Some(attempt.summary.clone()),
            };
            let send = self.http.post(&self.endpoint_url).json(&input).send();
            let resp = tokio::time::timeout(self.timeout, send)
                .await
                .map_err(|_| RunError::GateUnavailable("daemon request timed out".into()))?
                .map_err(|e| RunError::GateUnavailable(e.to_string()))?;
            if !resp.status().is_success() {
                return Err(RunError::GateUnavailable(format!(
                    "daemon HTTP {}",
                    resp.status()
                )));
            }
            resp.json::<DecisionReceipt>()
                .await
                .map_err(|e| RunError::GateUnavailable(e.to_string()))
        })
    }
}

#[must_use]
pub fn launch_attempt(req: &LaunchRequestSpec, now: Timestamp) -> ActionAttempt {
    let action_class = if req.tool_call_id.is_some() {
        ActionClass::Exec
    } else {
        ActionClass::AgentSpawn
    };
    ActionAttempt {
        id: format!("att_{}", Uuid::now_v7().simple()),
        session_id: req.session_id.clone(),
        device_id: "dev-local".into(),
        device_name: "local-host".into(),
        agent_name: req.agent_name.clone(),
        action_class,
        control_point: ControlPoint::Sandbox,
        target: req.program.clone(),
        summary: format!(
            "grdr-run strategy={} workspace={}",
            req.strategy.as_str(),
            req.workspace_root
        ),
        timestamp: now,
        provenance: ProvenanceSource::Mediated,
        ..Default::default()
    }
}

/// Evaluates launch authorization via daemon first, falling back ONLY to a
/// cryptographically verified `CompiledFloorTable` (`D-14`). Fails closed otherwise.
pub async fn authorize_launch<C: LaunchGateClient>(
    client: &C,
    req: &LaunchRequestSpec,
    floor: Option<(&CompiledFloorTable, &[TrustedKeyInfo])>,
    now: Timestamp,
) -> Result<GateVerdict, RunError> {
    let attempt = launch_attempt(req, now);
    match client.authorize(&attempt).await {
        Ok(receipt) => match receipt.verdict {
            Verdict::Allow => Ok(GateVerdict::Allow {
                source: GateDecisionSource::Daemon,
            }),
            other => Ok(GateVerdict::Deny {
                source: GateDecisionSource::Daemon,
                reason: format!("verdict {other:?}: {}", receipt.reason),
            }),
        },
        Err(daemon_err) => {
            let Some((table, trusted_keys)) = floor else {
                return Err(daemon_err);
            };
            if verify_floor_table(table, trusted_keys) != SignatureStatus::Verified {
                return Err(RunError::FloorUntrusted);
            }
            tracing::warn!(
                sr = "SR-15",
                degraded = true,
                session_id = %attempt.session_id,
                action_class = attempt.action_class.as_str(),
                "grdr-daemon unavailable; evaluating signed offline compiled floor in degraded mode"
            );
            let source = GateDecisionSource::SignedCompiledFloor { degraded: true };
            if let Some(matched) = evaluate_compiled_floor(
                table,
                attempt.action_class,
                &attempt.agent_name,
                &attempt.target,
            ) {
                return match matched.verdict {
                    Verdict::Allow if attempt.action_class != ActionClass::AgentSpawn => {
                        Ok(GateVerdict::Allow { source })
                    }
                    Verdict::Allow => Ok(GateVerdict::Deny {
                        source,
                        reason:
                            "D-15: session container spawn fails closed while daemon is offline"
                                .into(),
                    }),
                    Verdict::Deny | Verdict::StepUp | Verdict::Defer | Verdict::Modify => {
                        Ok(GateVerdict::Deny {
                            source,
                            reason: format!(
                                "compiled floor rule `{}` denied launch",
                                matched.rule_id
                            ),
                        })
                    }
                };
            }
            // D-15: Session container starts (`AgentSpawn`) always fail closed on daemon loss.
            if attempt.action_class == ActionClass::AgentSpawn {
                return Ok(GateVerdict::Deny {
                    source,
                    reason: "D-15: session container launch denied while grdr-daemon is offline"
                        .into(),
                });
            }
            let packs = [essentials_pack()];
            let receipt = evaluate(&attempt, &packs, &[], &KillSwitchState::Inactive, now);
            match receipt.verdict {
                Verdict::Allow => Ok(GateVerdict::Allow { source }),
                Verdict::Deny | Verdict::StepUp | Verdict::Defer | Verdict::Modify => {
                    Ok(GateVerdict::Deny {
                        source,
                        reason: receipt.reason,
                    })
                }
            }
        }
    }
}
