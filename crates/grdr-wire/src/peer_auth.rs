// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors
#![deny(clippy::arithmetic_side_effects)]

//! Endpoint peer authorization and single-step handshake protocol
//! (`docs/decisions/ADR-0051`, `docs/design/11`).

use grdr_crypto::fill_random;

use crate::frame::{
    CreditFlow, DEFAULT_INITIAL_CREDIT, IPC_WIRE_VERSION, IpcFrameError, MAX_CREDIT_WINDOW,
    WireFrame, WirePayload, decode_proto_payload, encode_proto_payload,
};
use crate::limits::embedded_limits;
use crate::messages::{
    CreditGrantFrame, EndpointServiceKind, HandoverStage, HelloFrame, ReadyFrame,
};
use crate::peer_policy::{verify_client_peer, verify_server_peer};
pub use crate::peer_types::*;

const MIN_CLIENT_NONCE_LEN: usize = 16;
const MAX_CLIENT_NONCE_LEN: usize = 64;
const SERVER_NONCE_ENTROPY_LEN: usize = 16;
const MAX_SERVER_NONCE_LEN: usize = MAX_CLIENT_NONCE_LEN + SERVER_NONCE_ENTROPY_LEN;

pub trait FrameStream {
    fn send_frame_bytes(&mut self, payload: &[u8]) -> Result<(), IpcFrameError>;
    fn recv_frame_bytes(&mut self, max_bytes: usize) -> Result<Vec<u8>, IpcFrameError>;
}

#[derive(Debug)]
pub struct AuthenticatedChannel<S> {
    stream: S,
    peer: VerifiedPeer,
    credit: CreditFlow,
    next_seq: u64,
    max_frame_bytes: usize,
}

#[derive(Debug)]
pub struct PendingPeer<S> {
    stream: S,
    pre_peer: Option<VerifiedPeer>,
    policy: ServerIdentityPolicy,
    connected_at_ticks: u64,
}

const fn profile_wire_id(profile: Profile) -> i32 {
    match profile {
        Profile::Protected => 1,
        Profile::User => 2,
        Profile::Inherited => 3,
    }
}

fn validate_max_frame_limit(requested: usize) -> Result<usize, Refusal> {
    let embedded = embedded_limits().map_err(|err| {
        Refusal::ProtocolRejected(Evidence::FrameError {
            detail: err.to_string(),
        })
    })?;
    if requested == 0 || requested > embedded.max_frame_bytes {
        return Err(Refusal::ProtocolRejected(Evidence::FrameError {
            detail: "max_frame_bytes outside configured embedded bounds".to_string(),
        }));
    }
    Ok(requested)
}

fn validate_client_nonce(nonce: &[u8]) -> Result<(), Refusal> {
    if !(MIN_CLIENT_NONCE_LEN..=MAX_CLIENT_NONCE_LEN).contains(&nonce.len()) {
        return Err(Refusal::ProtocolRejected(Evidence::FrameError {
            detail: "HelloFrame client_nonce must be 16..=64 bytes".to_string(),
        }));
    }
    Ok(())
}

impl<S: FrameStream> PendingPeer<S> {
    pub fn first_frame(
        self,
        expected_service: EndpointServiceKind,
        floor_digest: &str,
        epoch: u64,
        handover_stage: HandoverStage,
        max_frame_bytes: usize,
    ) -> Result<(AuthenticatedChannel<S>, HelloFrame), Refusal> {
        self.first_frame_with_claims(
            expected_service,
            floor_digest,
            epoch,
            handover_stage,
            max_frame_bytes,
            None::<fn(&mut S) -> Result<OsPeerClaims, Refusal>>,
        )
    }

    pub fn first_frame_with_claims<F>(
        mut self,
        expected_service: EndpointServiceKind,
        floor_digest: &str,
        epoch: u64,
        handover_stage: HandoverStage,
        max_frame_bytes: usize,
        post_read: Option<F>,
    ) -> Result<(AuthenticatedChannel<S>, HelloFrame), Refusal>
    where
        F: FnOnce(&mut S) -> Result<OsPeerClaims, Refusal>,
    {
        let bounded_max = validate_max_frame_limit(max_frame_bytes)?;
        let bytes = self.stream.recv_frame_bytes(bounded_max).map_err(|err| {
            Refusal::ProtocolRejected(Evidence::FrameError {
                detail: err.to_string(),
            })
        })?;
        let frame = decode_proto_payload(&bytes, bounded_max).map_err(|err| {
            Refusal::ProtocolRejected(Evidence::FrameError {
                detail: err.to_string(),
            })
        })?;
        let Some(WirePayload::Hello(hello)) = frame.payload else {
            return Err(Refusal::ProtocolRejected(Evidence::FrameError {
                detail: "first frame on channel must be HelloFrame".to_string(),
            }));
        };
        if hello.protocol_version != IPC_WIRE_VERSION {
            return Err(Refusal::ProtocolRejected(
                Evidence::ProtocolVersionMismatch {
                    expected: IPC_WIRE_VERSION,
                    found: hello.protocol_version,
                },
            ));
        }
        if hello.service != expected_service as i32 {
            return Err(Refusal::ProtocolRejected(Evidence::ChannelMismatch {
                expected: expected_service,
                found: hello.service,
            }));
        }
        let expected_profile_wire = profile_wire_id(self.policy.profile);
        if hello.profile != expected_profile_wire {
            return Err(Refusal::PolicyProfileMismatch(Evidence::ProfileRejected {
                profile: self.policy.profile,
                detail: "peer advertised unexpected profile".to_string(),
            }));
        }
        validate_client_nonce(&hello.client_nonce)?;

        let peer = match (self.pre_peer, post_read) {
            (Some(verified), None) => verified,
            (_, Some(verify_fn)) => {
                let claims = verify_fn(&mut self.stream)?;
                verify_client_peer(&claims, self.connected_at_ticks, &self.policy)?
            }
            (None, None) => {
                return Err(Refusal::UnauthenticatedPeer(Evidence::MissingPeerToken {
                    detail: "deferred peer verification callback required".to_string(),
                }));
            }
        };

        let mut server_entropy = [0u8; SERVER_NONCE_ENTROPY_LEN];
        fill_random(&mut server_entropy).map_err(|_| {
            Refusal::ProtocolRejected(Evidence::FrameError {
                detail: "server CSPRNG failure".to_string(),
            })
        })?;
        let mut server_nonce = Vec::with_capacity(
            hello
                .client_nonce
                .len()
                .saturating_add(SERVER_NONCE_ENTROPY_LEN),
        );
        server_nonce.extend_from_slice(&hello.client_nonce);
        server_nonce.extend_from_slice(&server_entropy);

        let max_u32 = u32::try_from(bounded_max).map_err(|_| {
            Refusal::ProtocolRejected(Evidence::FrameError {
                detail: "max_frame_bytes overflows u32".to_string(),
            })
        })?;
        let ready = WireFrame::with_payload(
            frame.stream_id,
            1,
            WirePayload::Ready(ReadyFrame {
                protocol_version: IPC_WIRE_VERSION,
                initial_credit: DEFAULT_INITIAL_CREDIT,
                max_frame_bytes: max_u32,
                server_nonce,
                floor_digest: floor_digest.to_string(),
                epoch,
                handover_stage: handover_stage as i32,
            }),
        );
        let encoded = encode_proto_payload(&ready, bounded_max).map_err(|err| {
            Refusal::ProtocolRejected(Evidence::FrameError {
                detail: err.to_string(),
            })
        })?;
        self.stream.send_frame_bytes(&encoded).map_err(|err| {
            Refusal::ProtocolRejected(Evidence::FrameError {
                detail: err.to_string(),
            })
        })?;
        Ok((
            AuthenticatedChannel {
                stream: self.stream,
                peer,
                credit: CreditFlow::new(DEFAULT_INITIAL_CREDIT),
                next_seq: 2,
                max_frame_bytes: bounded_max,
            },
            hello,
        ))
    }
}

impl<S: FrameStream> AuthenticatedChannel<S> {
    #[must_use]
    pub const fn peer(&self) -> &VerifiedPeer {
        &self.peer
    }

    #[must_use]
    pub const fn credit(&self) -> &CreditFlow {
        &self.credit
    }

    #[must_use]
    pub const fn max_frame_bytes(&self) -> usize {
        self.max_frame_bytes
    }

    pub fn stream_mut(&mut self) -> &mut S {
        &mut self.stream
    }

    pub fn send_frame(&mut self, mut frame: WireFrame) -> Result<(), Refusal> {
        if matches!(
            frame.payload,
            Some(WirePayload::Hello(_) | WirePayload::Ready(_))
        ) {
            return Err(Refusal::ProtocolRejected(Evidence::FrameError {
                detail: "handshake frames prohibited after channel open".to_string(),
            }));
        }
        let mut next_credit = self.credit;
        next_credit.try_consume_send(&frame).map_err(|err| {
            Refusal::ProtocolRejected(Evidence::FrameError {
                detail: err.to_string(),
            })
        })?;
        if !matches!(frame.payload, Some(WirePayload::CreditGrant(_)))
            && frame.credit_delta == 0
            && let Some(delta) = next_credit.recommended_inbound_grant()
        {
            next_credit.grant_inbound(delta).map_err(|err| {
                Refusal::ProtocolRejected(Evidence::FrameError {
                    detail: err.to_string(),
                })
            })?;
            frame.credit_delta = delta;
        }
        frame.seq = self.next_seq;
        let payload = encode_proto_payload(&frame, self.max_frame_bytes).map_err(|err| {
            Refusal::ProtocolRejected(Evidence::FrameError {
                detail: err.to_string(),
            })
        })?;
        self.stream.send_frame_bytes(&payload).map_err(|err| {
            Refusal::ProtocolRejected(Evidence::FrameError {
                detail: err.to_string(),
            })
        })?;
        self.credit = next_credit;
        self.next_seq = self.next_seq.saturating_add(1);
        Ok(())
    }

    pub fn send_credit_grant(&mut self, delta: u32) -> Result<(), Refusal> {
        let mut next_credit = self.credit;
        let granted = next_credit.grant_inbound(delta).map_err(|err| {
            Refusal::ProtocolRejected(Evidence::FrameError {
                detail: err.to_string(),
            })
        })?;
        let frame = WireFrame::with_payload(
            0,
            self.next_seq,
            WirePayload::CreditGrant(CreditGrantFrame { delta: granted }),
        );
        let payload = encode_proto_payload(&frame, self.max_frame_bytes).map_err(|err| {
            Refusal::ProtocolRejected(Evidence::FrameError {
                detail: err.to_string(),
            })
        })?;
        self.stream.send_frame_bytes(&payload).map_err(|err| {
            Refusal::ProtocolRejected(Evidence::FrameError {
                detail: err.to_string(),
            })
        })?;
        self.credit = next_credit;
        self.next_seq = self.next_seq.saturating_add(1);
        Ok(())
    }

    pub fn recv_frame(&mut self) -> Result<WireFrame, Refusal> {
        let bytes = self
            .stream
            .recv_frame_bytes(self.max_frame_bytes)
            .map_err(|err| {
                Refusal::ProtocolRejected(Evidence::FrameError {
                    detail: err.to_string(),
                })
            })?;
        let frame = decode_proto_payload(&bytes, self.max_frame_bytes).map_err(|err| {
            Refusal::ProtocolRejected(Evidence::FrameError {
                detail: err.to_string(),
            })
        })?;
        if matches!(
            frame.payload,
            Some(WirePayload::Hello(_) | WirePayload::Ready(_))
        ) {
            return Err(Refusal::ProtocolRejected(Evidence::FrameError {
                detail: "unexpected handshake frame after channel open".to_string(),
            }));
        }
        self.credit.record_inbound(&frame).map_err(|err| {
            Refusal::ProtocolRejected(Evidence::FrameError {
                detail: err.to_string(),
            })
        })?;
        Ok(frame)
    }

    pub fn into_inner(self) -> S {
        self.stream
    }
}

pub fn accept<S: FrameStream>(
    stream: S,
    claims: &OsPeerClaims,
    connected_at_ticks: u64,
    policy: &ServerIdentityPolicy,
) -> Result<PendingPeer<S>, Refusal> {
    let peer = verify_client_peer(claims, connected_at_ticks, policy)?;
    Ok(PendingPeer {
        stream,
        pre_peer: Some(peer),
        policy: policy.clone(),
        connected_at_ticks,
    })
}

pub fn accept_deferred_windows<S: FrameStream>(
    stream: S,
    connected_at_ticks: u64,
    policy: &ServerIdentityPolicy,
) -> Result<PendingPeer<S>, Refusal> {
    if policy.profile == Profile::Inherited {
        return Err(Refusal::PolicyProfileMismatch(Evidence::ProfileRejected {
            profile: policy.profile,
            detail: "deferred windows peer invalid under Inherited profile".to_string(),
        }));
    }
    Ok(PendingPeer {
        stream,
        pre_peer: None,
        policy: policy.clone(),
        connected_at_ticks,
    })
}

pub fn open<S: FrameStream>(
    mut stream: S,
    claims: &OsPeerClaims,
    connected_at_ticks: u64,
    policy: &ClientIdentityPolicy,
    hello: HelloFrame,
    max_frame_bytes: usize,
) -> Result<(AuthenticatedChannel<S>, ReadyFrame), Refusal> {
    let bounded_max = validate_max_frame_limit(max_frame_bytes)?;
    let peer = verify_server_peer(claims, connected_at_ticks, policy)?;
    if hello.protocol_version != IPC_WIRE_VERSION {
        return Err(Refusal::ProtocolRejected(
            Evidence::ProtocolVersionMismatch {
                expected: IPC_WIRE_VERSION,
                found: hello.protocol_version,
            },
        ));
    }
    if hello.profile != profile_wire_id(policy.profile) {
        return Err(Refusal::PolicyProfileMismatch(Evidence::ProfileRejected {
            profile: policy.profile,
            detail: "client HelloFrame profile disagrees with policy".to_string(),
        }));
    }
    validate_client_nonce(&hello.client_nonce)?;
    let sent_nonce = hello.client_nonce.clone();
    let frame = WireFrame::with_payload(1, 1, WirePayload::Hello(hello));
    let encoded = encode_proto_payload(&frame, bounded_max).map_err(|err| {
        Refusal::ProtocolRejected(Evidence::FrameError {
            detail: err.to_string(),
        })
    })?;
    stream.send_frame_bytes(&encoded).map_err(|err| {
        Refusal::ProtocolRejected(Evidence::FrameError {
            detail: err.to_string(),
        })
    })?;
    let reply_bytes = stream.recv_frame_bytes(bounded_max).map_err(|err| {
        Refusal::ProtocolRejected(Evidence::FrameError {
            detail: err.to_string(),
        })
    })?;
    let reply = decode_proto_payload(&reply_bytes, bounded_max).map_err(|err| {
        Refusal::ProtocolRejected(Evidence::FrameError {
            detail: err.to_string(),
        })
    })?;
    if reply.stream_id != 1 {
        return Err(Refusal::ProtocolRejected(Evidence::FrameError {
            detail: "server ReadyFrame stream_id mismatch".to_string(),
        }));
    }
    let Some(WirePayload::Ready(ready)) = reply.payload else {
        return Err(Refusal::ProtocolRejected(Evidence::FrameError {
            detail: "server reply to HelloFrame must be ReadyFrame".to_string(),
        }));
    };
    if ready.protocol_version != IPC_WIRE_VERSION {
        return Err(Refusal::ProtocolRejected(
            Evidence::ProtocolVersionMismatch {
                expected: IPC_WIRE_VERSION,
                found: ready.protocol_version,
            },
        ));
    }
    if ready.initial_credit == 0 || ready.initial_credit > MAX_CREDIT_WINDOW {
        return Err(Refusal::ProtocolRejected(Evidence::FrameError {
            detail: "server ReadyFrame initial_credit out of bounds".to_string(),
        }));
    }
    if ready.max_frame_bytes == 0 {
        return Err(Refusal::ProtocolRejected(Evidence::FrameError {
            detail: "server ReadyFrame max_frame_bytes must be > 0".to_string(),
        }));
    }
    let server_max = usize::try_from(ready.max_frame_bytes).map_err(|_| {
        Refusal::ProtocolRejected(Evidence::FrameError {
            detail: "server max_frame_bytes overflows usize".to_string(),
        })
    })?;
    let negotiated_max = bounded_max.min(server_max);
    if !ready.server_nonce.starts_with(&sent_nonce)
        || ready.server_nonce.len() < sent_nonce.len().saturating_add(SERVER_NONCE_ENTROPY_LEN)
        || ready.server_nonce.len() > MAX_SERVER_NONCE_LEN
    {
        return Err(Refusal::ProtocolRejected(Evidence::FrameError {
            detail: "server ReadyFrame server_nonce challenge failed".to_string(),
        }));
    }
    Ok((
        AuthenticatedChannel {
            stream,
            peer,
            credit: CreditFlow::new(ready.initial_credit),
            next_seq: 2,
            max_frame_bytes: negotiated_max,
        },
        ready,
    ))
}
