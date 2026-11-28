// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors

use serde::{Deserialize, Serialize};

use grdr_crypto::{SigningKeypair, verify_bytes};
use grdr_model::CodedError;
use grdr_ports::OrgId;

use crate::cell_types::{BUCKET_COUNT, CellEndpoint, CellId};
use crate::framing::{CanonicalFrame, ensure_clean_token, validate_https_endpoint};
use crate::{
    CODE_SAAS_INVALID_INPUT, CODE_SAAS_SIGNATURE_INVALID, CODE_SAAS_TENANT_MISMATCH, saas_error,
};

const ROUTE_TICKET_DOMAIN: &str = "grdr.saas.route-ticket.v1";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SignedRouteTicket {
    pub org_id: OrgId,
    pub device_id: String,
    pub bucket: u16,
    pub cell_id: CellId,
    pub api_endpoint: String,
    pub issued_at_s: i64,
    pub expires_at_s: i64,
    pub key_id: String,
    pub signature_b64: String,
}

pub fn sign_route_ticket(
    keypair: &SigningKeypair,
    org_id: &OrgId,
    device_id: &str,
    bucket: u16,
    cell: &CellEndpoint,
    issued_at_s: i64,
    ttl_seconds: i64,
) -> Result<SignedRouteTicket, CodedError> {
    ensure_clean_token("device_id", device_id)?;
    validate_https_endpoint(&cell.api_endpoint)?;
    if bucket >= BUCKET_COUNT || ttl_seconds <= 0 {
        return Err(saas_error(
            CODE_SAAS_INVALID_INPUT,
            "Route ticket requires bucket < 4096 and positive TTL.",
            "Pass a valid shard bucket and positive ttl_seconds.",
        ));
    }
    let expires_at_s = issued_at_s.checked_add(ttl_seconds).ok_or_else(|| {
        saas_error(
            CODE_SAAS_INVALID_INPUT,
            "Route ticket expiration timestamp overflowed.",
            "Pass a smaller ttl_seconds.",
        )
    })?;
    let mut ticket = SignedRouteTicket {
        org_id: org_id.clone(),
        device_id: device_id.to_owned(),
        bucket,
        cell_id: cell.cell_id.clone(),
        api_endpoint: cell.api_endpoint.clone(),
        issued_at_s,
        expires_at_s,
        key_id: keypair.key_id().to_owned(),
        signature_b64: String::new(),
    };
    let frame = canonical_ticket_frame(&ticket);
    ticket.signature_b64 = keypair.sign_bytes(ROUTE_TICKET_DOMAIN, frame.as_bytes());
    Ok(ticket)
}

pub fn verify_route_ticket(
    public_key_b64: &str,
    ticket: &SignedRouteTicket,
    expected_org: &OrgId,
    expected_device_id: &str,
    now_s: i64,
) -> Result<(), CodedError> {
    ensure_clean_token("expected_device_id", expected_device_id)?;
    ensure_clean_token("device_id", &ticket.device_id)?;
    ensure_clean_token("key_id", &ticket.key_id)?;
    validate_https_endpoint(&ticket.api_endpoint)?;
    if ticket.org_id != *expected_org || ticket.device_id != expected_device_id {
        return Err(saas_error(
            CODE_SAAS_TENANT_MISMATCH,
            "Route ticket tenant or device identifier does not match caller.",
            "Reject cross-tenant or cross-device route tickets.",
        ));
    }
    if ticket.bucket >= BUCKET_COUNT || ticket.expires_at_s <= ticket.issued_at_s {
        return Err(saas_error(
            CODE_SAAS_INVALID_INPUT,
            "Route ticket carries invalid shard bucket or validity window.",
            "Re-issue a valid route ticket.",
        ));
    }
    if now_s > ticket.expires_at_s {
        return Err(saas_error(
            CODE_SAAS_SIGNATURE_INVALID,
            "Signed route ticket has expired.",
            "Request a fresh cell route ticket from the control router.",
        ));
    }
    let frame = canonical_ticket_frame(ticket);
    verify_bytes(
        public_key_b64,
        ROUTE_TICKET_DOMAIN,
        frame.as_bytes(),
        &ticket.signature_b64,
    )
    .map_err(|_| {
        saas_error(
            CODE_SAAS_SIGNATURE_INVALID,
            "Route ticket Ed25519 signature verification failed.",
            "Reject tampered redirects and re-resolve from a trusted router key.",
        )
    })
}

fn canonical_ticket_frame(ticket: &SignedRouteTicket) -> CanonicalFrame {
    let mut frame = CanonicalFrame::new("route_ticket_v1");
    frame.push_str(ticket.org_id.as_str());
    frame.push_str(&ticket.device_id);
    frame.push_u32(u32::from(ticket.bucket));
    frame.push_str(ticket.cell_id.as_str());
    frame.push_str(&ticket.api_endpoint);
    frame.push_i64(ticket.issued_at_s);
    frame.push_i64(ticket.expires_at_s);
    frame.push_str(&ticket.key_id);
    frame
}
