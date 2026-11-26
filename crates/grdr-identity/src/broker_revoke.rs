// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors
#![deny(clippy::arithmetic_side_effects)]

use crate::IdentityError;
use crate::broker::CredentialBroker;
use crate::broker_types::{LeaseRecord, LeaseState, SessionRevocationReport};
use crate::issuer::CredentialIssuer;

impl CredentialBroker {
    pub async fn revoke_lease_with_issuer<I: CredentialIssuer>(
        &mut self,
        lease_id: &str,
        issuer: &I,
    ) -> Result<bool, IdentityError> {
        let is_active = self
            .leases
            .get(lease_id)
            .is_some_and(|l| l.state == LeaseState::Active);
        let pending = self.pending_revocations.get(lease_id).cloned();
        if !is_active && pending.is_none() {
            return Ok(false);
        }
        let handle = pending.or_else(|| self.revocation_handles.get(lease_id).cloned());
        if let Some(tok) = handle
            && issuer.supports_revocation()
        {
            issuer.revoke_credential(tok.as_str()).await?;
        }
        self.revocation_handles.remove(lease_id);
        self.pending_revocations.remove(lease_id);
        if let Some(lease) = self.leases.get_mut(lease_id) {
            lease.state = LeaseState::Revoked;
            lease.has_revocation_handle = false;
        }
        Ok(true)
    }

    pub async fn revoke_by_session_with_issuer<I: CredentialIssuer>(
        &mut self,
        session_id: &str,
        issuer: &I,
    ) -> SessionRevocationReport {
        let target_ids: Vec<String> = self
            .leases
            .values()
            .filter(|l| l.state == LeaseState::Active && l.session_id == session_id)
            .map(|l| l.lease_id.clone())
            .collect();
        let mut revoked: usize = 0;
        let mut pending_lease_ids = Vec::new();
        for lease_id in target_ids {
            let handle = self.revocation_handles.get(&lease_id).cloned();
            if let Some(tok) = handle
                && issuer.supports_revocation()
                && issuer.revoke_credential(tok.as_str()).await.is_err()
            {
                self.pending_revocations.insert(lease_id.clone(), tok);
                pending_lease_ids.push(lease_id);
                continue;
            }
            self.revocation_handles.remove(&lease_id);
            self.pending_revocations.remove(&lease_id);
            if let Some(lease) = self.leases.get_mut(&lease_id) {
                lease.state = LeaseState::Revoked;
                lease.has_revocation_handle = false;
                revoked = revoked.saturating_add(1);
            }
        }
        SessionRevocationReport {
            revoked,
            pending_lease_ids,
        }
    }

    #[must_use]
    pub fn pending_revocation_ids(&self) -> Vec<String> {
        self.pending_revocations.keys().cloned().collect()
    }

    pub fn revoke_by_session(&mut self, session_id: &str) -> usize {
        self.revoke_matching(|lease| lease.session_id == session_id)
    }

    pub fn revoke_by_instance(&mut self, instance_spiffe_id: &str) -> usize {
        self.revoke_matching(|lease| lease.instance_spiffe_id == instance_spiffe_id)
    }

    fn revoke_matching<F>(&mut self, mut predicate: F) -> usize
    where
        F: FnMut(&LeaseRecord) -> bool,
    {
        let mut count: usize = 0;
        for lease in self.leases.values_mut() {
            if lease.state == LeaseState::Active && predicate(lease) {
                lease.state = LeaseState::Revoked;
                if let Some(handle) = self.revocation_handles.remove(&lease.lease_id) {
                    self.pending_revocations
                        .insert(lease.lease_id.clone(), handle);
                    lease.has_revocation_handle = true;
                } else {
                    lease.has_revocation_handle = false;
                }
                count = count.saturating_add(1);
            }
        }
        count
    }
}
