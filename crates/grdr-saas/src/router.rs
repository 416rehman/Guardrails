// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use grdr_compat::SemVer;
use grdr_model::CodedError;
use grdr_ports::OrgId;

use crate::cell_types::{
    BucketRange, CellCapacityVector, CellEndpoint, CellId, CellSplitResult, CellState,
    OrgPlacement, RegionId, device_bucket,
};
use crate::config::SaasOperationalBounds;
use crate::framing::{ensure_clean_token, validate_https_endpoint};
use crate::gates::{SanctionsDecision, SanctionsScreen};
use crate::{
    CODE_SAAS_CELL_UNAVAILABLE, CODE_SAAS_INVALID_INPUT, CODE_SAAS_REGION_VIOLATION, saas_error,
};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OrgPlacementInput {
    pub org_id: OrgId,
    pub required_region: RegionId,
    pub preferred_cell: Option<CellId>,
    pub iso_country: String,
    pub entity_name: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CellRouter {
    bounds: SaasOperationalBounds,
    cells: BTreeMap<CellId, CellEndpoint>,
    placements: BTreeMap<OrgId, OrgPlacement>,
}

impl CellRouter {
    pub fn try_new(bounds: SaasOperationalBounds) -> Result<Self, CodedError> {
        bounds.validate()?;
        Ok(Self {
            bounds,
            cells: BTreeMap::new(),
            placements: BTreeMap::new(),
        })
    }

    pub fn new() -> Result<Self, CodedError> {
        Self::try_new(SaasOperationalBounds::load_embedded()?)
    }

    pub fn register_cell(&mut self, cell: CellEndpoint) -> Result<(), CodedError> {
        BucketRange::new(cell.buckets.start_inclusive, cell.buckets.end_exclusive)?;
        validate_https_endpoint(&cell.api_endpoint)?;
        if self.cells.contains_key(&cell.cell_id) {
            return Err(saas_error(
                CODE_SAAS_INVALID_INPUT,
                format!("Cell `{}` is already registered.", cell.cell_id.as_str()),
                "Use update_cell_state or update_cell_capacity instead of re-registering.",
            ));
        }
        for existing in self.cells.values() {
            if existing.region == cell.region
                && existing.state != CellState::Decommissioned
                && existing.buckets.overlaps(&cell.buckets)
            {
                return Err(saas_error(
                    CODE_SAAS_INVALID_INPUT,
                    format!(
                        "Cell `{}` bucket range overlaps active cell `{}` in region `{}`.",
                        cell.cell_id.as_str(),
                        existing.cell_id.as_str(),
                        cell.region.as_str()
                    ),
                    "Assign disjoint bucket ranges or split an existing cell cleanly.",
                ));
            }
        }
        self.cells.insert(cell.cell_id.clone(), cell);
        Ok(())
    }

    pub fn update_cell_state(
        &mut self,
        cell_id: &CellId,
        state: CellState,
    ) -> Result<(), CodedError> {
        let current = self.cells.get(cell_id).cloned().ok_or_else(|| {
            saas_error(
                CODE_SAAS_CELL_UNAVAILABLE,
                format!("Unknown cell `{}`.", cell_id.as_str()),
                "Register the cell before updating state.",
            )
        })?;
        if current.state == CellState::Decommissioned && state != CellState::Decommissioned {
            return Err(saas_error(
                CODE_SAAS_CELL_UNAVAILABLE,
                format!(
                    "Decommissioned cell `{}` cannot transition back to active service.",
                    cell_id.as_str()
                ),
                "Register a replacement cell with disjoint bucket ownership.",
            ));
        }
        if state != CellState::Decommissioned {
            for other in self.cells.values() {
                if other.cell_id != *cell_id
                    && other.region == current.region
                    && other.state != CellState::Decommissioned
                    && other.buckets.overlaps(&current.buckets)
                {
                    return Err(saas_error(
                        CODE_SAAS_INVALID_INPUT,
                        format!(
                            "Cell `{}` bucket range overlaps active cell `{}` in region `{}`.",
                            cell_id.as_str(),
                            other.cell_id.as_str(),
                            current.region.as_str()
                        ),
                        "Assign disjoint bucket ranges before activating the cell.",
                    ));
                }
            }
        }
        if let Some(cell) = self.cells.get_mut(cell_id) {
            cell.state = state;
        }
        Ok(())
    }

    pub fn update_cell_capacity(
        &mut self,
        cell_id: &CellId,
        capacity: CellCapacityVector,
    ) -> Result<(), CodedError> {
        let cell = self.cells.get_mut(cell_id).ok_or_else(|| {
            saas_error(
                CODE_SAAS_CELL_UNAVAILABLE,
                format!("Unknown cell `{}`.", cell_id.as_str()),
                "Register the cell before updating capacity.",
            )
        })?;
        cell.capacity = capacity;
        Ok(())
    }

    #[must_use]
    pub fn cell(&self, cell_id: &CellId) -> Option<&CellEndpoint> {
        self.cells.get(cell_id)
    }

    #[must_use]
    pub fn placement(&self, org_id: &OrgId) -> Option<&OrgPlacement> {
        self.placements.get(org_id)
    }

    pub fn place_org(
        &mut self,
        input: OrgPlacementInput,
        sanctions: &dyn SanctionsScreen,
    ) -> Result<OrgPlacement, CodedError> {
        match sanctions.screen_org(&input.org_id, &input.iso_country, &input.entity_name) {
            SanctionsDecision::Clear => {}
            SanctionsDecision::ManualReview { reason } | SanctionsDecision::Blocked { reason } => {
                return Err(saas_error(
                    CODE_SAAS_REGION_VIOLATION,
                    format!(
                        "Tenant `{}` failed compliance screening: {reason}.",
                        input.org_id.as_str()
                    ),
                    "Resolve sanctions/export review before placing tenant in a cell.",
                ));
            }
        }

        if let Some(existing) = self.placements.get(&input.org_id)
            && existing.required_region != input.required_region
        {
            return Err(saas_error(
                CODE_SAAS_REGION_VIOLATION,
                format!(
                    "Organisation `{}` is pinned to region `{}` and cannot move to `{}`.",
                    input.org_id.as_str(),
                    existing.required_region.as_str(),
                    input.required_region.as_str()
                ),
                "Run explicit customer offboarding/export before changing data residency.",
            ));
        }

        let bounds = self.bounds;
        let selected = match input.preferred_cell.as_ref() {
            Some(cell_id) => {
                let cell = self.cells.get(cell_id).ok_or_else(|| {
                    saas_error(
                        CODE_SAAS_CELL_UNAVAILABLE,
                        format!("Unknown cell `{}`.", cell_id.as_str()),
                        "Register the cell before assigning organisations to it.",
                    )
                })?;
                ensure_cell_placeable(cell, &input.required_region, &bounds)?;
                cell.cell_id.clone()
            }
            None => self
                .cells
                .values()
                .filter(|c| {
                    c.region == input.required_region
                        && c.state == CellState::Active
                        && c.capacity.can_accept_org(&bounds)
                })
                .min_by_key(|c| c.capacity.max_utilization_pct())
                .map(|c| c.cell_id.clone())
                .ok_or_else(|| {
                    saas_error(
                        CODE_SAAS_CELL_UNAVAILABLE,
                        format!(
                            "No active cell with reserve capacity in region `{}`.",
                            input.required_region.as_str()
                        ),
                        "Provision or split a regional cell before placing additional organisations.",
                    )
                })?,
        };

        let placement = OrgPlacement {
            org_id: input.org_id.clone(),
            required_region: input.required_region,
            primary_cell: selected,
            target_cell: None,
        };
        self.placements.insert(input.org_id, placement.clone());
        Ok(placement)
    }

    pub fn start_drain(&mut self, org_id: &OrgId, target_cell: CellId) -> Result<(), CodedError> {
        let placement = self.placements.get(org_id).ok_or_else(|| {
            saas_error(
                CODE_SAAS_CELL_UNAVAILABLE,
                format!("Organisation `{}` has no placement.", org_id.as_str()),
                "Place the organisation in a regional cell before migrating it.",
            )
        })?;
        let target = self.cells.get(&target_cell).ok_or_else(|| {
            saas_error(
                CODE_SAAS_CELL_UNAVAILABLE,
                format!("Target cell `{}` is not registered.", target_cell.as_str()),
                "Provision the target cell in the organisation's region first.",
            )
        })?;
        ensure_cell_placeable(target, &placement.required_region, &self.bounds)?;
        if let Some(mut_placement) = self.placements.get_mut(org_id) {
            mut_placement.target_cell = Some(target_cell);
        }
        Ok(())
    }

    pub fn commit_move(&mut self, org_id: &OrgId) -> Result<OrgPlacement, CodedError> {
        let placement = self.placements.get_mut(org_id).ok_or_else(|| {
            saas_error(
                CODE_SAAS_CELL_UNAVAILABLE,
                format!("Organisation `{}` has no placement.", org_id.as_str()),
                "Ensure the organisation placement exists before committing move.",
            )
        })?;
        let target = placement.target_cell.take().ok_or_else(|| {
            saas_error(
                CODE_SAAS_INVALID_INPUT,
                format!("Organisation `{}` is not draining.", org_id.as_str()),
                "Call start_drain with a valid target cell prior to commit_move.",
            )
        })?;
        placement.primary_cell = target;
        Ok(placement.clone())
    }

    pub fn split_cell(
        &mut self,
        source_cell_id: &CellId,
        new_cell_id: CellId,
        new_api_endpoint: String,
    ) -> Result<CellSplitResult, CodedError> {
        validate_https_endpoint(&new_api_endpoint)?;
        if self.cells.contains_key(&new_cell_id) {
            return Err(saas_error(
                CODE_SAAS_INVALID_INPUT,
                format!("Cell `{}` already exists.", new_cell_id.as_str()),
                "Choose a fresh cell identifier when splitting.",
            ));
        }
        let source = self.cells.get(source_cell_id).cloned().ok_or_else(|| {
            saas_error(
                CODE_SAAS_CELL_UNAVAILABLE,
                format!("Cell `{}` was not found.", source_cell_id.as_str()),
                "Verify the source cell identifier before splitting.",
            )
        })?;
        if source.state != CellState::Active {
            return Err(saas_error(
                CODE_SAAS_CELL_UNAVAILABLE,
                format!(
                    "Cannot split non-active cell `{}`.",
                    source_cell_id.as_str()
                ),
                "Wait until the cell returns to Active state before splitting.",
            ));
        }
        let (left, right) = source.buckets.split_midpoint()?;
        for placement in self.placements.values() {
            if placement.target_cell.as_ref() == Some(source_cell_id)
                || (placement.primary_cell == *source_cell_id && placement.target_cell.is_some())
            {
                return Err(saas_error(
                    CODE_SAAS_CELL_UNAVAILABLE,
                    format!(
                        "Cannot split cell `{}` while an organisation drain involving it is active.",
                        source_cell_id.as_str()
                    ),
                    "Finish or abort pending drains prior to splitting a cell shard.",
                ));
            }
        }

        let mut placed_total: u64 = 0;
        let mut reassigned = Vec::new();
        for (org_id, placement) in &mut self.placements {
            if placement.primary_cell == *source_cell_id {
                placed_total = placed_total.saturating_add(1);
                if right.contains(device_bucket(org_id.as_str())) {
                    placement.primary_cell = new_cell_id.clone();
                    reassigned.push(org_id.clone());
                }
            }
        }

        let moved_count = u64::try_from(reassigned.len()).unwrap_or(0);
        let right_share_bps = if placed_total > 0 {
            moved_count
                .saturating_mul(10_000)
                .checked_div(placed_total)
                .unwrap_or(5_000)
        } else {
            u64::from(right.len())
                .saturating_mul(10_000)
                .checked_div(u64::from(source.buckets.len().max(1)))
                .unwrap_or(5_000)
        };
        let left_share_bps = 10_000u64.saturating_sub(right_share_bps);

        let new_cell = CellEndpoint {
            cell_id: new_cell_id.clone(),
            region: source.region.clone(),
            api_endpoint: new_api_endpoint,
            state: CellState::Active,
            buckets: right,
            capacity: scale_capacity(source.capacity, right_share_bps),
            protocol_range: source.protocol_range,
        };
        let mut updated_source = source;
        updated_source.buckets = left;
        updated_source.capacity = scale_capacity(updated_source.capacity, left_share_bps);

        self.cells
            .insert(updated_source.cell_id.clone(), updated_source);
        self.cells.insert(new_cell_id.clone(), new_cell);

        Ok(CellSplitResult {
            source_cell: source_cell_id.clone(),
            new_cell: new_cell_id,
            source_buckets: left,
            new_buckets: right,
            reassigned_orgs: reassigned,
        })
    }

    pub fn route_device(
        &self,
        org_id: &OrgId,
        device_id: &str,
        agent_version: SemVer,
    ) -> Result<(CellEndpoint, u16), CodedError> {
        ensure_clean_token("device_id", device_id)?;
        let placement = self.placements.get(org_id).ok_or_else(|| {
            saas_error(
                CODE_SAAS_CELL_UNAVAILABLE,
                format!("No cell placement found for `{}`.", org_id.as_str()),
                "Provision the organisation placement before routing devices.",
            )
        })?;
        let target_id = placement
            .target_cell
            .as_ref()
            .unwrap_or(&placement.primary_cell);
        let cell = self.cells.get(target_id).ok_or_else(|| {
            saas_error(
                CODE_SAAS_CELL_UNAVAILABLE,
                format!("Placed cell `{}` is missing.", target_id.as_str()),
                "Restore or re-register the missing cell endpoint.",
            )
        })?;
        if matches!(cell.state, CellState::Decommissioned) {
            return Err(saas_error(
                CODE_SAAS_CELL_UNAVAILABLE,
                format!("Cell `{}` is decommissioned.", cell.cell_id.as_str()),
                "Move the organisation to an active cell.",
            ));
        }
        if !cell.protocol_range.contains(agent_version) {
            return Err(saas_error(
                CODE_SAAS_INVALID_INPUT,
                format!(
                    "Agent version {agent_version} is outside `{}` protocol range.",
                    cell.cell_id.as_str()
                ),
                "Upgrade the endpoint agent to a supported release before connecting.",
            ));
        }
        Ok((cell.clone(), device_bucket(device_id)))
    }
}

fn ensure_cell_placeable(
    cell: &CellEndpoint,
    required_region: &RegionId,
    bounds: &SaasOperationalBounds,
) -> Result<(), CodedError> {
    if cell.region != *required_region {
        return Err(saas_error(
            CODE_SAAS_REGION_VIOLATION,
            format!(
                "Cell `{}` in `{}` violates region `{}`.",
                cell.cell_id.as_str(),
                cell.region.as_str(),
                required_region.as_str()
            ),
            "Select or provision a cell inside the organisation's pinned data region.",
        ));
    }
    if cell.state != CellState::Active {
        return Err(saas_error(
            CODE_SAAS_CELL_UNAVAILABLE,
            format!(
                "Cell `{}` is not accepting placements.",
                cell.cell_id.as_str()
            ),
            "Wait for maintenance or pick an active cell.",
        ));
    }
    if !cell.capacity.can_accept_org(bounds) {
        return Err(saas_error(
            CODE_SAAS_CELL_UNAVAILABLE,
            format!(
                "Cell `{}` exceeded capacity headroom.",
                cell.cell_id.as_str()
            ),
            "Split the full cell or place the organisation in an under-utilized cell.",
        ));
    }
    Ok(())
}

fn scale_capacity(cap: CellCapacityVector, share_bps: u64) -> CellCapacityVector {
    let scale_u8 = |v: u8| -> u8 {
        let out = u64::from(v)
            .saturating_mul(share_bps)
            .checked_div(10_000)
            .unwrap_or(0);
        u8::try_from(out.min(100)).unwrap_or(100)
    };
    let scale_u32 = |v: u32| -> u32 {
        let out = u64::from(v)
            .saturating_mul(share_bps)
            .checked_div(10_000)
            .unwrap_or(0);
        u32::try_from(out).unwrap_or(u32::MAX)
    };
    CellCapacityVector {
        cpu_pct: scale_u8(cap.cpu_pct),
        active_sessions: scale_u32(cap.active_sessions),
        storage_pct: scale_u8(cap.storage_pct),
        write_iops_pct: scale_u8(cap.write_iops_pct),
        max_sessions: cap.max_sessions,
    }
}
