// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors

//! Authoritative exact-table + 24-bit Binary Fuse lookup, strictness merge,
//! data-driven guard list, and hourly new-artefact circuit breaker (`docs/design/14`).

use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};

use grdr_model::Mode;

use crate::IntelError;
pub use crate::breaker::{BreakerState, IntelCircuitBreaker, MAX_HOURLY_INTEL_BLOCKS, ONE_HOUR_MS};
use crate::canonical::{
    canonical_index_key_and_version, canonicalize_domain, is_guard_listed_host,
    normalize_observable, split_purl_body_and_version,
};
use crate::feeds::version_in_vulnerable_range;
use crate::fuse::BinaryFuse24;
use crate::pack::ValidatedIntelPack;
use crate::record::{GrdrIntelId, IntelSeverity, IntelStatus, ObservableKind, compute_status};
use crate::semver::{is_unbounded_all_versions_range, validate_version_range_syntax};
use crate::validators::validate_observable_syntax;

const MAX_ENTRY_STR_BYTES: usize = 4_096;
const MAX_INDEX_GUARD_DOMAINS: usize = 10_000;
const MAX_INDEX_KEYS: usize = 500_000;
const MAX_INDEX_TOTAL_ENTRIES: usize = 1_000_000;
const MAX_ENTRIES_PER_KEY: usize = 4_096;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(try_from = "RawIntelVerdictEntry")]
pub struct IntelVerdictEntry {
    pub record_id: String,
    pub kind: ObservableKind,
    pub canonical_value: String,
    pub version_range: Option<String>,
    pub status: IntelStatus,
    pub severity: IntelSeverity,
    #[serde(default)]
    pub activation_epoch: u64,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawIntelVerdictEntry {
    record_id: String,
    kind: ObservableKind,
    canonical_value: String,
    version_range: Option<String>,
    status: IntelStatus,
    severity: IntelSeverity,
    #[serde(default)]
    activation_epoch: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LookupTier {
    FuseReject,
    LocalExact,
    NeedsRemoteConfirm,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct IntelMatch {
    pub entry: IntelVerdictEntry,
    pub effective_mode: Mode,
    pub guard_list_protected: bool,
    pub lookup_tier: LookupTier,
}

/// Three-tier reputation output. Notably contains NO `Clean` variant (`docs/design/14`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "verdict", rename_all = "snake_case")]
pub enum ReputationVerdict {
    Unrated,
    Malicious(IntelMatch),
    Suspicious(IntelMatch),
    Vulnerable(IntelMatch),
    Withdrawn,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LookupOutcome {
    pub verdict: ReputationVerdict,
    pub tier: LookupTier,
    pub breaker_alert: Option<IntelError>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(try_from = "RawIntelIndex")]
pub struct IntelIndex {
    fuse: BinaryFuse24,
    exact_entries: BTreeMap<String, Vec<IntelVerdictEntry>>,
    guard_domains: BTreeSet<String>,
    rapid_lane: bool,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawIntelIndex {
    fuse: BinaryFuse24,
    exact_entries: BTreeMap<String, Vec<IntelVerdictEntry>>,
    guard_domains: BTreeSet<String>,
    rapid_lane: bool,
}

impl TryFrom<RawIntelVerdictEntry> for IntelVerdictEntry {
    type Error = IntelError;

    fn try_from(raw: RawIntelVerdictEntry) -> Result<Self, Self::Error> {
        let canonical_id = GrdrIntelId::parse(&raw.record_id)?;
        if raw.canonical_value.len() > MAX_ENTRY_STR_BYTES
            || raw.canonical_value.chars().any(char::is_control)
        {
            return Err(IntelError::InvalidRecord(
                "entry canonical_value contains controls or exceeds bound".into(),
            ));
        }
        let prefix = format!("{:?}:", raw.kind);
        let bare = raw.canonical_value.strip_prefix(&prefix).ok_or_else(|| {
            IntelError::InvalidRecord("entry canonical_value missing kind prefix".into())
        })?;
        validate_observable_syntax(raw.kind, bare, MAX_ENTRY_STR_BYTES)
            .map_err(|msg| IntelError::InvalidRecord(msg.into()))?;
        if normalize_observable(raw.kind, bare) != raw.canonical_value {
            return Err(IntelError::InvalidRecord(
                "non-canonical entry canonical_value".into(),
            ));
        }
        if let Some(ref vr) = raw.version_range {
            validate_version_range_syntax(vr)?;
        }
        Ok(Self {
            record_id: canonical_id.as_str().to_owned(),
            kind: raw.kind,
            canonical_value: raw.canonical_value,
            version_range: raw.version_range,
            status: raw.status,
            severity: raw.severity,
            activation_epoch: raw.activation_epoch,
        })
    }
}

impl TryFrom<RawIntelIndex> for IntelIndex {
    type Error = IntelError;

    fn try_from(raw: RawIntelIndex) -> Result<Self, Self::Error> {
        raw.fuse.validate()?;
        if raw.guard_domains.len() > MAX_INDEX_GUARD_DOMAINS {
            return Err(IntelError::NonRestrictivePack(
                "index guard_domains exceeds bound".into(),
            ));
        }
        for domain in &raw.guard_domains {
            if domain.is_empty() || domain.len() > 253 || canonicalize_domain(domain) != *domain {
                return Err(IntelError::NonRestrictivePack(
                    "index guard_domains entry is not canonical".into(),
                ));
            }
        }
        if raw.exact_entries.len() > MAX_INDEX_KEYS {
            return Err(IntelError::InvalidRecord(
                "index exact_entries key count exceeds bound".into(),
            ));
        }
        let mut total_entries: usize = 0;
        for (key, entries) in &raw.exact_entries {
            if key.trim().is_empty()
                || key.len() > MAX_ENTRY_STR_BYTES
                || key.chars().any(char::is_control)
                || entries.is_empty()
                || entries.len() > MAX_ENTRIES_PER_KEY
            {
                return Err(IntelError::InvalidRecord(
                    "index exact_entries bucket invalid or exceeds bound".into(),
                ));
            }
            total_entries = total_entries
                .checked_add(entries.len())
                .filter(|&n| n <= MAX_INDEX_TOTAL_ENTRIES)
                .ok_or_else(|| {
                    IntelError::InvalidRecord(
                        "index exact_entries total count exceeds bound".into(),
                    )
                })?;
            if !raw.fuse.might_contain(key)? {
                return Err(IntelError::CorruptFilter(
                    "index exact_entries key absent from fuse filter".into(),
                ));
            }
            for entry in entries {
                let prefix = format!("{:?}:", entry.kind);
                let bare = entry.canonical_value.strip_prefix(&prefix).unwrap_or("");
                let (expected_key, _) = canonical_index_key_and_version(entry.kind, bare);
                if expected_key != *key {
                    return Err(IntelError::InvalidRecord(
                        "index entry does not match bucket key".into(),
                    ));
                }
            }
        }
        Ok(Self {
            fuse: raw.fuse,
            exact_entries: raw.exact_entries,
            guard_domains: raw.guard_domains,
            rapid_lane: raw.rapid_lane,
        })
    }
}

impl IntelIndex {
    /// Builds an index using guard domains carried in the validated pack manifest.
    pub fn from_pack(pack: &ValidatedIntelPack) -> Result<Self, IntelError> {
        Self::from_pack_with_guard_list(pack, &pack.manifest.guard_domains, 1)
    }

    /// Builds an index with an explicit data-driven guard list and activation epoch.
    pub fn from_pack_with_guard_list(
        pack: &ValidatedIntelPack,
        guard_list: &[String],
        activation_epoch: u64,
    ) -> Result<Self, IntelError> {
        let mut exact_entries: BTreeMap<String, Vec<IntelVerdictEntry>> = BTreeMap::new();
        let mut keys = Vec::new();
        for rec in &pack.records {
            let status = compute_status(rec);
            if status == IntelStatus::None {
                continue;
            }
            for obs in &rec.observables {
                validate_observable_syntax(obs.kind, &obs.value, MAX_ENTRY_STR_BYTES)
                    .map_err(|msg| IntelError::InvalidRecord(msg.into()))?;
                if let Some(ref vr) = obs.version_range {
                    validate_version_range_syntax(vr)?;
                }
                let full_canonical = normalize_observable(obs.kind, &obs.value);
                if full_canonical.is_empty() {
                    continue;
                }
                let (index_key, pinned_ver) = canonical_index_key_and_version(obs.kind, &obs.value);
                let effective_range = match (&obs.version_range, pinned_ver.as_deref()) {
                    (Some(r), _) => Some(r.clone()),
                    (None, Some(v)) => {
                        let pinned_range = format!("=={v}");
                        validate_version_range_syntax(&pinned_range)
                            .ok()
                            .map(|()| pinned_range)
                    }
                    (None, None) => None,
                };
                keys.push(index_key.clone());
                exact_entries
                    .entry(index_key)
                    .or_default()
                    .push(IntelVerdictEntry {
                        record_id: rec.id.as_str().to_owned(),
                        kind: obs.kind,
                        canonical_value: full_canonical,
                        version_range: effective_range,
                        status,
                        severity: rec.severity,
                        activation_epoch,
                    });
            }
        }
        let fuse = BinaryFuse24::build(&keys)?;
        let guard_domains: BTreeSet<String> = guard_list
            .iter()
            .map(|d| canonicalize_domain(d))
            .filter(|d| !d.is_empty())
            .collect();
        Ok(Self {
            fuse,
            exact_entries,
            guard_domains,
            rapid_lane: pack.manifest.channel == "rapid",
        })
    }

    #[must_use]
    pub const fn fuse(&self) -> &BinaryFuse24 {
        &self.fuse
    }

    /// Authoritative lookup returning `Err(IntelError::CorruptFilter)` if fuse invariants fail,
    /// `LookupTier::{FuseReject, LocalExact, NeedsRemoteConfirm}`, and optional `BreakerOpen` alert.
    pub fn lookup_with_tier(
        &self,
        kind: ObservableKind,
        value: &str,
        device_id: &str,
        now_ms: i64,
        requested_mode: Mode,
        breaker: &mut IntelCircuitBreaker,
    ) -> Result<LookupOutcome, IntelError> {
        self.fuse.validate()?;
        let (index_key, candidate_ver) = canonical_index_key_and_version(kind, value);
        if index_key.is_empty() {
            return Ok(LookupOutcome {
                verdict: ReputationVerdict::Unrated,
                tier: LookupTier::FuseReject,
                breaker_alert: None,
            });
        }

        let fuse_hit = self.fuse.might_contain(&index_key)?;
        let candidates = self.exact_entries.get(&index_key);
        let matched = candidates
            .map(|entries| filter_matching_entries(entries, kind, candidate_ver.as_deref()));

        let Some(matched_entries) = matched.filter(|m| !m.is_empty()) else {
            let tier = if fuse_hit {
                LookupTier::NeedsRemoteConfirm
            } else {
                LookupTier::FuseReject
            };
            return Ok(LookupOutcome {
                verdict: ReputationVerdict::Unrated,
                tier,
                breaker_alert: None,
            });
        };

        let Some((effective_status, entry)) =
            select_strictest_entry(&matched_entries, kind, candidate_ver.as_deref())
        else {
            return Ok(LookupOutcome {
                verdict: ReputationVerdict::Unrated,
                tier: LookupTier::LocalExact,
                breaker_alert: None,
            });
        };

        if effective_status == IntelStatus::Withdrawn {
            return Ok(LookupOutcome {
                verdict: ReputationVerdict::Withdrawn,
                tier: LookupTier::LocalExact,
                breaker_alert: None,
            });
        }

        let full_canonical = normalize_observable(kind, value);
        let guarded = is_guard_listed_host(kind, &full_canonical, &self.guard_domains);
        let is_name_only_purl = kind == ObservableKind::PackagePurl
            && entry.version_range.is_none()
            && entry_pinned_purl_version(entry).is_none();

        let mut effective_mode = match effective_status {
            IntelStatus::Vulnerable => requested_mode.min(Mode::Watch),
            IntelStatus::Suspicious => requested_mode.min(Mode::Ask),
            IntelStatus::Malicious if is_name_only_purl => requested_mode.min(Mode::Ask),
            IntelStatus::Malicious if self.rapid_lane && guarded => requested_mode.min(Mode::Watch),
            IntelStatus::Malicious => requested_mode,
            IntelStatus::Withdrawn | IntelStatus::None => Mode::Off,
        };

        let mut breaker_alert = None;
        if effective_status == IntelStatus::Malicious && effective_mode == Mode::Block {
            match breaker.record_new_block(
                device_id,
                entry.activation_epoch,
                &entry.canonical_value,
                now_ms,
            ) {
                Ok(BreakerState::Closed) => {}
                Ok(BreakerState::Tripped) => {
                    effective_mode = Mode::Ask;
                }
                Err(err) => {
                    effective_mode = Mode::Ask;
                    breaker_alert = Some(err);
                }
            }
        }

        let intel_match = IntelMatch {
            entry: entry.clone(),
            effective_mode,
            guard_list_protected: self.rapid_lane && guarded,
            lookup_tier: LookupTier::LocalExact,
        };
        let verdict = match effective_status {
            IntelStatus::Malicious => ReputationVerdict::Malicious(intel_match),
            IntelStatus::Suspicious => ReputationVerdict::Suspicious(intel_match),
            IntelStatus::Vulnerable => ReputationVerdict::Vulnerable(intel_match),
            IntelStatus::Withdrawn => ReputationVerdict::Withdrawn,
            IntelStatus::None => ReputationVerdict::Unrated,
        };
        Ok(LookupOutcome {
            verdict,
            tier: LookupTier::LocalExact,
            breaker_alert,
        })
    }

    /// Convenience wrapper returning `ReputationVerdict` directly (collapsing corrupt filter to `Unrated`).
    pub fn lookup(
        &self,
        kind: ObservableKind,
        value: &str,
        device_id: &str,
        now_ms: i64,
        requested_mode: Mode,
        breaker: &mut IntelCircuitBreaker,
    ) -> ReputationVerdict {
        self.lookup_with_tier(kind, value, device_id, now_ms, requested_mode, breaker)
            .map_or(ReputationVerdict::Unrated, |res| res.verdict)
    }
}

fn entry_pinned_purl_version(entry: &IntelVerdictEntry) -> Option<&str> {
    if entry.kind != ObservableKind::PackagePurl {
        return None;
    }
    let bare = entry
        .canonical_value
        .strip_prefix("PackagePurl:")
        .unwrap_or(&entry.canonical_value);
    split_purl_body_and_version(bare).1
}

fn filter_matching_entries<'a>(
    entries: &'a [IntelVerdictEntry],
    kind: ObservableKind,
    candidate_ver: Option<&str>,
) -> Vec<&'a IntelVerdictEntry> {
    entries
        .iter()
        .filter(|entry| entry.status != IntelStatus::None)
        .filter(|entry| {
            if kind != ObservableKind::PackagePurl {
                return true;
            }
            match (
                &entry.version_range,
                entry_pinned_purl_version(entry),
                candidate_ver,
            ) {
                (Some(range), _, Some(ver)) => version_in_vulnerable_range(ver, range),
                (None, Some(pinned), Some(ver)) => pinned == ver,
                (Some(_), _, None) | (None, _, None) | (None, None, Some(_)) => true,
            }
        })
        .collect()
}

fn effective_entry_status(
    entry: &IntelVerdictEntry,
    kind: ObservableKind,
    candidate_ver: Option<&str>,
) -> IntelStatus {
    if entry.status == IntelStatus::Malicious
        && kind == ObservableKind::PackagePurl
        && candidate_ver.is_none()
    {
        if let Some(ref range) = entry.version_range {
            if !is_unbounded_all_versions_range(range) {
                return IntelStatus::Suspicious;
            }
        } else if entry_pinned_purl_version(entry).is_some() {
            return IntelStatus::Suspicious;
        }
    }
    entry.status
}

fn select_strictest_entry<'a>(
    entries: &[&'a IntelVerdictEntry],
    kind: ObservableKind,
    candidate_ver: Option<&str>,
) -> Option<(IntelStatus, &'a IntelVerdictEntry)> {
    let active_rank = |status: IntelStatus| -> u8 {
        match status {
            IntelStatus::Malicious => 4,
            IntelStatus::Suspicious => 3,
            IntelStatus::Vulnerable => 2,
            IntelStatus::Withdrawn => 1,
            IntelStatus::None => 0,
        }
    };
    entries
        .iter()
        .copied()
        .map(|e| (effective_entry_status(e, kind, candidate_ver), e))
        .max_by(|(sa, a), (sb, b)| {
            active_rank(*sa)
                .cmp(&active_rank(*sb))
                .then_with(|| a.severity.cmp(&b.severity))
                .then_with(|| b.record_id.cmp(&a.record_id))
        })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pack::validate_intel_pack_json;

    #[test]
    fn fuse_lookup_returns_unrated_never_clean_and_trips_guard_and_breaker() {
        let keys: Vec<String> = (0..10_500)
            .map(|i| format!("Domain:evil-{i}.example"))
            .collect();
        let filter = BinaryFuse24::build(&keys).expect("build fuse >10k");
        for k in &keys {
            assert!(
                filter.might_contain(k).expect("valid"),
                "false negative on {k}"
            );
        }

        let pack_json = serde_json::json!({
            "pack_id": "grdr.intel.test",
            "kind": "intel",
            "polarity": "protect",
            "version": "1.0.0",
            "channel": "rapid",
            "publisher": "Guardrails",
            "records": [
                {
                    "id": "GRDRI-2026-00010",
                    "title": "Evil domain",
                    "severity": "critical",
                    "withdrawn": false,
                    "observables": [{ "kind": "domain", "value": "c2.evil.test", "version_range": null }],
                    "evidence": [{
                        "feed": "ossf",
                        "organisation": "OSSF",
                        "method_family": "human_review",
                        "nature": "malicious",
                        "review_state": "published_external_human_review",
                        "disposition": "active",
                        "reference_url": null,
                        "summary": "Confirmed C2"
                    }]
                },
                {
                    "id": "GRDRI-2026-00011",
                    "title": "High-prevalence guard check",
                    "severity": "high",
                    "withdrawn": false,
                    "observables": [{ "kind": "domain", "value": "github.com", "version_range": null }],
                    "evidence": [{
                        "feed": "ossf",
                        "organisation": "OSSF",
                        "method_family": "human_review",
                        "nature": "malicious",
                        "review_state": "published_external_human_review",
                        "disposition": "active",
                        "reference_url": null,
                        "summary": "False block test"
                    }]
                },
                {
                    "id": "GRDRI-2026-00012",
                    "title": "Attacker subdomain on S3",
                    "severity": "critical",
                    "withdrawn": false,
                    "observables": [{ "kind": "url", "value": "https://evil.s3.amazonaws.com/p.sh", "version_range": null }],
                    "evidence": [{
                        "feed": "ossf",
                        "organisation": "OSSF",
                        "method_family": "human_review",
                        "nature": "malicious",
                        "review_state": "published_external_human_review",
                        "disposition": "active",
                        "reference_url": null,
                        "summary": "Attacker bucket"
                    }]
                },
                {
                    "id": "GRDRI-2026-00013",
                    "title": "Evil 2",
                    "severity": "critical",
                    "withdrawn": false,
                    "observables": [{ "kind": "domain", "value": "c2-2.evil.test", "version_range": null }],
                    "evidence": [{
                        "feed": "ossf",
                        "organisation": "OSSF",
                        "method_family": "human_review",
                        "nature": "malicious",
                        "review_state": "published_external_human_review",
                        "disposition": "active",
                        "reference_url": null,
                        "summary": "Confirmed C2 2"
                    }]
                },
                {
                    "id": "GRDRI-2026-00014",
                    "title": "Evil 3",
                    "severity": "critical",
                    "withdrawn": false,
                    "observables": [{ "kind": "domain", "value": "c2-3.evil.test", "version_range": null }],
                    "evidence": [{
                        "feed": "ossf",
                        "organisation": "OSSF",
                        "method_family": "human_review",
                        "nature": "malicious",
                        "review_state": "published_external_human_review",
                        "disposition": "active",
                        "reference_url": null,
                        "summary": "Confirmed C2 3"
                    }]
                },
                {
                    "id": "GRDRI-2026-00015",
                    "title": "Evil 4",
                    "severity": "critical",
                    "withdrawn": false,
                    "observables": [{ "kind": "domain", "value": "c2-4.evil.test", "version_range": null }],
                    "evidence": [{
                        "feed": "ossf",
                        "organisation": "OSSF",
                        "method_family": "human_review",
                        "nature": "malicious",
                        "review_state": "published_external_human_review",
                        "disposition": "active",
                        "reference_url": null,
                        "summary": "Confirmed C2 4"
                    }]
                }
            ]
        })
        .to_string();

        let pack = validate_intel_pack_json(&pack_json).expect("valid pack");
        let guard_list = vec!["github.com".to_owned(), "s3.amazonaws.com".to_owned()];
        let idx =
            IntelIndex::from_pack_with_guard_list(&pack, &guard_list, 1).expect("index built");
        let mut breaker = IntelCircuitBreaker::default();

        let unrated = idx
            .lookup_with_tier(
                ObservableKind::Domain,
                "benign.org",
                "dev-1",
                1000,
                Mode::Block,
                &mut breaker,
            )
            .expect("lookup");
        assert_eq!(unrated.verdict, ReputationVerdict::Unrated);
        assert_eq!(unrated.tier, LookupTier::FuseReject);

        let guard = idx.lookup(
            ObservableKind::Domain,
            "github.com",
            "dev-1",
            1000,
            Mode::Block,
            &mut breaker,
        );
        assert!(matches!(
            guard,
            ReputationVerdict::Malicious(m) if m.guard_list_protected && m.effective_mode == Mode::Watch
        ));

        let attacker_s3 = idx.lookup(
            ObservableKind::Url,
            "https://evil.s3.amazonaws.com/p.sh",
            "dev-1",
            1000,
            Mode::Block,
            &mut breaker,
        );
        assert!(matches!(
            attacker_s3,
            ReputationVerdict::Malicious(m) if !m.guard_list_protected && m.effective_mode == Mode::Block
        ));

        // Same artefact repeated 4 times in same epoch must NOT trip breaker.
        for t in [1_000_i64, 2_000, 3_000, 4_000] {
            let v = idx.lookup(
                ObservableKind::Domain,
                "c2.evil.test",
                "dev-same",
                t,
                Mode::Block,
                &mut breaker,
            );
            assert!(
                matches!(v, ReputationVerdict::Malicious(m) if m.effective_mode == Mode::Block)
            );
        }

        // 4 distinct newly activated artefacts on dev-2 MUST trip breaker on the 4th.
        for (dom, t) in [
            ("c2.evil.test", 1_000_i64),
            ("c2-2.evil.test", 2_000),
            ("c2-3.evil.test", 3_000),
        ] {
            let v = idx
                .lookup_with_tier(
                    ObservableKind::Domain,
                    dom,
                    "dev-2",
                    t,
                    Mode::Block,
                    &mut breaker,
                )
                .expect("ok");
            assert!(
                matches!(v.verdict, ReputationVerdict::Malicious(m) if m.effective_mode == Mode::Block)
            );
            assert!(v.breaker_alert.is_none());
        }
        let tripped = idx
            .lookup_with_tier(
                ObservableKind::Domain,
                "c2-4.evil.test",
                "dev-2",
                4_000,
                Mode::Block,
                &mut breaker,
            )
            .expect("ok");
        assert!(matches!(
            tripped.verdict,
            ReputationVerdict::Malicious(m) if m.effective_mode == Mode::Ask
        ));
        assert!(matches!(
            tripped.breaker_alert,
            Some(IntelError::BreakerOpen(_))
        ));
    }

    #[test]
    fn negative_tests_cover_strictest_merge_version_range_suspicious_cap_and_corrupt_fuse() {
        let shipped = include_str!("../../../packs/intel/sample-intel-pack.json");
        let pack = validate_intel_pack_json(shipped).expect("valid shipped pack");
        let idx = IntelIndex::from_pack(&pack).expect("index");
        let mut breaker = IntelCircuitBreaker::default();

        let hit = idx.lookup(
            ObservableKind::PackagePurl,
            "pkg:npm/guardrails-fake-helper@1.0.5",
            "dev-1",
            1_000,
            Mode::Block,
            &mut breaker,
        );
        assert!(matches!(
            hit,
            ReputationVerdict::Malicious(m) if m.effective_mode == Mode::Block
        ));

        let safe_ver = idx.lookup(
            ObservableKind::PackagePurl,
            "pkg:npm/guardrails-fake-helper@1.0.9",
            "dev-1",
            1_000,
            Mode::Block,
            &mut breaker,
        );
        assert_eq!(safe_ver, ReputationVerdict::Unrated);

        // Merge must keep strictest active Malicious even when a Withdrawn/None record shares the observable.
        let multi_pack_json = serde_json::json!({
            "pack_id": "grdr.intel.merge",
            "kind": "intel",
            "polarity": "protect",
            "version": "1.0.0",
            "channel": "standard",
            "publisher": "Guardrails",
            "records": [
                {
                    "id": "GRDRI-2026-00001",
                    "title": "Confirmed malicious domain",
                    "severity": "critical",
                    "withdrawn": false,
                    "observables": [{ "kind": "domain", "value": "evil.test", "version_range": null }],
                    "evidence": [{
                        "feed": "ossf",
                        "organisation": "OSSF",
                        "method_family": "human_review",
                        "nature": "malicious",
                        "review_state": "published_external_human_review",
                        "disposition": "active",
                        "reference_url": null,
                        "summary": "Active malicious"
                    }]
                },
                {
                    "id": "GRDRI-2026-00002",
                    "title": "Withdrawn duplicate domain",
                    "severity": "low",
                    "withdrawn": true,
                    "observables": [{ "kind": "domain", "value": "evil.test", "version_range": null }],
                    "evidence": []
                },
                {
                    "id": "GRDRI-2026-00003",
                    "title": "Suspicious domain",
                    "severity": "medium",
                    "withdrawn": false,
                    "observables": [{ "kind": "domain", "value": "suspect.test", "version_range": null }],
                    "evidence": [{
                        "feed": "researcher_report",
                        "organisation": "SingleResearcher",
                        "method_family": "static_analysis",
                        "nature": "suspicious",
                        "review_state": "unreviewed",
                        "disposition": "active",
                        "reference_url": null,
                        "summary": "Unverified"
                    }]
                },
                {
                    "id": "GRDRI-2026-00004",
                    "title": "Vulnerable CVE",
                    "severity": "high",
                    "withdrawn": false,
                    "observables": [{ "kind": "cve", "value": "CVE-2026-9999", "version_range": null }],
                    "evidence": [{
                        "feed": "ghsa",
                        "organisation": "GHSA",
                        "method_family": "advisory_feed",
                        "nature": "vulnerable",
                        "review_state": "maintainer_verified",
                        "disposition": "active",
                        "reference_url": null,
                        "summary": "Vuln"
                    }]
                }
            ]
        })
        .to_string();
        let multi = validate_intel_pack_json(&multi_pack_json).expect("multi");
        let multi_idx = IntelIndex::from_pack(&multi).expect("idx");

        let merged = multi_idx.lookup(
            ObservableKind::Domain,
            "evil.test",
            "dev-1",
            1_000,
            Mode::Block,
            &mut breaker,
        );
        assert!(matches!(
            merged,
            ReputationVerdict::Malicious(m) if m.entry.record_id == "GRDRI-2026-00001"
        ));

        let susp = multi_idx.lookup(
            ObservableKind::Domain,
            "suspect.test",
            "dev-1",
            1_000,
            Mode::Block,
            &mut breaker,
        );
        assert!(matches!(
            susp,
            ReputationVerdict::Suspicious(m) if m.effective_mode == Mode::Ask
        ));

        let vuln = multi_idx.lookup(
            ObservableKind::Cve,
            "CVE-2026-9999",
            "dev-1",
            1_000,
            Mode::Block,
            &mut breaker,
        );
        assert!(matches!(
            vuln,
            ReputationVerdict::Vulnerable(m) if m.effective_mode == Mode::Watch
        ));

        // Corrupt BinaryFuse24 deserialization with segment_length=0 must return CorruptFilter.
        let corrupt_fuse_json = r#"{"seed":1,"segment_length":0,"segment_length_mask":0,"segment_count_length":4,"fingerprints_3byte":[0,0,0,0,0,0,0,0,0]}"#;
        assert!(serde_json::from_str::<BinaryFuse24>(corrupt_fuse_json).is_err());
        assert!(matches!(
            BinaryFuse24::from_parts(1, 0, 0, 4, vec![0; 12]),
            Err(IntelError::CorruptFilter(_))
        ));

        // IP/IDNA normalization checks.
        assert_eq!(
            normalize_observable(ObservableKind::IpAddress, "010.0.0.1"),
            "IpAddress:8.0.0.1"
        );
        assert_eq!(
            normalize_observable(ObservableKind::IpAddress, "::ffff:10.0.0.1"),
            "IpAddress:10.0.0.1"
        );
        assert_eq!(
            normalize_observable(ObservableKind::Domain, "Bücher.example."),
            "Domain:xn--bcher-kva.example"
        );
    }

    #[test]
    fn round2_index_unversioned_purl_breaker_skew_canonical_ips_and_fuse_limits() {
        // Unversioned lookup against unbounded (>=0.0.0-0) matches record status (Malicious/Block),
        // while bounded range matches as Suspicious/Ask.
        let pack_json = serde_json::json!({
            "pack_id": "grdr.intel.round2",
            "kind": "intel",
            "polarity": "protect",
            "version": "1.0.0",
            "channel": "standard",
            "publisher": "OSSF",
            "guard_domains": [],
            "records": [
                {
                    "id": "GRDRI-2026-00501",
                    "title": "All versions backdoor",
                    "severity": "critical",
                    "withdrawn": false,
                    "observables": [{
                        "kind": "package-purl",
                        "value": "pkg:npm/all-bad",
                        "version_range": ">=0.0.0-0"
                    }],
                    "evidence": [
                        {
                            "feed": "ossf",
                            "organisation": "OSSF",
                            "method_family": "dynamic_sandbox",
                            "nature": "malicious",
                            "review_state": "published_external_human_review",
                            "disposition": "active",
                            "reference_url": "https://a.example/1",
                            "summary": "s1"
                        },
                        {
                            "feed": "vendor_advisory",
                            "organisation": "Socket",
                            "method_family": "static_analysis",
                            "nature": "malicious",
                            "review_state": "published_external_human_review",
                            "disposition": "active",
                            "reference_url": "https://b.example/2",
                            "summary": "s2"
                        }
                    ]
                },
                {
                    "id": "GRDRI-2026-00502",
                    "title": "Bounded malicious range",
                    "severity": "high",
                    "withdrawn": false,
                    "observables": [{
                        "kind": "package-purl",
                        "value": "pkg:npm/range-bad",
                        "version_range": ">=1.0.0, <2.0.0"
                    }],
                    "evidence": [
                        {
                            "feed": "ossf",
                            "organisation": "OSSF",
                            "method_family": "dynamic_sandbox",
                            "nature": "malicious",
                            "review_state": "published_external_human_review",
                            "disposition": "active",
                            "reference_url": "https://c.example/1",
                            "summary": "s1"
                        },
                        {
                            "feed": "vendor_advisory",
                            "organisation": "Socket",
                            "method_family": "static_analysis",
                            "nature": "malicious",
                            "review_state": "published_external_human_review",
                            "disposition": "active",
                            "reference_url": "https://d.example/2",
                            "summary": "s2"
                        }
                    ]
                }
            ]
        })
        .to_string();
        let pack = validate_intel_pack_json(&pack_json).expect("valid pack");
        let idx = IntelIndex::from_pack(&pack).expect("index");
        let mut breaker = IntelCircuitBreaker::default();

        let all_unver = idx.lookup(
            ObservableKind::PackagePurl,
            "pkg:npm/all-bad",
            "dev-u",
            1_000,
            Mode::Block,
            &mut breaker,
        );
        assert!(matches!(
            all_unver,
            ReputationVerdict::Malicious(m) if m.effective_mode == Mode::Block
        ));

        let bounded_unver = idx.lookup(
            ObservableKind::PackagePurl,
            "pkg:npm/range-bad",
            "dev-u",
            1_000,
            Mode::Block,
            &mut breaker,
        );
        assert!(matches!(
            bounded_unver,
            ReputationVerdict::Suspicious(m) if m.effective_mode == Mode::Ask
        ));

        // Shipped pack unversioned PURL lookup never silently returns Unrated.
        let shipped =
            validate_intel_pack_json(include_str!("../../../packs/intel/sample-intel-pack.json"))
                .expect("shipped pack");
        let shipped_idx = IntelIndex::from_pack(&shipped).expect("shipped index");
        let mut sb = IntelCircuitBreaker::default();
        assert!(!matches!(
            shipped_idx.lookup(
                ObservableKind::PackagePurl,
                "pkg:npm/guardrails-fake-helper",
                "dev-s",
                1_000,
                Mode::Block,
                &mut sb,
            ),
            ReputationVerdict::Unrated
        ));

        // Breaker monotonic pruning survives backward clock skew; state() aligns with >3 threshold.
        let mut skew_breaker = IntelCircuitBreaker::default();
        assert_eq!(
            skew_breaker
                .record_new_block("dev-k", 1, "Domain:a.test", 10_000_000)
                .unwrap(),
            BreakerState::Closed
        );
        assert_eq!(
            skew_breaker
                .record_new_block("dev-k", 1, "Domain:b.test", 9_990_000)
                .unwrap(),
            BreakerState::Closed
        );
        assert_eq!(
            skew_breaker
                .record_new_block("dev-k", 1, "Domain:c.test", 9_995_000)
                .unwrap(),
            BreakerState::Closed
        );
        assert_eq!(
            skew_breaker.state("dev-k", 10_000_000),
            BreakerState::Closed
        );
        assert!(
            skew_breaker
                .record_new_block("dev-k", 1, "Domain:d.test", 10_001_000)
                .is_err()
        );
        assert_eq!(
            skew_breaker.state("dev-k", 10_001_000),
            BreakerState::Tripped
        );

        // Scoped npm %40 normalization and newly blocked IPv4/IPv6 special-use ranges + 0x+ rejection.
        let (pct_key, pct_ver) = canonical_index_key_and_version(
            ObservableKind::PackagePurl,
            "pkg:npm/%40scope/pkg@1.2.3",
        );
        let (at_key, at_ver) = canonical_index_key_and_version(
            ObservableKind::PackagePurl,
            "pkg:npm/@scope/pkg@1.2.3",
        );
        assert_eq!(pct_key, at_key);
        assert_eq!(pct_ver, at_ver);

        assert!(crate::canonical::parse_canonical_ip("0x+1.0.0.1").is_none());
        for private_or_reserved_ip in [
            "192.0.0.1",
            "192.0.2.1",
            "198.18.0.1",
            "198.51.100.1",
            "203.0.113.1",
            "240.0.0.1",
            "100::1",
            "64:ff9b:1::1",
            "2001:db8::1",
            "fec0::1",
        ] {
            assert!(
                crate::canonical::validate_public_artefact(
                    ObservableKind::IpAddress,
                    private_or_reserved_ip
                )
                .is_err(),
                "expected reserved/special IP `{private_or_reserved_ip}` to fail public filter"
            );
        }

        // Incremental BinaryFuse24 serde rejects oversized / mismatched array before allocation.
        let huge_fuse = r#"{"seed":1,"segment_length":8,"segment_length_mask":7,"segment_count_length":2000000,"fingerprints_3byte":[0,1,2]}"#;
        assert!(serde_json::from_str::<BinaryFuse24>(huge_fuse).is_err());
    }

    #[test]
    fn round4_index_vulnerable_unversioned_breaker_skew_and_serde_invariants() {
        // 1. Bounded Vulnerable advisory keeps IntelStatus::Vulnerable (Mode::Watch) on unversioned
        // lookup and does not outrank Critical unbounded Vulnerable in select_strictest_entry.
        let vuln_pack_json = serde_json::json!({
            "pack_id": "grdr.intel.vuln-unver",
            "kind": "intel",
            "polarity": "protect",
            "version": "1.0.0",
            "channel": "standard",
            "publisher": "GHSA",
            "records": [
                {
                    "id": "GRDRI-2026-00601",
                    "title": "Low bounded vuln",
                    "severity": "low",
                    "withdrawn": false,
                    "observables": [{
                        "kind": "package-purl",
                        "value": "pkg:npm/agent-sdk",
                        "version_range": ">=0.4.0, <0.4.5"
                    }],
                    "evidence": [{
                        "feed": "ghsa",
                        "organisation": "GHSA",
                        "method_family": "advisory_feed",
                        "nature": "vulnerable",
                        "review_state": "maintainer_verified",
                        "disposition": "active",
                        "reference_url": null,
                        "summary": "Low bounded"
                    }]
                },
                {
                    "id": "GRDRI-2026-00602",
                    "title": "Critical unbounded vuln",
                    "severity": "critical",
                    "withdrawn": false,
                    "observables": [{
                        "kind": "package-purl",
                        "value": "pkg:npm/agent-sdk",
                        "version_range": null
                    }],
                    "evidence": [{
                        "feed": "ghsa",
                        "organisation": "GHSA",
                        "method_family": "advisory_feed",
                        "nature": "vulnerable",
                        "review_state": "maintainer_verified",
                        "disposition": "active",
                        "reference_url": null,
                        "summary": "Crit unbounded"
                    }]
                },
                {
                    "id": "GRDRI-2026-00603",
                    "title": "Bounded single vuln",
                    "severity": "high",
                    "withdrawn": false,
                    "observables": [{
                        "kind": "package-purl",
                        "value": "pkg:npm/only-bounded-vuln",
                        "version_range": ">=1.0.0, <1.2.0"
                    }],
                    "evidence": [{
                        "feed": "ghsa",
                        "organisation": "GHSA",
                        "method_family": "advisory_feed",
                        "nature": "vulnerable",
                        "review_state": "maintainer_verified",
                        "disposition": "active",
                        "reference_url": null,
                        "summary": "High bounded"
                    }]
                }
            ]
        })
        .to_string();
        let pack = validate_intel_pack_json(&vuln_pack_json).unwrap();
        let idx = IntelIndex::from_pack(&pack).unwrap();
        let mut breaker = IntelCircuitBreaker::default();

        match idx.lookup(
            ObservableKind::PackagePurl,
            "pkg:npm/only-bounded-vuln",
            "dev-1",
            1_000,
            Mode::Block,
            &mut breaker,
        ) {
            ReputationVerdict::Vulnerable(m) => {
                assert_eq!(m.effective_mode, Mode::Watch);
                assert_eq!(m.entry.record_id, "GRDRI-2026-00603");
            }
            other => panic!("expected Vulnerable for unversioned bounded vuln, got {other:?}"),
        }

        match idx.lookup(
            ObservableKind::PackagePurl,
            "pkg:npm/agent-sdk",
            "dev-1",
            1_000,
            Mode::Block,
            &mut breaker,
        ) {
            ReputationVerdict::Vulnerable(m) => {
                assert_eq!(m.effective_mode, Mode::Watch);
                assert_eq!(m.entry.record_id, "GRDRI-2026-00602");
            }
            other => panic!("expected Critical unbounded Vulnerable to win, got {other:?}"),
        }

        // 2. > ONE_HOUR_MS backward clock skew in IntelCircuitBreaker must NOT drop hits or diverge state().
        let mut cb = IntelCircuitBreaker::default();
        assert_eq!(
            cb.record_new_block("dev-secret-tag", 1, "Domain:a.test", 10_000_000)
                .unwrap(),
            BreakerState::Closed
        );
        assert_eq!(
            cb.record_new_block("dev-secret-tag", 1, "Domain:b.test", 5_000_000)
                .unwrap(),
            BreakerState::Closed
        );
        assert_eq!(
            cb.record_new_block("dev-secret-tag", 1, "Domain:c.test", 5_000_000)
                .unwrap(),
            BreakerState::Closed
        );
        let trip_err = cb
            .record_new_block("dev-secret-tag", 1, "Domain:d.test", 5_000_000)
            .unwrap_err();
        assert!(!trip_err.to_string().contains("dev-secret-tag"));
        assert_eq!(cb.state("dev-secret-tag", 5_000_000), BreakerState::Tripped);
        assert_eq!(
            cb.record_new_block("dev-secret-tag", 1, "Domain:a.test", 5_000_000)
                .unwrap(),
            BreakerState::Tripped
        );
        assert!(
            cb.record_new_block("dev-1", 1, "Domain:a.test", -1)
                .is_err()
        );
        assert!(
            cb.record_new_block("   ", 1, "Domain:a.test", 1000)
                .is_err()
        );

        // 3. IntelIndex and IntelVerdictEntry Deserialize enforce deny_unknown_fields, canonical
        // guard_domains, bucket key consistency, fuse membership, and entry syntax bounds.
        let rt_json = serde_json::to_string(&idx).unwrap();
        assert_eq!(serde_json::from_str::<IntelIndex>(&rt_json).unwrap(), idx);

        let mut raw_val: serde_json::Value = serde_json::from_str(&rt_json).unwrap();
        raw_val["extra_field"] = serde_json::json!(true);
        assert!(serde_json::from_value::<IntelIndex>(raw_val.clone()).is_err());
        raw_val.as_object_mut().unwrap().remove("extra_field");

        let mut bad_guard = raw_val.clone();
        bad_guard["guard_domains"] = serde_json::json!(["GITHUB.COM"]);
        assert!(serde_json::from_value::<IntelIndex>(bad_guard).is_err());

        let mut bad_bucket = raw_val;
        bad_bucket["exact_entries"] = serde_json::json!({
            "Domain:not-in-fuse.test": [{
                "record_id": "GRDRI-2026-00699",
                "kind": "domain",
                "canonical_value": "Domain:not-in-fuse.test",
                "version_range": null,
                "status": "malicious",
                "severity": "high",
                "activation_epoch": 1
            }]
        });
        assert!(serde_json::from_value::<IntelIndex>(bad_bucket).is_err());

        let bad_entry_url = serde_json::json!({
            "record_id": "GRDRI-2026-00699",
            "kind": "url",
            "canonical_value": "Url:javascript:alert(1)",
            "version_range": null,
            "status": "malicious",
            "severity": "high",
            "activation_epoch": 1
        });
        assert!(serde_json::from_value::<IntelVerdictEntry>(bad_entry_url).is_err());
    }

    #[test]
    fn round5_intel_index_cve_ghsa_roundtrip_and_purl_version_injection_guards() {
        use crate::pack::{IntelPackManifest, PackKind, Polarity, ValidatedIntelPack};
        use crate::record::{
            ClaimDisposition, ClaimNature, EvidenceFeed, IntelEvidence, IntelObservable,
            IntelRecord, MethodFamily, ReviewState,
        };

        // 1. Shipped sample-intel-pack.json (includes PackagePurl + Ghsa) roundtrips through IntelIndex.
        let shipped =
            validate_intel_pack_json(include_str!("../../../packs/intel/sample-intel-pack.json"))
                .expect("shipped pack valid");
        let shipped_idx = IntelIndex::from_pack(&shipped).expect("shipped index");
        let shipped_rt_json = serde_json::to_string(&shipped_idx).expect("serialize shipped index");
        let shipped_rt: IntelIndex =
            serde_json::from_str(&shipped_rt_json).expect("deserialize shipped index");
        assert_eq!(shipped_rt, shipped_idx);

        // 2. Pack with Cve + Ghsa + benign non-SemVer pinned PURL roundtrips and matches strictly.
        let r5_pack_json = serde_json::json!({
            "pack_id": "grdr.intel.round5",
            "kind": "intel",
            "polarity": "protect",
            "version": "1.0.0",
            "channel": "standard",
            "publisher": "OSSF",
            "records": [
                {
                    "id": "GRDRI-2026-00701",
                    "title": "CVE advisory",
                    "severity": "high",
                    "withdrawn": false,
                    "observables": [{ "kind": "cve", "value": "CVE-2026-9999", "version_range": null }],
                    "evidence": [{
                        "feed": "kev",
                        "organisation": "CISA",
                        "method_family": "exploit_telemetry",
                        "nature": "vulnerable",
                        "review_state": "published_external_human_review",
                        "disposition": "active",
                        "reference_url": null,
                        "summary": "KEV CVE"
                    }]
                },
                {
                    "id": "GRDRI-2026-00702",
                    "title": "GHSA advisory",
                    "severity": "high",
                    "withdrawn": false,
                    "observables": [{ "kind": "ghsa", "value": "GHSA-1111-2222-3333", "version_range": null }],
                    "evidence": [{
                        "feed": "ghsa",
                        "organisation": "GHSA",
                        "method_family": "advisory_feed",
                        "nature": "vulnerable",
                        "review_state": "maintainer_verified",
                        "disposition": "active",
                        "reference_url": null,
                        "summary": "GHSA"
                    }]
                },
                {
                    "id": "GRDRI-2026-00703",
                    "title": "Benign non-SemVer pinned PURL",
                    "severity": "critical",
                    "withdrawn": false,
                    "observables": [{
                        "kind": "package-purl",
                        "value": "pkg:pypi/evil@1.0.2.post1",
                        "version_range": null
                    }],
                    "evidence": [{
                        "feed": "ossf",
                        "organisation": "OSSF",
                        "method_family": "human_review",
                        "nature": "malicious",
                        "review_state": "published_external_human_review",
                        "disposition": "active",
                        "reference_url": null,
                        "summary": "Malicious post1 release"
                    }]
                }
            ]
        })
        .to_string();
        let r5_pack = validate_intel_pack_json(&r5_pack_json).expect("valid r5 pack");
        let r5_idx = IntelIndex::from_pack(&r5_pack).expect("r5 index");
        let r5_rt_json = serde_json::to_string(&r5_idx).expect("serialize r5 index");
        let r5_rt: IntelIndex = serde_json::from_str(&r5_rt_json).expect("deserialize r5 index");
        assert_eq!(r5_rt, r5_idx);

        let mut breaker = IntelCircuitBreaker::default();
        assert!(matches!(
            r5_rt.lookup(
                ObservableKind::Cve,
                "CVE-2026-9999",
                "dev-1",
                1_000,
                Mode::Block,
                &mut breaker,
            ),
            ReputationVerdict::Vulnerable(m) if m.effective_mode == Mode::Watch
        ));
        assert!(matches!(
            r5_rt.lookup(
                ObservableKind::Ghsa,
                "GHSA-1111-2222-3333",
                "dev-1",
                1_000,
                Mode::Block,
                &mut breaker,
            ),
            ReputationVerdict::Vulnerable(m) if m.effective_mode == Mode::Watch
        ));
        assert!(matches!(
            r5_rt.lookup(
                ObservableKind::PackagePurl,
                "pkg:pypi/evil@1.0.2.post1",
                "dev-1",
                1_000,
                Mode::Block,
                &mut breaker,
            ),
            ReputationVerdict::Malicious(m) if m.effective_mode == Mode::Block
        ));
        assert_eq!(
            r5_rt.lookup(
                ObservableKind::PackagePurl,
                "pkg:pypi/evil@9.9.9",
                "dev-1",
                1_000,
                Mode::Block,
                &mut breaker,
            ),
            ReputationVerdict::Unrated
        );
        assert!(matches!(
            r5_rt.lookup(
                ObservableKind::PackagePurl,
                "pkg:pypi/evil",
                "dev-1",
                1_000,
                Mode::Block,
                &mut breaker,
            ),
            ReputationVerdict::Suspicious(m) if m.effective_mode == Mode::Ask
        ));

        // 3. Non-canonical uppercase Cve/Ghsa entries must still fail IntelVerdictEntry deserialization.
        for (kind, canonical_val) in [
            ("cve", "Cve:CVE-2026-9999"),
            ("ghsa", "Ghsa:GHSA-0000-0000-0002"),
            ("ghsa", "Ghsa:ghsa-AAAA-0000-0002"),
        ] {
            let non_canon = serde_json::json!({
                "record_id": "GRDRI-2026-00704",
                "kind": kind,
                "canonical_value": canonical_val,
                "version_range": null,
                "status": "vulnerable",
                "severity": "high",
                "activation_epoch": 1
            });
            assert!(
                serde_json::from_value::<IntelVerdictEntry>(non_canon).is_err(),
                "must reject non-canonical {canonical_val}"
            );
        }

        // 4. PURL @version injection rejected in IntelIndex::from_pack and serde deserialization.
        let injected_pack = ValidatedIntelPack {
            manifest: IntelPackManifest {
                pack_id: "grdr.intel.bad".into(),
                kind: PackKind::Intel,
                polarity: Polarity::Protect,
                version: "1.0.0".into(),
                channel: "standard".into(),
                publisher: "Attacker".into(),
                guard_domains: Vec::new(),
            },
            records: vec![IntelRecord {
                id: GrdrIntelId::parse("GRDRI-2026-00705").unwrap(),
                title: "Injected PURL range".into(),
                severity: IntelSeverity::Critical,
                withdrawn: false,
                observables: vec![IntelObservable {
                    kind: ObservableKind::PackagePurl,
                    value: "pkg:npm/evil@1.0.0||>=0.0.0-0".into(),
                    version_range: None,
                }],
                evidence: vec![IntelEvidence {
                    feed: EvidenceFeed::Ossf,
                    organisation: "OSSF".into(),
                    method_family: MethodFamily::HumanReview,
                    nature: ClaimNature::Malicious,
                    review_state: ReviewState::PublishedExternalHumanReview,
                    disposition: ClaimDisposition::Active,
                    reference_url: None,
                    based_on_organisation: None,
                    summary: "Injected".into(),
                }],
            }],
            active_malicious_count: 1,
            active_suspicious_count: 0,
            active_vulnerable_count: 0,
            withdrawn_count: 0,
        };
        assert!(IntelIndex::from_pack(&injected_pack).is_err());

        let injected_entry = serde_json::json!({
            "record_id": "GRDRI-2026-00705",
            "kind": "package-purl",
            "canonical_value": "PackagePurl:pkg:npm/evil@1.0.0||>=0.0.0-0",
            "version_range": null,
            "status": "malicious",
            "severity": "critical",
            "activation_epoch": 1
        });
        assert!(serde_json::from_value::<IntelVerdictEntry>(injected_entry).is_err());

        // 5. Mixed-case non-SemVer & prerelease PURLs match version_range via canonicalize_purl.
        let mixed_case_pack = ValidatedIntelPack {
            manifest: IntelPackManifest {
                pack_id: "grdr.intel.case".into(),
                kind: PackKind::Intel,
                polarity: Polarity::Protect,
                version: "1.0.0".into(),
                channel: "standard".into(),
                publisher: "SecLab".into(),
                guard_domains: Vec::new(),
            },
            records: vec![
                IntelRecord {
                    id: GrdrIntelId::parse("GRDRI-2026-00706").unwrap(),
                    title: "Mixed-case non-SemVer token".into(),
                    severity: IntelSeverity::High,
                    withdrawn: false,
                    observables: vec![IntelObservable {
                        kind: ObservableKind::PackagePurl,
                        value: "pkg:maven/org.evil/lib".into(),
                        version_range: Some("==1.0.0 || ==1.0.0.Final".into()),
                    }],
                    evidence: vec![IntelEvidence {
                        feed: EvidenceFeed::Ghsa,
                        organisation: "GHSA".into(),
                        method_family: MethodFamily::HumanReview,
                        nature: ClaimNature::Malicious,
                        review_state: ReviewState::PublishedExternalHumanReview,
                        disposition: ClaimDisposition::Active,
                        reference_url: None,
                        based_on_organisation: None,
                        summary: "Mixed-case non-SemVer match".into(),
                    }],
                },
                IntelRecord {
                    id: GrdrIntelId::parse("GRDRI-2026-00707").unwrap(),
                    title: "Mixed-case SemVer prerelease".into(),
                    severity: IntelSeverity::Critical,
                    withdrawn: false,
                    observables: vec![IntelObservable {
                        kind: ObservableKind::PackagePurl,
                        value: "pkg:npm/evil-pre".into(),
                        version_range: Some(">=1.0.0-RC1, <1.0.0-RC3".into()),
                    }],
                    evidence: vec![IntelEvidence {
                        feed: EvidenceFeed::Ossf,
                        organisation: "OSSF".into(),
                        method_family: MethodFamily::HumanReview,
                        nature: ClaimNature::Malicious,
                        review_state: ReviewState::PublishedExternalHumanReview,
                        disposition: ClaimDisposition::Active,
                        reference_url: None,
                        based_on_organisation: None,
                        summary: "Mixed-case SemVer prerelease match".into(),
                    }],
                },
            ],
            active_malicious_count: 2,
            active_suspicious_count: 0,
            active_vulnerable_count: 0,
            withdrawn_count: 0,
        };
        let mixed_idx = IntelIndex::from_pack(&mixed_case_pack).expect("mixed case index");
        let mut mixed_breaker = IntelCircuitBreaker::default();
        assert!(matches!(
            mixed_idx.lookup(
                ObservableKind::PackagePurl,
                "pkg:maven/org.evil/lib@1.0.0.Final",
                "dev-1",
                1_000,
                Mode::Block,
                &mut mixed_breaker,
            ),
            ReputationVerdict::Malicious(_)
        ));
        assert!(matches!(
            mixed_idx.lookup(
                ObservableKind::PackagePurl,
                "pkg:npm/evil-pre@1.0.0-rc2",
                "dev-1",
                1_000,
                Mode::Block,
                &mut mixed_breaker,
            ),
            ReputationVerdict::Malicious(_)
        ));
        assert_eq!(
            mixed_idx.lookup(
                ObservableKind::PackagePurl,
                "pkg:npm/evil-pre@1.0.0-rc3",
                "dev-1",
                1_000,
                Mode::Block,
                &mut mixed_breaker,
            ),
            ReputationVerdict::Unrated
        );
    }
}
