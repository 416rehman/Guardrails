// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors

//! `GRDRI-YYYY-NNNNN` threat intelligence records and pure deterministic `status` classifier (`docs/design/14`).

use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};

use crate::IntelError;
use crate::governance::default_intel_governance;

pub const MIN_MALICIOUS_INDEPENDENT_SOURCES: usize = 2;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum IntelStatus {
    None,
    Vulnerable,
    Suspicious,
    Malicious,
    Withdrawn,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum IntelSeverity {
    Low,
    Medium,
    High,
    Critical,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ObservableKind {
    Sha256,
    PackagePurl,
    Domain,
    Url,
    IpAddress,
    Cve,
    Ghsa,
    SignerFingerprint,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EvidenceFeed {
    Ossf,
    Ghsa,
    Kev,
    Osv,
    Nvd,
    SensorSighting,
    VendorAdvisory,
    ResearcherReport,
    ExternalHumanReview,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MethodFamily {
    StaticAnalysis,
    DynamicSandbox,
    HumanReview,
    AdvisoryFeed,
    ExploitTelemetry,
    CryptographicRevocation,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ClaimDisposition {
    Active,
    Retracted,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ClaimNature {
    Malicious,
    Suspicious,
    Vulnerable,
    CompetitorDisputed,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReviewState {
    Unreviewed,
    PublishedExternalHumanReview,
    MaintainerVerified,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct IntelObservable {
    pub kind: ObservableKind,
    pub value: String,
    pub version_range: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct IntelEvidence {
    pub feed: EvidenceFeed,
    pub organisation: String,
    pub method_family: MethodFamily,
    pub nature: ClaimNature,
    pub review_state: ReviewState,
    pub disposition: ClaimDisposition,
    pub reference_url: Option<String>,
    #[serde(default)]
    pub based_on_organisation: Option<String>,
    pub summary: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(try_from = "String")]
pub struct GrdrIntelId(String);

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct IntelRecord {
    pub id: GrdrIntelId,
    pub title: String,
    pub severity: IntelSeverity,
    pub withdrawn: bool,
    pub observables: Vec<IntelObservable>,
    pub evidence: Vec<IntelEvidence>,
}

enum EffectiveProducer {
    InternalEcho,
    InternalOwn,
    External(String),
}

impl TryFrom<String> for GrdrIntelId {
    type Error = IntelError;

    fn try_from(raw: String) -> Result<Self, Self::Error> {
        Self::parse(&raw)
    }
}

impl GrdrIntelId {
    /// Parses and validates canonical `GRDRI-YYYY-NNNNN` identifiers.
    pub fn parse(raw: &str) -> Result<Self, IntelError> {
        if raw != raw.trim() || raw.chars().any(char::is_control) {
            return Err(IntelError::InvalidRecord(
                "GRDRI identifier cannot contain leading/trailing whitespace or control characters"
                    .into(),
            ));
        }
        let Some(rest) = raw.strip_prefix("GRDRI-") else {
            return Err(IntelError::InvalidRecord(
                "expected `GRDRI-YYYY-NNNNN` prefix".into(),
            ));
        };
        let Some((year_str, seq_str)) = rest.split_once('-') else {
            return Err(IntelError::InvalidRecord(
                "missing sequence separator in GRDRI identifier".into(),
            ));
        };
        if year_str.len() != 4 || !year_str.bytes().all(|b| b.is_ascii_digit()) {
            return Err(IntelError::InvalidRecord(
                "invalid year component in GRDRI identifier".into(),
            ));
        }
        let year: u16 = year_str
            .parse()
            .map_err(|_| IntelError::InvalidRecord("unparseable year".into()))?;
        if year < 2024 {
            return Err(IntelError::InvalidRecord(format!(
                "GRDRI year `{year}` predates platform launch (2024)"
            )));
        }
        if seq_str.len() != 5 || !seq_str.bytes().all(|b| b.is_ascii_digit()) {
            return Err(IntelError::InvalidRecord(
                "expected 5-digit sequence in GRDRI identifier".into(),
            ));
        }
        Ok(Self(raw.to_owned()))
    }

    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// Pure deterministic `status` computation enforcing independence, external human-review,
/// competitor-claim, basis deduplication, vulnerability, and withdrawal rules (`docs/design/14`).
#[must_use]
pub fn compute_status(record: &IntelRecord) -> IntelStatus {
    if record.withdrawn {
        return IntelStatus::Withdrawn;
    }

    let active: Vec<&IntelEvidence> = record
        .evidence
        .iter()
        .filter(|ev| ev.disposition == ClaimDisposition::Active)
        .collect();

    if active.is_empty() {
        return IntelStatus::None;
    }

    let mut basis_owner_by_url: BTreeMap<String, String> = BTreeMap::new();
    for ev in &active {
        if ev.nature != ClaimNature::Malicious {
            continue;
        }
        let author_norm = normalize_org_token(&ev.organisation);
        let own_norm = producer_org_token(ev);
        if author_norm.is_empty()
            || author_norm == "__self__"
            || own_norm.is_empty()
            || own_norm == "__self__"
        {
            continue;
        }
        if let Some(ref_url) = ev.reference_url.as_deref() {
            let ref_norm = normalize_basis_url(ref_url);
            if !ref_norm.is_empty() {
                basis_owner_by_url.entry(ref_norm).or_insert(own_norm);
            }
        }
    }

    let mut malicious_orgs = BTreeSet::new();
    let mut malicious_methods = BTreeSet::new();
    let mut malicious_pairs: BTreeSet<(String, MethodFamily)> = BTreeSet::new();
    let mut has_external_human_review = false;
    let mut has_external_malicious = false;
    let mut saw_any_malicious_or_suspicious = false;
    let mut saw_competitor_disputed = false;
    let mut saw_vulnerable = false;

    for ev in &active {
        match ev.nature {
            ClaimNature::Malicious => {
                saw_any_malicious_or_suspicious = true;
                match resolve_effective_producer(ev, &basis_owner_by_url) {
                    None => continue,
                    Some(EffectiveProducer::InternalEcho) => {}
                    Some(EffectiveProducer::InternalOwn) => {
                        if malicious_pairs.insert(("__self__".to_owned(), ev.method_family)) {
                            malicious_orgs.insert("__self__".to_owned());
                            malicious_methods.insert(ev.method_family);
                        }
                    }
                    Some(EffectiveProducer::External(effective_org)) => {
                        has_external_malicious = true;
                        if ev.review_state == ReviewState::PublishedExternalHumanReview
                            && ev.method_family == MethodFamily::HumanReview
                            && !matches!(
                                ev.feed,
                                EvidenceFeed::SensorSighting | EvidenceFeed::VendorAdvisory
                            )
                        {
                            has_external_human_review = true;
                        }
                        if malicious_pairs.insert((effective_org.clone(), ev.method_family)) {
                            malicious_orgs.insert(effective_org);
                            malicious_methods.insert(ev.method_family);
                        }
                    }
                }
            }
            ClaimNature::CompetitorDisputed => {
                saw_competitor_disputed = true;
                saw_any_malicious_or_suspicious = true;
            }
            ClaimNature::Suspicious => {
                saw_any_malicious_or_suspicious = true;
            }
            ClaimNature::Vulnerable => {
                saw_vulnerable = true;
            }
        }
    }

    let has_independent_corroboration = malicious_orgs.len() >= MIN_MALICIOUS_INDEPENDENT_SOURCES
        && malicious_methods.len() >= MIN_MALICIOUS_INDEPENDENT_SOURCES
        && malicious_pairs.len() >= MIN_MALICIOUS_INDEPENDENT_SOURCES;

    let competitor_blocks_internal_only = saw_competitor_disputed && !has_external_malicious;

    if !competitor_blocks_internal_only
        && (has_external_human_review || has_independent_corroboration)
    {
        IntelStatus::Malicious
    } else if saw_any_malicious_or_suspicious {
        IntelStatus::Suspicious
    } else if saw_vulnerable {
        IntelStatus::Vulnerable
    } else {
        IntelStatus::None
    }
}

fn producer_org_token(ev: &IntelEvidence) -> String {
    let raw_producer = ev
        .based_on_organisation
        .as_deref()
        .filter(|s| !s.trim().is_empty())
        .unwrap_or(&ev.organisation);
    normalize_org_token(raw_producer)
}

fn resolve_effective_producer(
    ev: &IntelEvidence,
    basis_owner_by_url: &BTreeMap<String, String>,
) -> Option<EffectiveProducer> {
    let author_norm = normalize_org_token(&ev.organisation);
    let own_norm = producer_org_token(ev);
    if author_norm.is_empty() || own_norm.is_empty() {
        return None;
    }
    let is_external = author_norm != "__self__" && own_norm != "__self__";
    if let Some(ref_url) = ev.reference_url.as_deref() {
        let ref_norm = normalize_basis_url(ref_url);
        if !ref_norm.is_empty()
            && let Some(existing_owner) = basis_owner_by_url.get(&ref_norm)
        {
            return Some(if is_external {
                EffectiveProducer::External(existing_owner.clone())
            } else {
                EffectiveProducer::InternalEcho
            });
        }
    }
    if !is_external {
        if author_norm == "__self__" && own_norm != "__self__" {
            return Some(EffectiveProducer::InternalEcho);
        }
        return Some(EffectiveProducer::InternalOwn);
    }
    Some(EffectiveProducer::External(own_norm))
}

#[must_use]
pub fn normalize_org_token(raw: &str) -> String {
    let words: Vec<String> = raw
        .split(|c: char| !c.is_ascii_alphanumeric())
        .filter(|s| !s.is_empty())
        .map(str::to_ascii_lowercase)
        .collect();
    if words.is_empty() {
        return String::new();
    }
    let compact: String = words.concat();
    let Ok(gov) = default_intel_governance() else {
        return "__self__".to_owned();
    };
    let is_self = gov
        .self_org_aliases
        .iter()
        .any(|a| a == &compact || words.iter().any(|w| w == a))
        || gov
            .self_org_substring_aliases
            .iter()
            .any(|a| compact.contains(a.as_str()));
    if is_self {
        return "__self__".to_owned();
    } else if gov.ossf_aliases.iter().any(|a| a == &compact) {
        return "ossf".to_owned();
    } else if gov.ghsa_aliases.iter().any(|a| a == &compact) {
        return "ghsa".to_owned();
    }
    compact
}

fn normalize_basis_url(raw: &str) -> String {
    let trimmed = raw.trim();
    if let Ok(mut parsed) = url::Url::parse(trimmed)
        && !parsed.cannot_be_a_base()
        && parsed.set_username("").is_ok()
        && parsed.set_password(None).is_ok()
    {
        parsed.set_fragment(None);
        return parsed
            .to_string()
            .trim_end_matches('/')
            .to_ascii_lowercase();
    }
    trimmed.trim_end_matches('/').to_ascii_lowercase()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn mk_ev(
        feed: EvidenceFeed,
        org: &str,
        method: MethodFamily,
        nature: ClaimNature,
        review_state: ReviewState,
    ) -> IntelEvidence {
        IntelEvidence {
            feed,
            organisation: org.into(),
            method_family: method,
            nature,
            review_state,
            disposition: ClaimDisposition::Active,
            reference_url: None,
            based_on_organisation: None,
            summary: "test".into(),
        }
    }

    #[test]
    fn deterministic_status_enforces_two_independent_sources_competitor_and_withdrawal() {
        let id = GrdrIntelId::parse("GRDRI-2026-00042").expect("valid id");
        assert!(GrdrIntelId::parse("GRDRI-2026-42").is_err());

        let single = IntelRecord {
            id: id.clone(),
            title: "pkg-a".into(),
            severity: IntelSeverity::High,
            withdrawn: false,
            observables: Vec::new(),
            evidence: vec![mk_ev(
                EvidenceFeed::VendorAdvisory,
                "OrgA",
                MethodFamily::StaticAnalysis,
                ClaimNature::Malicious,
                ReviewState::Unreviewed,
            )],
        };
        assert_eq!(compute_status(&single), IntelStatus::Suspicious);

        let same_method = IntelRecord {
            evidence: vec![
                mk_ev(
                    EvidenceFeed::VendorAdvisory,
                    "OrgA",
                    MethodFamily::StaticAnalysis,
                    ClaimNature::Malicious,
                    ReviewState::Unreviewed,
                ),
                mk_ev(
                    EvidenceFeed::ResearcherReport,
                    "OrgB",
                    MethodFamily::StaticAnalysis,
                    ClaimNature::Malicious,
                    ReviewState::Unreviewed,
                ),
            ],
            ..single.clone()
        };
        assert_eq!(compute_status(&same_method), IntelStatus::Suspicious);

        let dual_indep = IntelRecord {
            evidence: vec![
                mk_ev(
                    EvidenceFeed::VendorAdvisory,
                    "OrgA",
                    MethodFamily::StaticAnalysis,
                    ClaimNature::Malicious,
                    ReviewState::Unreviewed,
                ),
                mk_ev(
                    EvidenceFeed::Ossf,
                    "OSSF",
                    MethodFamily::DynamicSandbox,
                    ClaimNature::Malicious,
                    ReviewState::Unreviewed,
                ),
            ],
            ..single.clone()
        };
        assert_eq!(compute_status(&dual_indep), IntelStatus::Malicious);

        let competitor = IntelRecord {
            evidence: vec![mk_ev(
                EvidenceFeed::VendorAdvisory,
                "RivalVendor",
                MethodFamily::DynamicSandbox,
                ClaimNature::CompetitorDisputed,
                ReviewState::Unreviewed,
            )],
            ..single.clone()
        };
        assert_eq!(compute_status(&competitor), IntelStatus::Suspicious);

        let reviewed = IntelRecord {
            evidence: vec![mk_ev(
                EvidenceFeed::ExternalHumanReview,
                "IndependentSecurityLab",
                MethodFamily::HumanReview,
                ClaimNature::Malicious,
                ReviewState::PublishedExternalHumanReview,
            )],
            ..single
        };
        assert_eq!(compute_status(&reviewed), IntelStatus::Malicious);

        let withdrawn = IntelRecord {
            withdrawn: true,
            ..reviewed
        };
        assert_eq!(compute_status(&withdrawn), IntelStatus::Withdrawn);
    }

    #[test]
    fn negative_cases_block_maintainer_shortcut_self_review_aliases_and_internal_competitor() {
        let id = GrdrIntelId::parse("GRDRI-2026-00043").expect("valid id");

        let maintainer_only = IntelRecord {
            id: id.clone(),
            title: "maintainer-only".into(),
            severity: IntelSeverity::Critical,
            withdrawn: false,
            observables: Vec::new(),
            evidence: vec![mk_ev(
                EvidenceFeed::VendorAdvisory,
                "ExternalVendor",
                MethodFamily::HumanReview,
                ClaimNature::Malicious,
                ReviewState::MaintainerVerified,
            )],
        };
        assert_eq!(compute_status(&maintainer_only), IntelStatus::Suspicious);

        let non_human_method = IntelRecord {
            evidence: vec![mk_ev(
                EvidenceFeed::ExternalHumanReview,
                "ExternalLab",
                MethodFamily::DynamicSandbox,
                ClaimNature::Malicious,
                ReviewState::PublishedExternalHumanReview,
            )],
            ..maintainer_only.clone()
        };
        assert_eq!(compute_status(&non_human_method), IntelStatus::Suspicious);

        let self_human_review = IntelRecord {
            evidence: vec![mk_ev(
                EvidenceFeed::ExternalHumanReview,
                "Loonaro",
                MethodFamily::HumanReview,
                ClaimNature::Malicious,
                ReviewState::PublishedExternalHumanReview,
            )],
            ..maintainer_only.clone()
        };
        assert_eq!(compute_status(&self_human_review), IntelStatus::Suspicious);

        let whitespace_alias = IntelRecord {
            evidence: vec![
                mk_ev(
                    EvidenceFeed::ResearcherReport,
                    "OrgA",
                    MethodFamily::StaticAnalysis,
                    ClaimNature::Malicious,
                    ReviewState::Unreviewed,
                ),
                mk_ev(
                    EvidenceFeed::ResearcherReport,
                    "Org A",
                    MethodFamily::DynamicSandbox,
                    ClaimNature::Malicious,
                    ReviewState::Unreviewed,
                ),
            ],
            ..maintainer_only.clone()
        };
        assert_eq!(compute_status(&whitespace_alias), IntelStatus::Suspicious);

        let mut echoed = mk_ev(
            EvidenceFeed::ResearcherReport,
            "MirrorOrg",
            MethodFamily::DynamicSandbox,
            ClaimNature::Malicious,
            ReviewState::Unreviewed,
        );
        echoed.based_on_organisation = Some("VendorAlpha".into());
        let basis_linked = IntelRecord {
            evidence: vec![
                mk_ev(
                    EvidenceFeed::VendorAdvisory,
                    "Vendor Alpha",
                    MethodFamily::StaticAnalysis,
                    ClaimNature::Malicious,
                    ReviewState::Unreviewed,
                ),
                echoed,
            ],
            ..maintainer_only.clone()
        };
        assert_eq!(compute_status(&basis_linked), IntelStatus::Suspicious);

        let shared_url_a = IntelEvidence {
            reference_url: Some("https://blog.example/report-1/".into()),
            ..mk_ev(
                EvidenceFeed::ResearcherReport,
                "BlogOne",
                MethodFamily::StaticAnalysis,
                ClaimNature::Malicious,
                ReviewState::Unreviewed,
            )
        };
        let shared_url_b = IntelEvidence {
            reference_url: Some("https://blog.example/report-1".into()),
            ..mk_ev(
                EvidenceFeed::Ossf,
                "OSSF",
                MethodFamily::DynamicSandbox,
                ClaimNature::Malicious,
                ReviewState::Unreviewed,
            )
        };
        let url_echo = IntelRecord {
            evidence: vec![shared_url_a, shared_url_b],
            ..maintainer_only.clone()
        };
        assert_eq!(compute_status(&url_echo), IntelStatus::Suspicious);

        let competitor_internal_only = IntelRecord {
            id,
            evidence: vec![
                mk_ev(
                    EvidenceFeed::VendorAdvisory,
                    "RivalCorp",
                    MethodFamily::AdvisoryFeed,
                    ClaimNature::CompetitorDisputed,
                    ReviewState::Unreviewed,
                ),
                mk_ev(
                    EvidenceFeed::ResearcherReport,
                    "Loonaro",
                    MethodFamily::StaticAnalysis,
                    ClaimNature::Malicious,
                    ReviewState::Unreviewed,
                ),
                mk_ev(
                    EvidenceFeed::ResearcherReport,
                    "Guardrails ADR",
                    MethodFamily::DynamicSandbox,
                    ClaimNature::Malicious,
                    ReviewState::Unreviewed,
                ),
            ],
            ..maintainer_only
        };
        assert_eq!(
            compute_status(&competitor_internal_only),
            IntelStatus::Suspicious
        );
    }

    #[test]
    fn round2_record_id_serde_and_self_first_external_url_isolation() {
        // GrdrIntelId serde must reject leading/trailing whitespace and control characters.
        for bad_json in [
            "\" GRDRI-2026-00001\"",
            "\"\\nGRDRI-2026-00001 \"",
            "\"GRDRI-2026-00001\\u0000\"",
        ] {
            assert!(
                serde_json::from_str::<GrdrIntelId>(bad_json).is_err(),
                "expected serde rejection of {bad_json}"
            );
        }

        // "__self__" appearing BEFORE PublishedExternalHumanReview sharing the same reference_url
        // must NOT taint external attribution into internal "__self__".
        let id = GrdrIntelId::parse("GRDRI-2026-00099").unwrap();
        let self_first = IntelEvidence {
            reference_url: Some("https://vendor.example/advisory-42".into()),
            ..mk_ev(
                EvidenceFeed::ResearcherReport,
                "Guardrails Team",
                MethodFamily::StaticAnalysis,
                ClaimNature::Malicious,
                ReviewState::Unreviewed,
            )
        };
        let external_human = IntelEvidence {
            reference_url: Some("https://vendor.example/advisory-42".into()),
            ..mk_ev(
                EvidenceFeed::Ossf,
                "OSSF",
                MethodFamily::DynamicSandbox,
                ClaimNature::Malicious,
                ReviewState::PublishedExternalHumanReview,
            )
        };
        let second_external = IntelEvidence {
            reference_url: Some("https://socket.example/advisory-99".into()),
            ..mk_ev(
                EvidenceFeed::VendorAdvisory,
                "Socket Research",
                MethodFamily::StaticAnalysis,
                ClaimNature::Malicious,
                ReviewState::PublishedExternalHumanReview,
            )
        };
        let rec = IntelRecord {
            id: id.clone(),
            title: "Self pre-pass test".into(),
            severity: IntelSeverity::High,
            withdrawn: false,
            observables: vec![IntelObservable {
                kind: ObservableKind::Domain,
                value: "evil.test".into(),
                version_range: None,
            }],
            evidence: vec![self_first, external_human, second_external],
        };
        assert_eq!(compute_status(&rec), IntelStatus::Malicious);

        // Word-token / brand-prefix aliases map "Loonaro Labs" + "Guardrails Team" -> "__self__", unlike "RivalLabs".
        assert_eq!(normalize_org_token("Loonaro Labs"), "__self__");
        assert_eq!(normalize_org_token("Guardrails Team"), "__self__");
        assert_eq!(normalize_org_token("RivalLabs"), "rivallabs");
        let self_brand = mk_ev(
            EvidenceFeed::ResearcherReport,
            "Loonaro Labs",
            MethodFamily::StaticAnalysis,
            ClaimNature::Malicious,
            ReviewState::PublishedExternalHumanReview,
        );
        let self_team = mk_ev(
            EvidenceFeed::VendorAdvisory,
            "Guardrails Team",
            MethodFamily::DynamicSandbox,
            ClaimNature::Malicious,
            ReviewState::PublishedExternalHumanReview,
        );
        let brand_rec = IntelRecord {
            id,
            title: "Brand token check".into(),
            severity: IntelSeverity::High,
            withdrawn: false,
            observables: vec![IntelObservable {
                kind: ObservableKind::Domain,
                value: "brand.test".into(),
                version_range: None,
            }],
            evidence: vec![self_brand, self_team],
        };
        // Both normalize to "__self__" (single internal org) -> Suspicious (never Malicious).
        assert_eq!(compute_status(&brand_rec), IntelStatus::Suspicious);
    }

    #[test]
    fn round4_self_based_on_external_and_method_crediting_isolation() {
        let id = GrdrIntelId::parse("GRDRI-2026-00301").unwrap();

        // 1. Internal "__self__" claiming based_on_organisation="ExternalBlog" must NOT bypass
        // external human-review or competitor-dispute gates.
        let mut spoofed_human = mk_ev(
            EvidenceFeed::ExternalHumanReview,
            "Loonaro",
            MethodFamily::HumanReview,
            ClaimNature::Malicious,
            ReviewState::PublishedExternalHumanReview,
        );
        spoofed_human.based_on_organisation = Some("ExternalBlog".into());
        let rec_spoofed = IntelRecord {
            id: id.clone(),
            title: "Spoofed self human review".into(),
            severity: IntelSeverity::Critical,
            withdrawn: false,
            observables: vec![IntelObservable {
                kind: ObservableKind::Domain,
                value: "spoof.test".into(),
                version_range: None,
            }],
            evidence: vec![spoofed_human.clone()],
        };
        assert_eq!(compute_status(&rec_spoofed), IntelStatus::Suspicious);

        let competitor = mk_ev(
            EvidenceFeed::VendorAdvisory,
            "RivalVendor",
            MethodFamily::AdvisoryFeed,
            ClaimNature::CompetitorDisputed,
            ReviewState::Unreviewed,
        );
        let rec_comp = IntelRecord {
            evidence: vec![competitor, spoofed_human],
            ..rec_spoofed.clone()
        };
        assert_eq!(compute_status(&rec_comp), IntelStatus::Suspicious);

        // 2. Single-entry external PublishedExternalHumanReview AFTER __self__ sharing reference_url
        // must remain Malicious (isolated single-entry HumanReview without second_external).
        let self_first = IntelEvidence {
            reference_url: Some("HTTPS://Vendor.Example:443/report-42#top".into()),
            ..mk_ev(
                EvidenceFeed::ResearcherReport,
                "ACME Loonaro Security",
                MethodFamily::StaticAnalysis,
                ClaimNature::Malicious,
                ReviewState::Unreviewed,
            )
        };
        let ext_human_only = IntelEvidence {
            reference_url: Some("https://vendor.example/report-42/".into()),
            ..mk_ev(
                EvidenceFeed::ExternalHumanReview,
                "IndependentLab",
                MethodFamily::HumanReview,
                ClaimNature::Malicious,
                ReviewState::PublishedExternalHumanReview,
            )
        };
        let single_human_rec = IntelRecord {
            id: id.clone(),
            evidence: vec![self_first.clone(), ext_human_only],
            ..rec_spoofed.clone()
        };
        assert_eq!(compute_status(&single_human_rec), IntelStatus::Malicious);

        // 3. __self__ sharing reference_url with external OSSF must NOT credit its distinct
        // method_family onto OSSF (even when a second external org uses DynamicSandbox).
        let ossf_dyn = IntelEvidence {
            reference_url: Some("https://vendor.example/report-42".into()),
            ..mk_ev(
                EvidenceFeed::Ossf,
                "OSSF",
                MethodFamily::DynamicSandbox,
                ClaimNature::Malicious,
                ReviewState::Unreviewed,
            )
        };
        let socket_dyn = mk_ev(
            EvidenceFeed::VendorAdvisory,
            "Socket Research",
            MethodFamily::DynamicSandbox,
            ClaimNature::Malicious,
            ReviewState::Unreviewed,
        );
        let no_method_credit = IntelRecord {
            id,
            evidence: vec![self_first, ossf_dyn, socket_dyn],
            ..rec_spoofed
        };
        assert_eq!(compute_status(&no_method_credit), IntelStatus::Suspicious);

        // 4. Embedded brand names normalize to "__self__".
        assert_eq!(normalize_org_token("ACME Loonaro Security"), "__self__");
        assert_eq!(normalize_org_token("MyGuardrailsTeam"), "__self__");
        assert_eq!(
            normalize_org_token("CustomTheGuardrailsADRAuthorsTeam"),
            "__self__"
        );
        assert_eq!(
            normalize_basis_url("HTTPS://Blog.Example:443/report-1#sec"),
            normalize_basis_url("https://blog.example/report-1/")
        );
    }
}
