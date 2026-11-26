// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors

//! Privacy-preserving `k=5` multi-organisation sightings aggregation (`docs/design/14`).

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

use serde::{Deserialize, Serialize};
use zeroize::{Zeroize, Zeroizing};

use grdr_crypto::{domain_hmac_sha256, encode_lower_hex};

use crate::IntelError;
use crate::canonical::{normalize_observable, validate_public_artefact};
use crate::fuse::BinaryFuse24;
use crate::record::ObservableKind;

pub const MIN_SIGHTINGS_COHORT_K: usize = 5;
pub const MIN_ORG_TENURE_DAYS: u32 = 30;
pub const MIN_ORG_ENROLLED_DEVICES: u32 = 10;
pub const MAX_BUCKETS_PER_ORG: usize = 256;
pub const MAX_AGGREGATOR_BUCKETS: usize = 100_000;
pub const MAX_TRACKED_ORGS: usize = 100_000;
const MAX_BUCKET_SATURATED_ORGS: usize = 101;
pub const SIGHTINGS_RETENTION_DAYS: i64 = 30;
const MS_PER_DAY: i64 = 86_400_000;
const SIGHTING_HMAC_DOMAIN: &str = "grdr.intel.sighting.org.v1";

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum PrevalenceBucket {
    #[serde(rename = "5-20")]
    From5To20,
    #[serde(rename = "21-100")]
    From21To100,
    #[serde(rename = ">100")]
    Over100,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PublishedSighting {
    pub kind: ObservableKind,
    pub canonical_value: String,
    pub prevalence_bucket: PrevalenceBucket,
    pub first_seen_day: i64,
    pub last_seen_day: i64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PublicArtefactFilter {
    fuse: BinaryFuse24,
    exact_public_keys: BTreeSet<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ObservableBucket {
    kind: ObservableKind,
    canonical_value: String,
    salted_org_digests: BTreeSet<String>,
    first_seen_day: i64,
    last_seen_day: i64,
}

#[derive(Clone)]
pub struct SightingsAggregator {
    salt_key: Zeroizing<[u8; 32]>,
    public_filter: PublicArtefactFilter,
    buckets: BTreeMap<String, ObservableBucket>,
    org_bucket_counts: BTreeMap<String, usize>,
}

impl fmt::Debug for SightingsAggregator {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SightingsAggregator")
            .field("salt_key", &"[REDACTED]")
            .field("bucket_count", &self.buckets.len())
            .finish()
    }
}

impl PublicArtefactFilter {
    pub fn from_observables(entries: &[(ObservableKind, &str)]) -> Result<Self, IntelError> {
        let mut exact = BTreeSet::new();
        for &(kind, raw) in entries {
            let key = validate_public_artefact(kind, raw)?;
            exact.insert(key);
        }
        let keys_vec: Vec<String> = exact.iter().cloned().collect();
        let fuse = BinaryFuse24::build(&keys_vec)?;
        Ok(Self {
            fuse,
            exact_public_keys: exact,
        })
    }

    pub fn is_public_key(&self, canonical_key: &str) -> Result<bool, IntelError> {
        if !self.fuse.might_contain(canonical_key)? {
            return Ok(false);
        }
        Ok(self.exact_public_keys.contains(canonical_key))
    }
}

impl SightingsAggregator {
    #[must_use]
    pub fn new(mut salt_key: [u8; 32], public_filter: PublicArtefactFilter) -> Self {
        let wrapped = Zeroizing::new(salt_key);
        salt_key.zeroize();
        Self {
            salt_key: wrapped,
            public_filter,
            buckets: BTreeMap::new(),
            org_bucket_counts: BTreeMap::new(),
        }
    }

    /// Records a sighting after enforcing public-artefact membership, org eligibility,
    /// epoch-bound HMAC pseudonymization, per-org flood bounds, server-clamped timestamp,
    /// and day-level bucketing.
    #[allow(clippy::too_many_arguments)]
    pub fn record_sighting(
        &mut self,
        kind: ObservableKind,
        observable_value: &str,
        org_id: &str,
        observed_at_ms: i64,
        now_ms: i64,
        tenure_days: u32,
        enrolled_devices: u32,
    ) -> Result<(), IntelError> {
        if now_ms < 0 {
            return Err(IntelError::SightingRejected(
                "negative server timestamp".into(),
            ));
        }
        let clean_org = org_id.trim().to_ascii_lowercase();
        if clean_org.is_empty() || clean_org.len() > 128 || clean_org.chars().any(char::is_control)
        {
            return Err(IntelError::SightingRejected(
                "invalid or empty org_id".into(),
            ));
        }
        if tenure_days < MIN_ORG_TENURE_DAYS || enrolled_devices < MIN_ORG_ENROLLED_DEVICES {
            return Err(IntelError::SightingRejected(
                "organisation does not meet minimum tenure/device eligibility".into(),
            ));
        }
        let canonical_value = validate_public_artefact(kind, observable_value)?;
        if !self.public_filter.is_public_key(&canonical_value)? {
            return Err(IntelError::SightingRejected(
                "observable absent from public-artefact filter".into(),
            ));
        }

        let mac = domain_hmac_sha256(&*self.salt_key, SIGHTING_HMAC_DOMAIN, clean_org.as_bytes());
        let org_digest = encode_lower_hex(&mac);
        let min_allowed_ms = now_ms
            .saturating_sub(SIGHTINGS_RETENTION_DAYS.saturating_mul(MS_PER_DAY))
            .max(0);
        let clamped_ms = observed_at_ms.clamp(min_allowed_ms, now_ms);
        let observed_day = clamped_ms.div_euclid(MS_PER_DAY);

        let already_voted = self
            .buckets
            .get(&canonical_value)
            .is_some_and(|b| b.salted_org_digests.contains(&org_digest));
        let bucket_saturated = self
            .buckets
            .get(&canonical_value)
            .is_some_and(|b| b.salted_org_digests.len() >= MAX_BUCKET_SATURATED_ORGS);

        if !already_voted {
            let existing_org_count = self.org_bucket_counts.get(org_digest.as_str()).copied();
            if existing_org_count.unwrap_or(0) >= MAX_BUCKETS_PER_ORG {
                return Err(IntelError::SightingRejected(
                    "organisation exceeded per-epoch sighting flood cap".into(),
                ));
            }
            if !bucket_saturated {
                if existing_org_count.is_none() && self.org_bucket_counts.len() >= MAX_TRACKED_ORGS
                {
                    return Err(IntelError::SightingRejected(
                        "sightings aggregator org capacity reached".into(),
                    ));
                }
                if !self.buckets.contains_key(&canonical_value)
                    && self.buckets.len() >= MAX_AGGREGATOR_BUCKETS
                {
                    return Err(IntelError::SightingRejected(
                        "sightings aggregator capacity reached".into(),
                    ));
                }
                self.org_bucket_counts.insert(
                    org_digest.clone(),
                    existing_org_count.unwrap_or(0).saturating_add(1),
                );
            }
        }

        let bucket = self
            .buckets
            .entry(canonical_value.clone())
            .or_insert_with(|| ObservableBucket {
                kind,
                canonical_value,
                salted_org_digests: BTreeSet::new(),
                first_seen_day: observed_day,
                last_seen_day: observed_day,
            });
        if !already_voted && bucket.salted_org_digests.len() < MAX_BUCKET_SATURATED_ORGS {
            bucket.salted_org_digests.insert(org_digest);
        }
        if observed_day < bucket.first_seen_day {
            bucket.first_seen_day = observed_day;
        }
        if observed_day > bucket.last_seen_day {
            bucket.last_seen_day = observed_day;
        }
        Ok(())
    }

    /// Publishes an individual observable only when its distinct contributor cohort reaches `k >= 5`.
    pub fn try_publish_observable(
        &self,
        kind: ObservableKind,
        observable_value: &str,
    ) -> Result<PublishedSighting, IntelError> {
        let key = normalize_observable(kind, observable_value);
        let k_u32 = u32::try_from(MIN_SIGHTINGS_COHORT_K).unwrap_or(5);
        let bucket = self
            .buckets
            .get(&key)
            .ok_or(IntelError::CohortTooSmall(k_u32))?;
        let count = bucket.salted_org_digests.len();
        let Some(prevalence_bucket) = bucket_for_count(count) else {
            return Err(IntelError::CohortTooSmall(k_u32));
        };
        Ok(PublishedSighting {
            kind: bucket.kind,
            canonical_value: bucket.canonical_value.clone(),
            prevalence_bucket,
            first_seen_day: bucket.first_seen_day,
            last_seen_day: bucket.last_seen_day,
        })
    }

    /// Exports only observables meeting the `k=5` anonymity floor with day-granularity and coarse buckets.
    #[must_use]
    pub fn export_k_anonymous(&self) -> Vec<PublishedSighting> {
        self.buckets
            .values()
            .filter_map(|b| {
                let prevalence_bucket = bucket_for_count(b.salted_org_digests.len())?;
                Some(PublishedSighting {
                    kind: b.kind,
                    canonical_value: b.canonical_value.clone(),
                    prevalence_bucket,
                    first_seen_day: b.first_seen_day,
                    last_seen_day: b.last_seen_day,
                })
            })
            .collect()
    }

    /// Purges sub-`k` buckets older than 30 days so stale low-count cohorts do not persist,
    /// decrementing `org_bucket_counts` for every removed contributor digest.
    pub fn purge_expired_below_k(&mut self, now_ms: i64) -> u64 {
        let now_day = now_ms.div_euclid(MS_PER_DAY);
        let cutoff_day = now_day.saturating_sub(SIGHTINGS_RETENTION_DAYS);
        let expired_keys: Vec<String> = self
            .buckets
            .iter()
            .filter(|(_, b)| {
                b.salted_org_digests.len() < MIN_SIGHTINGS_COHORT_K && b.last_seen_day < cutoff_day
            })
            .map(|(k, _)| k.clone())
            .collect();
        let mut purged: u64 = 0;
        for key in expired_keys {
            if let Some(bucket) = self.buckets.remove(&key) {
                purged = purged.saturating_add(1);
                for org_digest in bucket.salted_org_digests {
                    if let Some(count) = self.org_bucket_counts.get_mut(&org_digest) {
                        *count = count.saturating_sub(1);
                        if *count == 0 {
                            self.org_bucket_counts.remove(&org_digest);
                        }
                    }
                }
            }
        }
        purged
    }

    #[must_use]
    pub fn bucket_count(&self) -> u64 {
        u64::try_from(self.buckets.len()).unwrap_or(u64::MAX)
    }

    #[must_use]
    pub fn tracked_org_count(&self) -> usize {
        self.org_bucket_counts.len()
    }
}

fn bucket_for_count(count: usize) -> Option<PrevalenceBucket> {
    if count < MIN_SIGHTINGS_COHORT_K {
        None
    } else if count <= 20 {
        Some(PrevalenceBucket::From5To20)
    } else if count <= 100 {
        Some(PrevalenceBucket::From21To100)
    } else {
        Some(PrevalenceBucket::Over100)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn suppresses_sightings_until_five_distinct_organisations_contribute() {
        let filter = PublicArtefactFilter::from_observables(&[
            (ObservableKind::Domain, "rare.evil.test"),
            (ObservableKind::PackagePurl, "pkg:npm/public-bad-pkg"),
        ])
        .expect("public filter");
        let mut agg = SightingsAggregator::new([7_u8; 32], filter);

        let day_ms = 20_000 * MS_PER_DAY + 43_200_000;
        for idx in 0..4 {
            agg.record_sighting(
                ObservableKind::Domain,
                "rare.evil.test",
                &format!("org-{idx}"),
                day_ms.saturating_add(idx),
                day_ms.saturating_add(idx),
                45,
                20,
            )
            .expect("valid sighting");
        }
        assert!(matches!(
            agg.try_publish_observable(ObservableKind::Domain, "rare.evil.test"),
            Err(IntelError::CohortTooSmall(5))
        ));
        assert!(agg.export_k_anonymous().is_empty());

        agg.record_sighting(
            ObservableKind::Domain,
            "rare.evil.test",
            "org-0",
            day_ms.saturating_add(2_000),
            day_ms.saturating_add(2_000),
            45,
            20,
        )
        .expect("dup org allowed");
        assert!(agg.export_k_anonymous().is_empty());

        agg.record_sighting(
            ObservableKind::Domain,
            "rare.evil.test",
            "org-4",
            day_ms.saturating_add(3_000),
            day_ms.saturating_add(3_000),
            45,
            20,
        )
        .expect("5th org");
        let pub_item = agg
            .try_publish_observable(ObservableKind::Domain, "rare.evil.test")
            .expect("k=5 met");
        assert_eq!(pub_item.prevalence_bucket, PrevalenceBucket::From5To20);
        assert_eq!(pub_item.first_seen_day, 20_000);
        assert_eq!(pub_item.last_seen_day, 20_000);
        assert_eq!(agg.export_k_anonymous().len(), 1);
    }

    #[test]
    fn negative_cases_reject_private_artefacts_ineligible_orgs_and_purge_stale_buckets() {
        let filter = PublicArtefactFilter::from_observables(&[
            (ObservableKind::Domain, "public.example"),
            (ObservableKind::Domain, "stale.example"),
        ])
        .expect("filter");
        assert!(
            PublicArtefactFilter::from_observables(&[(
                ObservableKind::Url,
                "https://user:secret@internal.corp/path"
            )])
            .is_err()
        );
        assert!(
            PublicArtefactFilter::from_observables(&[(ObservableKind::IpAddress, "192.168.1.10")])
                .is_err()
        );

        let mut agg = SightingsAggregator::new([9_u8; 32], filter);

        assert!(matches!(
            agg.record_sighting(
                ObservableKind::Domain,
                "private-unlisted.example",
                "org-1",
                MS_PER_DAY,
                MS_PER_DAY,
                40,
                15
            ),
            Err(IntelError::SightingRejected(_))
        ));
        assert!(matches!(
            agg.record_sighting(
                ObservableKind::Domain,
                "public.example",
                "   ",
                MS_PER_DAY,
                MS_PER_DAY,
                40,
                15
            ),
            Err(IntelError::SightingRejected(_))
        ));
        assert!(matches!(
            agg.record_sighting(
                ObservableKind::Domain,
                "public.example",
                "org-new",
                MS_PER_DAY,
                MS_PER_DAY,
                5,
                15
            ),
            Err(IntelError::SightingRejected(_))
        ));

        agg.record_sighting(
            ObservableKind::Domain,
            "stale.example",
            "org-1",
            10 * MS_PER_DAY,
            10 * MS_PER_DAY,
            60,
            20,
        )
        .expect("stale recorded");
        assert_eq!(agg.bucket_count(), 1);
        assert_eq!(agg.tracked_org_count(), 1);
        let purged = agg.purge_expired_below_k(45 * MS_PER_DAY);
        assert_eq!(purged, 1);
        assert_eq!(agg.bucket_count(), 0);
        assert_eq!(agg.tracked_org_count(), 0);
    }

    #[test]
    fn round2_sightings_clamping_case_dedup_and_org_count_cleanup() {
        let filter = PublicArtefactFilter::from_observables(&[
            (ObservableKind::Domain, "backdated.example"),
            (ObservableKind::Domain, "future.example"),
            (ObservableKind::Domain, "case.example"),
        ])
        .expect("filter");
        let mut agg = SightingsAggregator::new([7_u8; 32], filter);

        let now_ms = 50 * MS_PER_DAY;
        // Backdated timestamp beyond 30-day window clamps to now_ms - 30d (day 20).
        agg.record_sighting(
            ObservableKind::Domain,
            "backdated.example",
            "Org-One",
            5 * MS_PER_DAY,
            now_ms,
            60,
            20,
        )
        .expect("backdated clamped");
        // Future i64::MAX timestamp clamps down to now_ms (day 50).
        agg.record_sighting(
            ObservableKind::Domain,
            "future.example",
            "Org-Two",
            i64::MAX,
            now_ms,
            60,
            20,
        )
        .expect("future clamped");
        // Mixed-case org_id deduplicates to one distinct org.
        agg.record_sighting(
            ObservableKind::Domain,
            "case.example",
            "Org-Alpha",
            now_ms,
            now_ms,
            60,
            20,
        )
        .expect("alpha 1");
        agg.record_sighting(
            ObservableKind::Domain,
            "case.example",
            "org-alpha",
            now_ms + 1_000,
            now_ms + 1_000,
            60,
            20,
        )
        .expect("alpha 2");
        assert_eq!(
            agg.buckets
                .get("Domain:case.example")
                .map(|b| b.salted_org_digests.len()),
            Some(1)
        );
        assert_eq!(agg.tracked_org_count(), 3);

        // At cutoff_ms = 49d (cutoff_day = 19), day-20 clamped bucket is NOT yet expired.
        assert_eq!(agg.purge_expired_below_k(49 * MS_PER_DAY), 0);
        // At cutoff_ms = 55d (cutoff_day = 25), day-20 bucket expires, day-50 does not.
        assert_eq!(agg.purge_expired_below_k(55 * MS_PER_DAY), 1);
        assert_eq!(agg.tracked_org_count(), 2);
        // At cutoff_ms = 90d (cutoff_day = 60), day-50 i64::MAX-clamped bucket expires cleanly.
        assert_eq!(agg.purge_expired_below_k(90 * MS_PER_DAY), 2);
        assert_eq!(agg.bucket_count(), 0);
        assert_eq!(agg.tracked_org_count(), 0);
    }

    #[test]
    fn round4_canonical_public_filter_ipv6_userinfo_and_sightings_saturation_bounds() {
        // 1. Domain public-artefact filter rejects path/userinfo/invalid punycode/trailing-dot-dot.
        for bad_dom in [
            "user:secret@internal.corp/api?tok=1",
            "a.xn--invalid\u{FF0E}local",
            "evil.example..",
            "-bad.example",
            &format!("{}.example", "a".repeat(64)),
        ] {
            assert!(
                validate_public_artefact(ObservableKind::Domain, bad_dom).is_err(),
                "expected invalid domain `{bad_dom}` to be rejected"
            );
        }

        // 2. Newly blocked IPv6 special-use & private 6to4 ranges.
        for bad_ip in [
            "3fff::1",
            "2001:2::1",
            "2001:10::1",
            "2001:20::1",
            "::ffff:0:10.0.0.1",
            "::ffff:0:8.8.8.8",
            "2002:0a00:0001::1",
        ] {
            assert!(
                validate_public_artefact(ObservableKind::IpAddress, bad_ip).is_err(),
                "expected non-routable IPv6 `{bad_ip}` to fail public filter"
            );
        }

        // 3. PURL requires pkg:<eco>/<name>, and Url canonicalization strips userinfo.
        for bad_purl in ["pkg:npm", "pkg:npm/", "pkg:/foo", "pkg:npm/@1.0.0"] {
            assert!(validate_public_artefact(ObservableKind::PackagePurl, bad_purl).is_err());
        }
        assert_eq!(
            normalize_observable(ObservableKind::Url, "https://user:secret@evil.test/p"),
            "Url:https://evil.test/p"
        );

        // 4. SightingsAggregator: min_allowed_ms floored at 0; salted_org_digests capped at 101 (Over100);
        // org_bucket_counts bounded by MAX_TRACKED_ORGS.
        let filter =
            PublicArtefactFilter::from_observables(&[(ObservableKind::Domain, "popular.example")])
                .unwrap();
        let mut agg = SightingsAggregator::new([3_u8; 32], filter);

        let early_now = 5 * MS_PER_DAY;
        agg.record_sighting(
            ObservableKind::Domain,
            "popular.example",
            "org-neg",
            -1_000_000_000,
            early_now,
            60,
            20,
        )
        .unwrap();
        assert_eq!(
            agg.buckets
                .get("Domain:popular.example")
                .map(|b| b.first_seen_day),
            Some(0)
        );

        for idx in 0..120 {
            agg.record_sighting(
                ObservableKind::Domain,
                "popular.example",
                &format!("org-sat-{idx}"),
                early_now,
                early_now,
                60,
                20,
            )
            .unwrap();
        }
        let sat_bucket = &agg.buckets["Domain:popular.example"];
        assert_eq!(
            sat_bucket.salted_org_digests.len(),
            MAX_BUCKET_SATURATED_ORGS
        );
        assert_eq!(
            agg.try_publish_observable(ObservableKind::Domain, "popular.example")
                .unwrap()
                .prevalence_bucket,
            PrevalenceBucket::Over100
        );

        let filter2 =
            PublicArtefactFilter::from_observables(&[(ObservableKind::Domain, "cap.example")])
                .unwrap();
        let mut capped_agg = SightingsAggregator::new([4_u8; 32], filter2);
        for idx in 0..MAX_TRACKED_ORGS {
            capped_agg
                .org_bucket_counts
                .insert(format!("digest-{idx}"), 1);
        }
        assert!(matches!(
            capped_agg.record_sighting(
                ObservableKind::Domain,
                "cap.example",
                "org-overflow",
                early_now,
                early_now,
                60,
                20
            ),
            Err(IntelError::SightingRejected(_))
        ));
    }

    #[test]
    fn round6_sightings_debug_redacts_salt_and_leaks_no_salt_bytes() {
        let filter =
            PublicArtefactFilter::from_observables(&[(ObservableKind::Domain, "dbg.example")])
                .unwrap();

        let ascii_salt = *b"SALT_SECRET_BYTES_DO_NOT_LEAK_32";
        let agg_ascii = SightingsAggregator::new(ascii_salt, filter.clone());
        let dbg_ascii = format!("{agg_ascii:?}");
        assert!(dbg_ascii.contains("[REDACTED]"));
        assert!(!dbg_ascii.contains("SALT_SECRET"));
        assert!(!dbg_ascii.contains("DO_NOT_LEAK"));

        let num_agg = SightingsAggregator::new([239_u8; 32], filter);
        let dbg_num = format!("{num_agg:?}");
        assert!(dbg_num.contains("[REDACTED]"));
        assert!(!dbg_num.contains("239"));
        assert!(!dbg_num.to_ascii_lowercase().contains("ef"));
    }
}
