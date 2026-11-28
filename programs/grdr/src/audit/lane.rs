// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors

use grdr_model::{AuditLane, CommitmentClass, FiveWayCommitments};
use serde::Deserialize;
use serde_json::{Map, Value};

use super::commitments::withheld_classes_for_capture_level;
use super::lane_chain::verify_lane_audit_chain_with_expected;
use super::types::{
    AuditVerifyError, AuditVerifySummary, ExpectedAnchor, LaneAuditRecord, LaneChainAnchor,
    LaneEntryKind, MerkleConsistencyInput, MerkleInclusionInput,
};

use super::{extract_hash_strings, gap_err, lane_err, malformed, parse_line_obj_strict};

#[derive(Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct AnchorJson {
    device_id: String,
    epoch: u64,
    prev_epoch_final_hash: Option<String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct GapJson {
    start_seq: u64,
    end_seq: u64,
    dropped_count: u64,
    reason: String,
}

#[derive(Default, Deserialize)]
#[serde(deny_unknown_fields)]
struct PayloadsJson {
    identifier: Option<String>,
    structural: Option<String>,
    derived: Option<String>,
    #[serde(alias = "content.argument", alias = "argument")]
    content_argument: Option<String>,
    #[serde(alias = "content.body", alias = "body")]
    content_body: Option<String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct MerkleJson {
    leaf: String,
    leaf_index: u64,
    tree_size: u64,
    audit_path: Vec<String>,
    expected_root: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ConsistencyJson {
    first_size: u64,
    second_size: u64,
    first_root: String,
    second_root: String,
    proof: Vec<String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct IntegrityLaneJson {
    commitments: Option<FiveWayCommitments>,
    commitment_root_digest: Option<String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RedactionJson {
    #[serde(default)]
    withheld_classes: Vec<String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct LaneLineJson {
    lane: String,
    epoch: u64,
    seq: u64,
    anchor: Option<AnchorJson>,
    kind: Option<String>,
    gap: Option<GapJson>,
    start_seq: Option<u64>,
    end_seq: Option<u64>,
    dropped_count: Option<u64>,
    reason: Option<String>,
    commitments: Option<FiveWayCommitments>,
    commitment_root_digest: Option<String>,
    payloads: Option<PayloadsJson>,
    #[serde(alias = "merkle_proof")]
    merkle: Option<MerkleJson>,
    merkle_consistency: Option<ConsistencyJson>,
    integrity: Option<IntegrityLaneJson>,
    capture_level: Option<String>,
    redaction: Option<RedactionJson>,
}

struct OwnedLaneEntry {
    line: usize,
    lane: AuditLane,
    prev_hash: String,
    entry_hash: String,
    data: LaneLineJson,
    withheld: Option<Vec<CommitmentClass>>,
}

pub(crate) fn has_lane_fields(obj: &Map<String, Value>) -> bool {
    obj.contains_key("lane")
        || obj.contains_key("commitments")
        || obj
            .get("integrity")
            .and_then(Value::as_object)
            .is_some_and(|i| {
                i.contains_key("commitments") || i.contains_key("commitment_root_digest")
            })
}

pub(crate) fn has_lane_only_meta(obj: &Map<String, Value>) -> bool {
    obj.contains_key("epoch")
        || obj.contains_key("anchor")
        || obj.contains_key("kind")
        || obj.contains_key("gap")
        || obj.contains_key("start_seq")
        || obj.contains_key("end_seq")
        || obj.contains_key("dropped_count")
        || obj.contains_key("commitment_root_digest")
        || obj.contains_key("payloads")
        || obj.contains_key("merkle")
        || obj.contains_key("merkle_proof")
        || obj.contains_key("merkle_consistency")
        || obj.contains_key("capture_level")
        || obj.contains_key("redaction")
}

pub(crate) fn verify_lane_lines(
    lines: &[(usize, &str)],
    expected: Option<&ExpectedAnchor>,
) -> Result<AuditVerifySummary, AuditVerifyError> {
    let mut owned = Vec::with_capacity(lines.len());
    for &(line, text) in lines {
        let mut obj = parse_line_obj_strict(line, text)?;
        let (prev_hash, entry_hash, remove_key) = extract_hash_strings(line, &obj)?;
        match remove_key {
            None => {
                if let Some(Value::Object(m)) = obj.get_mut("integrity") {
                    m.remove("prev");
                    m.remove("digest");
                }
            }
            Some(hkey) => {
                obj.remove(hkey);
                obj.remove("prev_hash");
                obj.remove("prev");
            }
        }
        let data: LaneLineJson = serde_json::from_value(Value::Object(obj))
            .map_err(|_| malformed(line, "invalid lane record schema"))?;
        let lane = AuditLane::parse(&data.lane)
            .ok_or_else(|| lane_err(line, "unrecognized audit lane"))?;
        let withheld = resolve_withheld_classes(line, &data)?;
        owned.push(OwnedLaneEntry {
            line,
            lane,
            prev_hash,
            entry_hash,
            data,
            withheld,
        });
    }

    let first_line = owned.first().map_or(1, |x| x.line);
    let first_anchor = owned
        .first()
        .and_then(|x| x.data.anchor.as_ref())
        .ok_or_else(|| {
            lane_err(
                first_line,
                "lane-chain audit log requires anchor on first entry",
            )
        })?;
    for entry in owned.iter().skip(1) {
        if let Some(ref later) = entry.data.anchor
            && later != first_anchor
        {
            return Err(lane_err(
                entry.line,
                "conflicting or unexpected mid-stream anchor",
            ));
        }
    }
    let anchor = LaneChainAnchor {
        device_id: first_anchor.device_id.clone(),
        epoch: first_anchor.epoch,
        prev_epoch_final_hash: first_anchor.prev_epoch_final_hash.clone(),
    };

    let mut records = Vec::with_capacity(owned.len());
    for item in &owned {
        records.push(LaneAuditRecord {
            line: item.line,
            epoch: item.data.epoch,
            lane: item.lane,
            seq: item.data.seq,
            prev_hash: &item.prev_hash,
            entry_hash: &item.entry_hash,
            kind: build_lane_kind(item)?,
        });
    }
    verify_lane_audit_chain_with_expected(&records, &anchor, expected)
}

fn resolve_withheld_classes(
    line: usize,
    data: &LaneLineJson,
) -> Result<Option<Vec<CommitmentClass>>, AuditVerifyError> {
    let level_withheld = if let Some(ref lvl) = data.capture_level {
        let Some(list) = withheld_classes_for_capture_level(lvl) else {
            return Err(malformed(line, "invalid capture_level"));
        };
        Some(list)
    } else {
        None
    };

    let red_withheld = if let Some(ref red) = data.redaction {
        let mut out = Vec::with_capacity(red.withheld_classes.len());
        for raw in &red.withheld_classes {
            let cls = parse_class_name(raw)
                .ok_or_else(|| malformed(line, "invalid redaction class name"))?;
            if !out.contains(&cls) {
                out.push(cls);
            }
        }
        Some(out)
    } else {
        None
    };

    match (level_withheld, red_withheld) {
        (Some(lvl_w), Some(red_w)) => {
            for req in &lvl_w {
                if !red_w.contains(req) {
                    return Err(malformed(
                        line,
                        "redaction omits class withheld by capture_level",
                    ));
                }
            }
            Ok(Some(red_w))
        }
        (Some(lvl_w), None) => Ok(Some(lvl_w)),
        (None, Some(red_w)) => Ok(Some(red_w)),
        (None, None) => Ok(Some(Vec::new())),
    }
}

fn parse_class_name(raw: &str) -> Option<CommitmentClass> {
    match raw {
        "identifier" => Some(CommitmentClass::Identifier),
        "structural" => Some(CommitmentClass::Structural),
        "derived" => Some(CommitmentClass::Derived),
        "content.argument" | "argument" => Some(CommitmentClass::ContentArgument),
        "content.body" | "body" => Some(CommitmentClass::ContentBody),
        _ => None,
    }
}

fn build_lane_kind(item: &OwnedLaneEntry) -> Result<LaneEntryKind<'_>, AuditVerifyError> {
    let line = item.line;
    let d = &item.data;
    match d.kind.as_deref() {
        None | Some("event") => build_event_kind(line, d, item.withheld.as_deref()),
        Some("gap") => build_gap_kind(line, d),
        Some(_) => Err(malformed(line, "unsupported lane record kind")),
    }
}

fn build_gap_kind(line: usize, d: &LaneLineJson) -> Result<LaneEntryKind<'_>, AuditVerifyError> {
    let has_event_fields = d.commitments.is_some()
        || d.commitment_root_digest.is_some()
        || d.payloads.is_some()
        || d.merkle.is_some()
        || d.merkle_consistency.is_some()
        || d.capture_level.is_some()
        || d.redaction.is_some()
        || d.integrity
            .as_ref()
            .is_some_and(|i| i.commitments.is_some() || i.commitment_root_digest.is_some());
    if has_event_fields {
        return Err(gap_err(
            line,
            "gap record cannot include event commitment or merkle fields",
        ));
    }
    let has_flat = d.start_seq.is_some()
        || d.end_seq.is_some()
        || d.dropped_count.is_some()
        || d.reason.is_some();
    if d.gap.is_some() && has_flat {
        return Err(gap_err(line, "conflicting nested gap and flat gap fields"));
    }
    let (s, e, cnt, r) = match d.gap.as_ref() {
        Some(g) => (g.start_seq, g.end_seq, g.dropped_count, g.reason.as_str()),
        None => (
            d.start_seq
                .ok_or_else(|| gap_err(line, "missing start_seq"))?,
            d.end_seq.ok_or_else(|| gap_err(line, "missing end_seq"))?,
            d.dropped_count
                .ok_or_else(|| gap_err(line, "missing dropped_count"))?,
            d.reason.as_deref().unwrap_or(""),
        ),
    };
    Ok(LaneEntryKind::Gap {
        start_seq: s,
        end_seq: e,
        dropped_count: cnt,
        reason: r,
    })
}

fn build_event_kind<'a>(
    line: usize,
    d: &'a LaneLineJson,
    withheld: Option<&'a [CommitmentClass]>,
) -> Result<LaneEntryKind<'a>, AuditVerifyError> {
    if d.gap.is_some()
        || d.start_seq.is_some()
        || d.end_seq.is_some()
        || d.dropped_count.is_some()
        || d.reason.is_some()
    {
        return Err(malformed(line, "event record cannot carry gap fields"));
    }
    let int_comm = d.integrity.as_ref().and_then(|i| i.commitments.as_ref());
    if d.commitments.is_some() && int_comm.is_some() {
        return Err(malformed(
            line,
            "conflicting top-level and integrity.commitments",
        ));
    }
    let int_root = d
        .integrity
        .as_ref()
        .and_then(|i| i.commitment_root_digest.as_deref());
    if d.commitment_root_digest.is_some() && int_root.is_some() {
        return Err(malformed(
            line,
            "conflicting top-level and integrity.commitment_root_digest",
        ));
    }
    let comm = d
        .commitments
        .as_ref()
        .or(int_comm)
        .ok_or_else(|| malformed(line, "missing commitments"))?;
    let root = d
        .commitment_root_digest
        .as_deref()
        .or(int_root)
        .ok_or_else(|| malformed(line, "missing commitment_root_digest"))?;
    let p = d.payloads.as_ref();
    let payloads = [
        p.and_then(|x| x.identifier.as_deref()).map(str::as_bytes),
        p.and_then(|x| x.structural.as_deref()).map(str::as_bytes),
        p.and_then(|x| x.derived.as_deref()).map(str::as_bytes),
        p.and_then(|x| x.content_argument.as_deref())
            .map(str::as_bytes),
        p.and_then(|x| x.content_body.as_deref()).map(str::as_bytes),
    ];
    let merkle = d.merkle.as_ref().map(|m| {
        Box::new(MerkleInclusionInput {
            leaf: m.leaf.as_bytes(),
            leaf_index: m.leaf_index,
            tree_size: m.tree_size,
            audit_path: &m.audit_path,
            expected_root: &m.expected_root,
        })
    });
    let merkle_consistency = d.merkle_consistency.as_ref().map(|c| {
        Box::new(MerkleConsistencyInput {
            first_size: c.first_size,
            second_size: c.second_size,
            first_root: &c.first_root,
            second_root: &c.second_root,
            proof: &c.proof,
        })
    });
    Ok(LaneEntryKind::Event {
        commitments: comm,
        commitment_root_digest: root,
        payloads,
        withheld_classes: withheld,
        merkle,
        merkle_consistency,
    })
}
