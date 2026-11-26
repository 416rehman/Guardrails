// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors
#![deny(clippy::arithmetic_side_effects)]

use std::collections::BTreeMap;

use jiff::Timestamp;
use serde::{Deserialize, Serialize};

use grdr_model::{
    ActionAttempt, ActionClass, ControlPoint, Finding, FindingClass, FindingLifecycle,
    FindingSeverity,
};

use crate::WindowsSensorError;

const MAX_EVENT_XML_BYTES: usize = 131_072;
const MAX_DATA_FIELDS: usize = 64;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ParsedWindowsEventXml {
    pub event_id: u16,
    pub system_pid: u32,
    pub computer: String,
    pub timestamp: Timestamp,
    pub data: BTreeMap<String, String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SysmonNormalizationOutcome {
    Attempt(ActionAttempt),
    TamperFinding(Finding),
    IgnoredEventId(u16),
    DroppedOutOfInterest,
}

pub fn parse_sysmon_event_xml(
    xml: &str,
    expected_sysmon_pid: Option<u32>,
    in_agent_lineage: bool,
    session_id: &str,
    agent_name: &str,
    device_id: &str,
    device_name: &str,
) -> Result<SysmonNormalizationOutcome, WindowsSensorError> {
    let parsed = parse_windows_event_xml(xml)?;
    if let Some(expected_pid) = expected_sysmon_pid
        && parsed.system_pid != expected_pid
    {
        return Ok(SysmonNormalizationOutcome::TamperFinding(Finding {
            id: format!(
                "fnd-sysmon-spoof-{}-{}",
                parsed.system_pid,
                parsed.timestamp.as_nanosecond()
            ),
            title: "Sysmon Execution ProcessID mismatch".into(),
            class: FindingClass::Tamper,
            finding_class_other: None,
            severity: FindingSeverity::High,
            lifecycle: FindingLifecycle::Open,
            device_id: device_id.into(),
            device_name: device_name.into(),
            session_id: session_id.into(),
            agent_name: agent_name.into(),
            rule_id: Some("windows.sysmon.pid_validation".into()),
            summary: format!(
                "Sysmon XML event {} emitted by Execution ProcessID {} (expected {expected_pid})",
                parsed.event_id, parsed.system_pid
            ),
            target: parsed
                .data
                .get("Image")
                .cloned()
                .unwrap_or_else(|| parsed.computer.clone()),
            detected_at: parsed.timestamp,
        }));
    }

    let Some((action_class, lineage_only, target, summary)) = map_sysmon_fields(&parsed) else {
        return Ok(SysmonNormalizationOutcome::IgnoredEventId(parsed.event_id));
    };

    if lineage_only && !in_agent_lineage {
        return Ok(SysmonNormalizationOutcome::DroppedOutOfInterest);
    }

    Ok(SysmonNormalizationOutcome::Attempt(ActionAttempt {
        id: format!(
            "att-sysmon-{}-{}-{}",
            parsed.event_id,
            parsed.system_pid,
            parsed.timestamp.as_nanosecond()
        ),
        session_id: session_id.into(),
        device_id: device_id.into(),
        device_name: device_name.into(),
        agent_name: agent_name.into(),
        action_class,
        control_point: ControlPoint::Sensor,
        target,
        summary,
        timestamp: parsed.timestamp,
        ..Default::default()
    }))
}

pub(crate) fn parse_windows_event_xml(
    xml: &str,
) -> Result<ParsedWindowsEventXml, WindowsSensorError> {
    if xml.len() > MAX_EVENT_XML_BYTES {
        return Err(WindowsSensorError::Sysmon(format!(
            "Windows Event XML exceeds {} byte cap",
            MAX_EVENT_XML_BYTES
        )));
    }
    if xml.contains('\0') {
        return Err(WindowsSensorError::Sysmon(
            "Windows Event XML contains interior NUL byte".to_string(),
        ));
    }
    let upper = xml.to_ascii_uppercase();
    if upper.contains("<!DOCTYPE") || upper.contains("<!ENTITY") {
        return Err(WindowsSensorError::Sysmon(
            "Windows Event XML rejected due to DTD/ENTITY declaration".to_string(),
        ));
    }

    let without_comments = strip_xml_comments_and_cdata(xml)?;
    let cleaned = strip_tag_block(&without_comments, "RenderingInfo");
    let system_body = extract_tag_block_inner(&cleaned, "System").ok_or_else(|| {
        WindowsSensorError::Sysmon("missing <System> element in Windows Event XML".to_string())
    })?;
    let event_id_raw = extract_tag_text(system_body, "EventID").ok_or_else(|| {
        WindowsSensorError::Sysmon("missing <EventID> in Windows Event <System>".to_string())
    })?;
    let event_id = event_id_raw
        .trim()
        .parse::<u16>()
        .map_err(|_| WindowsSensorError::Sysmon(format!("invalid <EventID> `{event_id_raw}`")))?;

    let system_pid = extract_tag_attr(system_body, "Execution", "ProcessID")
        .and_then(|v| v.parse::<u32>().ok())
        .unwrap_or(0);
    let computer = extract_tag_text(system_body, "Computer")
        .map(|s| decode_xml_entities(s.trim()))
        .unwrap_or_default();
    let timestamp = extract_tag_attr(system_body, "TimeCreated", "SystemTime")
        .and_then(|raw| raw.parse::<Timestamp>().ok())
        .unwrap_or(Timestamp::UNIX_EPOCH);

    let event_data_body = extract_tag_block_inner(&cleaned, "EventData").unwrap_or("");
    let data = parse_event_data_fields(event_data_body);

    Ok(ParsedWindowsEventXml {
        event_id,
        system_pid,
        computer,
        timestamp,
        data,
    })
}

fn map_sysmon_fields(
    parsed: &ParsedWindowsEventXml,
) -> Option<(ActionClass, bool, String, String)> {
    let field = |name: &str| parsed.data.get(name).map(String::as_str).unwrap_or("");
    match parsed.event_id {
        1 => {
            let cmd = field("CommandLine");
            let image = field("Image");
            let target = if cmd.is_empty() { image } else { cmd };
            Some((
                ActionClass::Exec,
                false,
                target.to_string(),
                format!(
                    "Sysmon 1 ProcessCreate pid={} ppid={} image={}",
                    field("ProcessId"),
                    field("ParentProcessId"),
                    image
                ),
            ))
        }
        3 => {
            let host = field("DestinationHostname");
            let dst = if host.is_empty() {
                format!("{}:{}", field("DestinationIp"), field("DestinationPort"))
            } else {
                format!("{host}:{}", field("DestinationPort"))
            };
            Some((
                ActionClass::NetConnect,
                true,
                dst,
                format!("Sysmon 3 NetworkConnect proto={}", field("Protocol")),
            ))
        }
        7 => Some((
            ActionClass::Exec,
            true,
            field("ImageLoaded").to_string(),
            format!("Sysmon 7 ImageLoad image={}", field("Image")),
        )),
        11 => Some((
            ActionClass::FileWrite,
            true,
            field("TargetFilename").to_string(),
            format!("Sysmon 11 FileCreate image={}", field("Image")),
        )),
        12..=14 => Some((
            ActionClass::ConfigChange,
            false,
            field("TargetObject").to_string(),
            format!(
                "Sysmon {} RegistryEvent type={}",
                parsed.event_id,
                field("EventType")
            ),
        )),
        22 => Some((
            ActionClass::NetConnect,
            true,
            field("QueryName").to_string(),
            format!(
                "Sysmon 22 DNSEvent status={} results={}",
                field("QueryStatus"),
                field("QueryResults")
            ),
        )),
        _ => None,
    }
}

fn strip_xml_comments_and_cdata(xml: &str) -> Result<String, WindowsSensorError> {
    if xml.contains("<![CDATA[") {
        return Err(WindowsSensorError::Sysmon(
            "Windows Event XML rejected due to CDATA section".to_string(),
        ));
    }
    let mut out = xml.to_string();
    while let Some(start) = out.find("<!--") {
        let Some(end_rel) = out.get(start..).and_then(|s| s.find("-->")) else {
            return Err(WindowsSensorError::Sysmon(
                "unterminated XML comment in Windows Event XML".to_string(),
            ));
        };
        let end = start.saturating_add(end_rel).saturating_add(3);
        let mut rebuilt = String::with_capacity(out.len());
        rebuilt.push_str(out.get(..start).unwrap_or_default());
        rebuilt.push_str(out.get(end..).unwrap_or_default());
        out = rebuilt;
    }
    Ok(out)
}

fn strip_tag_block(xml: &str, tag: &str) -> String {
    let open = format!("<{tag}");
    let close = format!("</{tag}>");
    let mut out = xml.to_string();
    while let Some(start) = out.find(&open) {
        let Some(end_rel) = out.get(start..).and_then(|s| s.find(&close)) else {
            break;
        };
        let end = start.saturating_add(end_rel).saturating_add(close.len());
        let mut rebuilt = String::with_capacity(out.len());
        rebuilt.push_str(out.get(..start).unwrap_or_default());
        rebuilt.push_str(out.get(end..).unwrap_or_default());
        out = rebuilt;
    }
    out
}

fn extract_tag_block_inner<'a>(xml: &'a str, tag: &str) -> Option<&'a str> {
    let open = format!("<{tag}");
    let close = format!("</{tag}>");
    let start = xml.find(&open)?;
    let rest = xml.get(start..)?;
    let gt = rest.find('>')?;
    let body_start = start.saturating_add(gt).saturating_add(1);
    let close_rel = xml.get(body_start..)?.find(&close)?;
    xml.get(body_start..body_start.saturating_add(close_rel))
}

fn extract_tag_text<'a>(xml: &'a str, tag: &str) -> Option<&'a str> {
    extract_tag_block_inner(xml, tag)
}

fn extract_tag_attr(xml: &str, tag: &str, attr: &str) -> Option<String> {
    let open = format!("<{tag}");
    let start = xml.find(&open)?;
    let rest = xml.get(start..)?;
    let gt = rest.find('>')?;
    let header = rest.get(..gt)?;
    extract_attr_value(header, attr).map(decode_xml_entities)
}

fn extract_attr_value<'a>(header: &'a str, attr: &str) -> Option<&'a str> {
    for quote in ['"', '\''] {
        let needle = format!("{attr}={quote}");
        if let Some(pos) = header.find(&needle) {
            let val_start = pos.saturating_add(needle.len());
            if let Some(tail) = header.get(val_start..)
                && let Some(end_rel) = tail.find(quote)
            {
                return tail.get(..end_rel);
            }
        }
    }
    None
}

fn parse_event_data_fields(body: &str) -> BTreeMap<String, String> {
    let mut map = BTreeMap::new();
    let mut cursor = body;
    while map.len() < MAX_DATA_FIELDS {
        let Some(pos) = cursor.find("<Data") else {
            break;
        };
        let Some(after_open) = cursor.get(pos..) else {
            break;
        };
        let Some(gt) = after_open.find('>') else {
            break;
        };
        let tag_header = after_open.get(..gt).unwrap_or_default();
        let name = extract_attr_value(tag_header, "Name").unwrap_or("");
        let is_self_closing = tag_header.ends_with('/');
        let after_gt = gt.saturating_add(1);

        if is_self_closing {
            if !name.is_empty() {
                map.insert(decode_xml_entities(name), String::new());
            }
            cursor = after_open.get(after_gt..).unwrap_or_default();
            continue;
        }

        let Some(tail) = after_open.get(after_gt..) else {
            break;
        };
        let Some(close_rel) = tail.find("</Data>") else {
            break;
        };
        let val = tail.get(..close_rel).unwrap_or_default();
        if !name.is_empty() {
            map.insert(decode_xml_entities(name), decode_xml_entities(val));
        }
        let next_pos = after_gt.saturating_add(close_rel).saturating_add(7);
        cursor = after_open.get(next_pos..).unwrap_or_default();
    }
    map
}

pub(crate) fn decode_xml_entities(raw: &str) -> String {
    let mut out = String::with_capacity(raw.len());
    let mut rest = raw;
    while let Some(amp) = rest.find('&') {
        out.push_str(rest.get(..amp).unwrap_or_default());
        let after = rest.get(amp..).unwrap_or_default();
        let Some(semi) = after.find(';') else {
            out.push_str(after);
            return out;
        };
        let ent = after.get(1..semi).unwrap_or_default();
        let decoded = match ent {
            "lt" => Some('<'),
            "gt" => Some('>'),
            "amp" => Some('&'),
            "quot" => Some('"'),
            "apos" => Some('\''),
            _ if ent.starts_with("#x") || ent.starts_with("#X") => {
                u32::from_str_radix(ent.get(2..).unwrap_or_default(), 16)
                    .ok()
                    .and_then(char::from_u32)
            }
            _ if ent.starts_with('#') => ent
                .get(1..)
                .unwrap_or_default()
                .parse::<u32>()
                .ok()
                .and_then(char::from_u32),
            _ => None,
        };
        if let Some(ch) = decoded {
            out.push(ch);
        } else {
            out.push('&');
            out.push_str(ent);
            out.push(';');
        }
        rest = after.get(semi.saturating_add(1)..).unwrap_or_default();
    }
    out.push_str(rest);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_sysmon_events_strips_rendering_info_and_detects_tamper() {
        let xml = r#"<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
  <System>
    <EventID>1</EventID>
    <TimeCreated SystemTime="2026-11-26T10:00:00Z"/>
    <Execution ProcessID="4000" ThreadID="12"/>
    <Computer>WIN-AGENT-01</Computer>
  </System>
  <EventData>
    <Data Name="ProcessId">5100</Data>
    <Data Name="ParentProcessId">4200</Data>
    <Data Name="Image">C:\Windows\System32\cmd.exe</Data>
    <Data Name="CommandLine">cmd.exe /c dir &amp; echo ok</Data>
  </EventData>
  <RenderingInfo Culture="en-US">
    <Data Name="CommandLine">SPOOFED_IN_RENDERING_INFO</Data>
  </RenderingInfo>
</Event>"#;

        let ok =
            parse_sysmon_event_xml(xml, Some(4000), true, "sess-1", "claude-code", "d1", "win")
                .expect("valid Sysmon XML");
        let SysmonNormalizationOutcome::Attempt(att) = ok else {
            panic!("expected Attempt");
        };
        assert_eq!(att.action_class, ActionClass::Exec);
        assert_eq!(att.target, "cmd.exe /c dir & echo ok");

        let tamper =
            parse_sysmon_event_xml(xml, Some(9999), true, "sess-1", "claude-code", "d1", "win")
                .expect("pid mismatch yields tamper");
        assert!(matches!(
            tamper,
            SysmonNormalizationOutcome::TamperFinding(f) if f.class == FindingClass::Tamper
        ));
    }

    #[test]
    fn rejects_xxe_doctype_in_sysmon_xml() {
        let bad = "<!DOCTYPE foo [<!ENTITY xxe SYSTEM \"file:///etc/passwd\">]><Event/>";
        assert!(parse_sysmon_event_xml(bad, None, true, "s", "a", "d", "w").is_err());
    }

    #[test]
    fn maps_sysmon_3_7_11_13_22_correctly() {
        let dns_xml = r#"<Event><System><EventID>22</EventID><Execution ProcessID="4000"/></System><EventData><Data Name="QueryName">api.github.com</Data><Data Name="QueryStatus">0</Data><Data Name="QueryResults">::1</Data></EventData></Event>"#;
        let out =
            parse_sysmon_event_xml(dns_xml, Some(4000), true, "s", "a", "d", "w").expect("dns");
        assert!(matches!(
            out,
            SysmonNormalizationOutcome::Attempt(att)
                if att.action_class == ActionClass::NetConnect && att.target == "api.github.com"
        ));

        let reg_xml = r#"<Event><System><EventID>13</EventID><Execution ProcessID="4000"/></System><EventData><Data Name="EventType">SetValue</Data><Data Name="TargetObject">HKCU\Software\Test</Data></EventData></Event>"#;
        let out2 =
            parse_sysmon_event_xml(reg_xml, Some(4000), false, "s", "a", "d", "w").expect("reg");
        assert!(matches!(
            out2,
            SysmonNormalizationOutcome::Attempt(att) if att.action_class == ActionClass::ConfigChange
        ));
    }
}
