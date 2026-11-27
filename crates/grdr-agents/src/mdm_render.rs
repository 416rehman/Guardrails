// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors

//! Enterprise MDM policy template rendering from P14 agent manifests (`docs/design/07`).

use grdr_model::CodedError;
use grdr_schema::brand::load_embedded_brand_display;
use serde::{Deserialize, Serialize};
use serde_json::json;

use crate::catalogue::AgentManifest;
use crate::install_entries::{build_entry_for_manifest, format_hook_command};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MdmTemplateFormat {
    Json,
    Plist,
    Reg,
    Intune,
    Jamf,
}

pub fn render_mdm_snippet(
    manifest: &AgentManifest,
    hook_command: &str,
    format: MdmTemplateFormat,
) -> Result<String, CodedError> {
    if !manifest.hook.supported {
        return Err(mdm_err(format!(
            "agent `{}` does not declare native hook control support",
            manifest.id
        )));
    }
    validate_mdm_scalar("manifest.id", &manifest.id)?;
    validate_mdm_scalar("hook_command", hook_command)?;
    let brand = load_embedded_brand_display().map_err(mdm_err)?;
    let root_key = if manifest.hook.root_key.is_empty() {
        "hooks"
    } else {
        manifest.hook.root_key.as_str()
    };
    validate_mdm_scalar("hook.root_key", root_key)?;
    let primary_event = manifest
        .hook
        .events
        .first()
        .map(String::as_str)
        .unwrap_or("PreToolUse");
    validate_mdm_scalar("hook.event", primary_event)?;

    let cmd = format_hook_command(manifest, hook_command);
    let default_domain = format!("{}.agent", brand.macos_agent_label);
    let default_subkey = format!(r"Software\Policies\{}\Agent", brand.windows_program_dir);

    match format {
        MdmTemplateFormat::Json => {
            let entry = build_entry_for_manifest(manifest, hook_command);
            let payload = match manifest.hook.version_field {
                Some(ver) => json!({
                    "version": ver,
                    root_key: {
                        primary_event: [entry]
                    }
                }),
                None => json!({
                    root_key: {
                        primary_event: [entry]
                    }
                }),
            };
            serde_json::to_string_pretty(&payload).map_err(|e| mdm_err(e.to_string()))
        }
        MdmTemplateFormat::Plist => {
            let domain = manifest
                .hook
                .mdm_ids
                .plist_domain
                .as_deref()
                .unwrap_or(&default_domain);
            validate_plist_domain(domain)?;
            Ok(render_macos_plist(domain, primary_event, &cmd))
        }
        MdmTemplateFormat::Jamf => {
            let domain = manifest
                .hook
                .mdm_ids
                .plist_domain
                .as_deref()
                .unwrap_or(&default_domain);
            validate_plist_domain(domain)?;
            Ok(render_jamf_mobileconfig(domain, primary_event, &cmd))
        }
        MdmTemplateFormat::Reg => {
            let subkey = manifest
                .hook
                .mdm_ids
                .registry_subkey
                .as_deref()
                .unwrap_or(&default_subkey);
            validate_reg_subkey(subkey)?;
            Ok(render_windows_reg(subkey, primary_event, &cmd))
        }
        MdmTemplateFormat::Intune => {
            let subkey = manifest
                .hook
                .mdm_ids
                .registry_subkey
                .as_deref()
                .unwrap_or(&default_subkey);
            validate_reg_subkey(subkey)?;
            let segment = manifest.id.replace('-', "_");
            validate_oma_uri_segment(&segment)?;
            let oma_uri = format!("./Device/Vendor/MSFT/Policy/Config/{segment}/HookCommand");
            let payload = json!({
                "omaUri": oma_uri,
                "registryPath": format!("HKLM\\{subkey}"),
                "event": primary_event,
                "command": cmd
            });
            serde_json::to_string_pretty(&payload).map_err(|e| mdm_err(e.to_string()))
        }
    }
}

fn mdm_err(msg: impl Into<String>) -> CodedError {
    CodedError::new(
        "GRDR-AGENTS-0006",
        msg,
        "Ensure MDM hook snippet fields contain safe non-control characters and valid identifiers.",
    )
}

fn validate_mdm_scalar(label: &str, raw: &str) -> Result<(), CodedError> {
    if raw.trim().is_empty() {
        return Err(mdm_err(format!("{label} cannot be empty")));
    }
    if raw.chars().any(char::is_control) {
        return Err(mdm_err(format!(
            "{label} contains forbidden control character or newline"
        )));
    }
    Ok(())
}

fn validate_plist_domain(domain: &str) -> Result<(), CodedError> {
    validate_mdm_scalar("plist_domain", domain)?;
    let valid_chars = domain
        .bytes()
        .all(|b| matches!(b, b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'.' | b'-'));
    if !valid_chars
        || !domain.contains('.')
        || domain.starts_with('.')
        || domain.ends_with('.')
        || domain.contains("..")
    {
        return Err(mdm_err(format!(
            "plist_domain `{domain}` must be a reverse-DNS identifier matching [A-Za-z0-9.-]+"
        )));
    }
    Ok(())
}

fn validate_reg_subkey(subkey: &str) -> Result<(), CodedError> {
    validate_mdm_scalar("registry_subkey", subkey)?;
    if subkey.contains('[')
        || subkey.contains(']')
        || subkey.contains("..")
        || subkey.contains('/')
        || subkey.starts_with('\\')
        || subkey.ends_with('\\')
        || subkey.to_ascii_uppercase().starts_with("HKEY_")
        || subkey.split('\\').any(str::is_empty)
    {
        return Err(mdm_err(format!(
            "registry_subkey `{subkey}` violates safe subkey syntax"
        )));
    }
    Ok(())
}

fn validate_oma_uri_segment(seg: &str) -> Result<(), CodedError> {
    if seg.is_empty()
        || !seg
            .bytes()
            .all(|b| matches!(b, b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'_'))
    {
        return Err(mdm_err(format!(
            "Intune OMA-URI segment `{seg}` must match [A-Za-z0-9_]+"
        )));
    }
    Ok(())
}

fn render_macos_plist(domain: &str, event: &str, command: &str) -> String {
    let dom = escape_xml(domain);
    let ev = escape_xml(event);
    let cmd = escape_xml(command);
    format!(
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<plist version=\"1.0\">\n<dict>\n  <key>PayloadDomain</key>\n  <string>{dom}</string>\n  <key>HookEvent</key>\n  <string>{ev}</string>\n  <key>HookCommand</key>\n  <string>{cmd}</string>\n</dict>\n</plist>\n"
    )
}

fn render_jamf_mobileconfig(domain: &str, event: &str, command: &str) -> String {
    let dom = escape_xml(domain);
    let ev = escape_xml(event);
    let cmd = escape_xml(command);
    format!(
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<plist version=\"1.0\">\n<dict>\n  <key>PayloadType</key>\n  <string>Configuration</string>\n  <key>PayloadIdentifier</key>\n  <string>{dom}.hook</string>\n  <key>PayloadContent</key>\n  <array>\n    <dict>\n      <key>PayloadType</key>\n      <string>{dom}</string>\n      <key>HookEvent</key>\n      <string>{ev}</string>\n      <key>HookCommand</key>\n      <string>{cmd}</string>\n    </dict>\n  </array>\n</dict>\n</plist>\n"
    )
}

fn render_windows_reg(subkey: &str, event: &str, command: &str) -> String {
    let esc_cmd = command.replace('\\', "\\\\").replace('"', "\\\"");
    let esc_evt = event.replace('\\', "\\\\").replace('"', "\\\"");
    format!(
        "Windows Registry Editor Version 5.00\n\n[HKEY_LOCAL_MACHINE\\{subkey}]\n\"HookEvent\"=\"{esc_evt}\"\n\"HookCommand\"=\"{esc_cmd}\"\n"
    )
}

fn escape_xml(raw: &str) -> String {
    raw.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&apos;")
}
