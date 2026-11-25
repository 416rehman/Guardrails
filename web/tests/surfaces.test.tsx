import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import { beforeEach, describe, expect, it, vi } from "vitest";
import { CONNECT_PATHS } from "@grdr/api";
import { App } from "@grdr/console";
import { OperatorApp } from "@grdr/operator";

function jsonResp(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { "Content-Type": "application/json" },
  });
}

function installSurfacesMock() {
  return vi.spyOn(globalThis, "fetch").mockImplementation(async (input) => {
    const rawUrl = typeof input === "string" ? input : input.toString();
    const path = rawUrl.split("?")[0];

    if (path === CONNECT_PATHS.getHealth) {
      return jsonResp({ status: "ok", version: "0.2.0", storage_mode: { kind: "memory" }, timestamp: "2026-11-24T00:00:00Z" });
    }
    if (path === CONNECT_PATHS.getOverview) {
      return jsonResp({
        server_status: "ok",
        total_devices: 1,
        online_devices: 1,
        total_agents: 1,
        total_mcp_servers: 0,
        active_sessions: 1,
        pending_approvals: 1,
        open_findings: 0,
        open_incidents: 0,
        kill_switch: { state: "inactive" },
        tiles: [],
        setup_steps: [{ id: "scan", label: "Scan", done: true, detail: "Ready" }],
      });
    }
    if (path === CONNECT_PATHS.listUsers) return jsonResp({ users: [], pageInfo: { totalSizeEstimate: 0 } });
    if (path === CONNECT_PATHS.getPrivacyConfig) return jsonResp({ config: { identity_mode: "named", user_risk_scoring: true } });
    if (path === CONNECT_PATHS.listDevices) {
      return jsonResp({
        devices: [
          {
            id: "dev-1",
            hostname: "dev-macbook",
            os: "macos",
            arch: "aarch64",
            install_profile: "protected",
            daemon_version: "0.2.0",
            online: true,
            hook_effective: true,
            agents: [
              {
                id: "ag-1",
                name: "Claude Code",
                kind: "cli",
                config_path: "~/.claude.json",
                hook_installed: true,
                mcp_count: 0,
                assurance: { visibility: "full", control: "boundary", on_failure: "deny", tamper: "protected" },
                assurance_level: "AL3",
                sponsor: null,
                detected_at: "2026-11-24T00:00:00Z",
              },
            ],
            mcp_servers: [],
            artifacts: [],
            last_seen: "2026-11-24T00:00:00Z",
          },
        ],
        pageInfo: { totalSizeEstimate: 1 },
      });
    }
    if (path === CONNECT_PATHS.listSessions) return jsonResp({ sessions: [], pageInfo: { totalSizeEstimate: 0 } });
    if (path === CONNECT_PATHS.listPacks) return jsonResp({ packs: [] });
    if (path === CONNECT_PATHS.listApprovals) {
      return jsonResp({
        approvals: [
          {
            id: "apr-1",
            receipt_id: "rcpt-1",
            session_id: "sess-1",
            device_id: "dev-1",
            device_name: "dev-macbook",
            agent_name: "Claude Code",
            action_class: "file.read",
            target: "~/.ssh/id_rsa",
            rule_id: "essentials.cred-store.read",
            rule_title: "Guard credential stores",
            required_grade: "G1",
            reason: "Requires explicit approval.",
            requested_at: "2026-11-24T00:00:00Z",
            state: { status: "pending" },
          },
        ],
        pageInfo: { totalSizeEstimate: 1 },
      });
    }
    if (path === CONNECT_PATHS.listFindings) return jsonResp({ findings: [], pageInfo: { totalSizeEstimate: 0 } });
    if (path === CONNECT_PATHS.listIncidents) return jsonResp({ incidents: [], pageInfo: { totalSizeEstimate: 0 } });
    if (path === CONNECT_PATHS.getKillSwitch) return jsonResp({ killSwitch: { state: "inactive" } });
    if (path === CONNECT_PATHS.listKeys) return jsonResp({ keys: [] });
    if (path === CONNECT_PATHS.listAuditEvents) return jsonResp({ entries: [], pageInfo: { totalSizeEstimate: 0 } });
    if (path === CONNECT_PATHS.issueLiveTicket) return jsonResp({ ticket: "test-live-ticket" });

    if (path === CONNECT_PATHS.explainReceipt) {
      return jsonResp({
        explanation: {
          reference: "apr-1",
          receipt_id: "rcpt-1",
          attempt_id: "att-1",
          heading: "Guardrails ADR asked before running this",
          verdict: "step_up",
          status_code: "GRDR-DEC-STEPUP",
          component: "Guardrails ADR",
          action_class: "file.read",
          rule_id: "essentials.cred-store.read",
          rule_title: "Guard credential stores",
          pack_id: "pack-essentials",
          agent_name: "Claude Code",
          device_id: "dev-1",
          device_name: "dev-macbook",
          session_id: "sess-1",
          target_quoted: "~/.ssh/id_rsa",
          reason: "Credential reads require one-time sign-off.",
          agent_told: "Guardrails ADR held this file.read [GRDR-DEC-STEPUP; ref apr-1].",
          timestamp: "2026-11-24T00:00:00Z",
          key_id: "key-local-1",
          signature_status: "verified",
          primary_action_label: "Review approval",
          primary_action_route: "/respond",
          approval_id: "apr-1",
          approver_label: "You",
        },
      });
    }
    if (path === CONNECT_PATHS.listReviewQueue) {
      return jsonResp({
        worth_a_look_count: 1,
        routine_count: 0,
        noise_count: 0,
        clusters: [
          {
            id: "rev-01",
            bucket: "worth_a_look",
            score: 88,
            rule_id: "essentials.cred-store.read",
            rule_title: "Guard credential stores",
            observable_digest: "deadbeef",
            agent_name: "Claude Code",
            device_id: "dev-1",
            device_name: "dev-macbook",
            session_id: "sess-1",
            receipt_ref: "rcpt-1",
            occurrence_count: 2,
            latest_timestamp: "2026-11-24T00:00:00Z",
            target_preview: "~/.ssh/id_rsa",
            current_mode: "watch",
            suggested_mode: "ask",
            risk_label: "High risk",
            status: "open",
            reason: "Repeated key reads in session",
            note: "",
          },
        ],
      });
    }
    if (path === CONNECT_PATHS.getComplianceWorkspace) {
      return jsonResp({
        frameworks: [{ framework_id: "nist-800-53", display_title: "NIST 800-53 Rev 5", total_controls: 10, addressed_controls: 8, coverage_percent: 80 }],
        evidence_items: [{ id: "ev-1", capability: "receipt.signing", statement: "Ed25519 signing enabled", result: "met", responsibility: "provider", control_refs: ["AU-9"], sample_ids: ["rcpt-1"], period_end: "2026-11-24", signature_status: "verified" }],
        retention: { organisation: "org-default", privacy_profile: "standard", presets: ["default"], content_days: 30, activity_days: 184, decision_days: 396, audit_days: 396, hot_days: 30, backup_days_max: 35, legal_basis: ["legitimate-interest"], conflict_note: "" },
        legal_holds: [],
        subject_requests: [],
        connectors: [{ id: "ciso-assistant", name: "CISO Assistant", kind: "grc", stability: "beta", circuit_state: "closed", queued_items: 0, delivered_items: 1, capture_ceiling: "metadata-only", assurance_label: "Signed", last_delivery_at: null, summary: "Connected" }],
        reid_requests: [],
        disclosures: [],
        disclosure_metrics: { quarter: "2026-Q4", total_reidentifications: 0, total_holds: 0, total_erasures: 0, total_exports: 1 },
        first_run: {
          selected_profile: "protected",
          confirmed: false,
          step_up_enabled: true,
          steps: [{ id: "s1", label: "Scan endpoints", detail: "Found Claude Code", done: true }],
        },
      });
    }
    if (path === CONNECT_PATHS.getProviderWorkspace) {
      return jsonResp({
        acting_as_org_id: null,
        acting_as_org_name: null,
        acting_as_reason: null,
        orgs: [{ org_id: "org-acme", name: "Acme Corp", org_set: "global-enterprise", ring: "ring-1-early", devices_count: 14, open_findings: 2, pending_approvals: 1, coverage_pct: 92, floor_version: "1.2.0", delegated_overrides: 0, status: "healthy" }],
        rings: [{ ring: "ring-1-early", org_count: 3, target_version: "1.3.0", health_state: "healthy", soak_hours: 48 }],
      });
    }
    if (path === CONNECT_PATHS.getOperatorState) {
      return jsonResp({
        runtime_config: { revision_id: "rev-0001", version: 1, capture_level: "metadata-only", privacy_profile: "standard", retention_preset: "default", hot_days: 30, activity_days: 184, decision_days: 396, audit_days: 396, otlp_enabled: false, release_channel: "stable", summary: "Baseline config" },
        revisions: [{ revision_id: "rev-0001", version: 1, state: "applied", author: "system", summary: "Baseline config", created_at: "2026-11-24T00:00:00Z", applied_at: "2026-11-24T00:00:00Z", diff_lines: [], config: { revision_id: "rev-0001", version: 1, capture_level: "metadata-only", privacy_profile: "standard", retention_preset: "default", hot_days: 30, activity_days: 184, decision_days: 396, audit_days: 396, otlp_enabled: false, release_channel: "stable", summary: "Baseline config" } }],
        preflight_matrix: [{ component: "grdr-server", current_version: "1.2.0", target_version: "1.3.0", supported_range: "^1.2", status: "compatible", agreed_capabilities: ["oscal-1.2.3"], warnings: [], remediation: "" }],
        target_version: "1.3.0",
        overall_compatible: true,
        targets: [{ id: "tgt-ledger", name: "Local SQLite Ledger", tier: 0, kind: "sqlite", status: "healthy", circuit_state: "closed", failure_count: 0, latency_ms: 2, detail: "WAL nominal", last_checked_at: "2026-11-24T00:00:00Z" }],
        drills: [{ drill_id: "drl-01", kind: "backup", status: "passed", snapshot_digest: "abc123def456", record_count: 42, verified_tables: 6, duration_ms: 14, executed_at: "2026-11-24T00:00:00Z", actor: "system", note: "Baseline drill" }],
      });
    }
    return jsonResp({ code: "not_found", message: `Unmocked RPC ${path}` }, 404);
  });
}

describe("Milestone 15b Web Console & Operator Surfaces", () => {
  beforeEach(() => {
    vi.restoreAllMocks();
    class MockEventSource {
      addEventListener() {}
      removeEventListener() {}
      close() {}
    }
    vi.stubGlobal("EventSource", MockEventSource);
    Object.defineProperty(window, "matchMedia", {
      writable: true,
      value: () => ({
        matches: false,
        media: "",
        onchange: null,
        addListener: () => {},
        removeListener: () => {},
        addEventListener: () => {},
        removeEventListener: () => {},
        dispatchEvent: () => false,
      }),
    });
  });

  it("opens WhyCardDrawer from Home waiting approval and navigates Review/Compliance/Settings/Provider", async () => {
    window.history.replaceState(null, "", "/");
    installSurfacesMock();
    const { unmount } = render(<App />);

    await waitFor(() => {
      expect(screen.getByText("Guard credential stores")).toBeTruthy();
    });

    fireEvent.click(screen.getByRole("button", { name: "Review" }));
    fireEvent.click(screen.getByRole("button", { name: "Why?" }));
    await waitFor(() => {
      expect(screen.getByText("What the agent was told (max 600 chars)")).toBeTruthy();
      expect(screen.getAllByText(/GRDR-DEC-STEPUP/).length).toBeGreaterThan(0);
    });
    unmount();

    for (const [routePath, expectedText] of [
      ["/first-run", "First run setup"],
      ["/review", "Review queue"],
      ["/compliance", "Compliance & integrations"],
      ["/settings", "Settings, privacy & disclosure"],
      ["/provider", "Provider workbench"],
    ] as const) {
      window.history.replaceState(null, "", routePath);
      const r = render(<App />);
      await waitFor(() => {
        expect(screen.getByRole("heading", { name: expectedText })).toBeTruthy();
      });
      r.unmount();
    }
  });

  it("renders Operator Plane Upgrades and Backups governance routes", async () => {
    window.history.replaceState(null, "", "/upgrades");
    installSurfacesMock();
    const { unmount } = render(<OperatorApp />);
    await waitFor(() => {
      expect(screen.getByText("Runtime configuration revisions")).toBeTruthy();
      expect(screen.getByText("Upgrade compatibility preflight")).toBeTruthy();
    });
    unmount();

    window.history.replaceState(null, "", "/backups");
    render(<OperatorApp />);
    await waitFor(() => {
      expect(screen.getByText("Delivery targets and circuit breakers")).toBeTruthy();
      expect(screen.getByText("Signed backup and restore drills")).toBeTruthy();
    });
  });
});
