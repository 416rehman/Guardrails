import { render, screen } from "@testing-library/react";
import { describe, expect, it } from "vitest";
import { ModeControl } from "./components/ModeControl";
import { Quoted } from "./components/Quoted";
import { ModeBadge, VerdictBadge } from "./components/VerdictBadge";
import { RespondPage } from "./pages/RespondPage";
import { SessionsPage } from "./pages/SessionsPage";

describe("Guardrails console UI primitives", () => {
  it("renders ModeControl segments and respects locked floor constraints", () => {
    const changes: string[] = [];
    render(<ModeControl value="block" locked={true} onChange={(m) => changes.push(m)} />);
    const radios = screen.getAllByRole("radio");
    expect(radios).toHaveLength(4);
    expect(radios[3]?.getAttribute("aria-checked")).toBe("true");
    expect(radios[0]?.hasAttribute("disabled")).toBe(true);
    expect(changes).toEqual([]);
  });

  it("renders untrusted text inert inside ltr isolate and flags bidi controls", () => {
    render(<Quoted text={"safe\u202Eevil"} />);
    const icon = screen.getByLabelText("Control or bidirectional character flagged");
    expect(icon).toBeTruthy();
  });

  it("renders verdict and mode badges clearly", () => {
    render(
      <div>
        <VerdictBadge verdict="step_up" />
        <ModeBadge mode="watch" />
      </div>,
    );
    expect(screen.getByText("STEP_UP")).toBeTruthy();
    expect(screen.getByText("Watch")).toBeTruthy();
  });

  it("renders enforcing session labels and correlated incidents", async () => {
    const fetchMock = globalThis.fetch;
    globalThis.fetch = (async () =>
      new Response(
        JSON.stringify({
          session: {
            id: "sess-1",
            device_id: "dev-1",
            device_name: "host-1",
            agent_name: "claude-code",
            started_at: "2026-11-23T00:00:00Z",
            last_activity: "2026-11-23T00:01:00Z",
            total_actions: 1,
            blocked_count: 1,
            step_up_count: 0,
            watch_hits: 0,
            assurance_level: "AL2",
            labels: ["credential_accessed", "tainted_exfil_risk"],
          },
          attempts: [
            {
              id: "att-1",
              session_id: "sess-1",
              device_id: "dev-1",
              device_name: "host-1",
              agent_name: "claude-code",
              action_class: "file.write",
              control_point: "hook",
              target: ".claude/settings.json",
              summary: "Blocked edit",
              timestamp: "2026-11-23T00:00:30Z",
            },
          ],
          receipts: [
            {
              receipt_id: "rcp-1",
              attempt_id: "att-1",
              session_id: "sess-1",
              device_id: "dev-1",
              agent_name: "claude-code",
              action_class: "file.write",
              control_point: "hook",
              target: ".claude/settings.json",
              verdict: "deny",
              would_be: null,
              rule_id: "essentials.agent-control-files",
              pack_id: "pack-essentials-slice0",
              mode_applied: "block",
              grant_id: null,
              reason: "Blocked",
              next_step: "None",
              receipt_digest: "0123456789abcdef0123456789abcdef",
              decided_at: "2026-11-23T00:00:30Z",
              key_id: "kid_test1234",
              signature: "sig==",
              signature_verified: true,
            },
          ],
        }),
        { status: 200, headers: { "Content-Type": "application/json" } },
      )) as typeof fetch;

    try {
      render(
        <div>
          <SessionsPage
            sessions={[
              {
                id: "sess-1",
                device_id: "dev-1",
                device_name: "host-1",
                agent_name: "claude-code",
                started_at: "2026-11-23T00:00:00Z",
                last_activity: "2026-11-23T00:01:00Z",
                total_actions: 2,
                blocked_count: 1,
                step_up_count: 1,
                watch_hits: 0,
                assurance_level: "AL2",
                labels: ["credential_accessed", "tainted_exfil_risk"],
              },
            ]}
            searchQuery=""
            onCreateRuleFromAttempt={() => {}}
          />
          <RespondPage
            approvals={[]}
            findings={[]}
            incidents={[
              {
                id: "inc-dev-1-sess-1",
                session_id: "sess-1",
                device_id: "dev-1",
                device_name: "host-1",
                agent_name: "claude-code",
                title: "claude-code session incident (2)",
                summary: "Blocked control edit; Approval requested",
                severity: "critical",
                lifecycle: "open",
                finding_ids: ["f1", "f2"],
                finding_count: 2,
                labels: ["credential_accessed"],
                first_seen: "2026-11-23T00:00:00Z",
                last_seen: "2026-11-23T00:01:00Z",
              },
            ]}
            killSwitch={{ state: "inactive" }}
            defaultSessionId="sess-1"
            onUpdated={() => {}}
          />
        </div>,
      );
      expect(screen.getByText("Credential accessed")).toBeTruthy();
      expect(screen.getByText("Tainted exfil risk")).toBeTruthy();
      expect(screen.getByText("claude-code session incident (2)")).toBeTruthy();
      expect(await screen.findByText("Signed (kid_test1234)")).toBeTruthy();
    } finally {
      globalThis.fetch = fetchMock;
    }
  });
});
