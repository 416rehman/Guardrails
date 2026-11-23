import { AlertCircle, ArrowRight, CheckCircle2, Circle } from "lucide-react";
import { VerdictBadge } from "../components/VerdictBadge";
import { Quoted } from "../components/Quoted";
import type { ApprovalRequest, Finding, NavRoute, OverviewResponse } from "../types";

interface HomePageProps {
  overview: OverviewResponse | null;
  approvals: ApprovalRequest[];
  findings: Finding[];
  onNavigate: (route: NavRoute) => void;
}

export function HomePage({ overview, approvals, findings, onNavigate }: HomePageProps) {
  const pending = approvals.filter((a) => a.state.status === "pending");
  const openFindings = findings.filter((f) => f.lifecycle !== "resolved");
  const completedSteps = overview?.setup_steps.filter((s) => s.done).length ?? 0;
  const totalSteps = overview?.setup_steps.length ?? 0;

  return (
    <>
      <div className="page-header">
        <div>
          <h1>Home</h1>
          <p>
            Live visibility across enrolled endpoints, policy enforcement strength, and actions waiting on review.
          </p>
        </div>
        <button type="button" className="btn btn-primary" onClick={() => onNavigate("tester")}>
          Test live policy
          <ArrowRight size={14} />
        </button>
      </div>

      {overview?.kill_switch.state !== "inactive" && overview?.kill_switch && (
        <div className="banner danger" role="alert">
          <span>
            Kill switch active ({overview.kill_switch.state}): {overview.kill_switch.reason}
          </span>
          <button type="button" className="btn" onClick={() => onNavigate("respond")}>
            Manage in Respond
          </button>
        </div>
      )}

      <div className="grid-4">
        {overview?.tiles.map((tile) => (
          <div key={tile.id} className="tile">
            <div className="tile-metric tabular">{tile.metric}</div>
            <p className="tile-headline">{tile.headline}</p>
            <div className="tile-comparison">{tile.comparison}</div>
            <div className="tile-footer">
              <button type="button" className="btn-link" onClick={() => onNavigate(tile.route)}>
                <span>{tile.action_label}</span>
                <ArrowRight size={13} />
              </button>
            </div>
          </div>
        ))}
      </div>

      <div className="grid-2">
        <section className="surface">
          <div className="page-header">
            <h2 className="section-title">Needs you</h2>
            <span className="badge warning tabular">{pending.length + openFindings.length} open</span>
          </div>

          {pending.length === 0 && openFindings.length === 0 ? (
            <p style={{ margin: 0, color: "var(--ink-secondary)" }}>
              No pending step-up requests or open findings right now.
            </p>
          ) : (
            <div className="checklist">
              {pending.slice(0, 3).map((item) => (
                <div key={item.id} className="check-row todo" style={{ justifyContent: "space-between" }}>
                  <div style={{ display: "flex", flexDirection: "column", gap: "4px" }}>
                    <div style={{ display: "flex", alignItems: "center", gap: "8px" }}>
                      <VerdictBadge verdict="step_up" />
                      <strong>{item.rule_title}</strong>
                    </div>
                    <Quoted text={item.target} />
                  </div>
                  <button type="button" className="btn" onClick={() => onNavigate("respond")}>
                    Review
                  </button>
                </div>
              ))}
              {openFindings.slice(0, 3).map((finding) => (
                <div key={finding.id} className="check-row todo" style={{ justifyContent: "space-between" }}>
                  <div style={{ display: "flex", flexDirection: "column", gap: "4px" }}>
                    <div style={{ display: "flex", alignItems: "center", gap: "8px" }}>
                      <AlertCircle size={14} color="var(--tone-block)" />
                      <strong>{finding.title}</strong>
                    </div>
                    <Quoted text={finding.target} />
                  </div>
                  <button type="button" className="btn" onClick={() => onNavigate("respond")}>
                    Inspect
                  </button>
                </div>
              ))}
            </div>
          )}
        </section>

        <section className="surface">
          <div className="page-header">
            <h2 className="section-title">Platform readiness</h2>
            <span className="badge success tabular">
              {completedSteps} of {totalSteps} ready
            </span>
          </div>
          <div className="checklist">
            {overview?.setup_steps.map((step) => (
              <div key={step.id} className={`check-row ${step.done ? "done" : "todo"}`}>
                {step.done ? (
                  <CheckCircle2 size={16} color="var(--tone-allow)" style={{ flexShrink: 0, marginTop: 2 }} />
                ) : (
                  <Circle size={16} color="var(--ink-muted)" style={{ flexShrink: 0, marginTop: 2 }} />
                )}
                <div>
                  <div style={{ fontWeight: 500 }}>{step.label}</div>
                  <div style={{ fontSize: 12.5, color: "var(--ink-secondary)" }}>{step.detail}</div>
                </div>
              </div>
            ))}
          </div>
        </section>
      </div>
    </>
  );
}
