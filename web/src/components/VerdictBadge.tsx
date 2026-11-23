import { Ban, Check, Clock, Eye, Hand, Pencil, Shield, ShieldAlert, ShieldCheck, ShieldHalf } from "lucide-react";
import type { AssuranceLevel, Mode, Verdict } from "../types";

export function ModeBadge({ mode }: { mode: Mode }) {
  const label = mode.charAt(0).toUpperCase() + mode.slice(1);
  return (
    <span className={`badge ${mode}`}>
      {mode === "watch" && <Eye size={12} />}
      {mode === "ask" && <Hand size={12} />}
      {mode === "block" && <Ban size={12} />}
      <span>{label}</span>
    </span>
  );
}

export function VerdictBadge({ verdict }: { verdict: Verdict }) {
  const label = verdict === "step_up" ? "STEP_UP" : verdict.toUpperCase();
  return (
    <span className={`badge ${verdict}`}>
      {verdict === "allow" && <Check size={12} />}
      {verdict === "deny" && <Ban size={12} />}
      {verdict === "step_up" && <Hand size={12} />}
      {verdict === "defer" && <Clock size={12} />}
      {verdict === "modify" && <Pencil size={12} />}
      <span>{label}</span>
    </span>
  );
}

export function AssuranceBadge({ level, control }: { level: AssuranceLevel; control: string }) {
  const isBoundary = control.includes("boundary");
  const isRequest = control === "request";
  const tone = isBoundary ? "success" : isRequest ? "warning" : "neutral";
  return (
    <span className={`badge ${tone}`} title={`Control strength: ${control}`}>
      {isBoundary ? <ShieldCheck size={12} /> : isRequest ? <ShieldHalf size={12} /> : control === "none" ? <ShieldAlert size={12} /> : <Shield size={12} />}
      <span className="tabular">{level}</span>
      <span>({isBoundary ? "Boundary" : isRequest ? "Request" : "Observe"})</span>
    </span>
  );
}
