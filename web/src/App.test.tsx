import { render, screen } from "@testing-library/react";
import { describe, expect, it } from "vitest";
import { ModeControl } from "./components/ModeControl";
import { Quoted } from "./components/Quoted";
import { ModeBadge, VerdictBadge } from "./components/VerdictBadge";

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
});
