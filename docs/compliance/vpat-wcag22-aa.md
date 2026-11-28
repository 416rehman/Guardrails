# VPAT 2.5 INT Accessibility Conformance Guide (WCAG 2.2 Level A / AA)

Guardrails ADR targets WCAG 2.2 Level A and Level AA conformance across both
interactive graphical surfaces:

1. **Guardrails Web Console (`web/`)**
2. **Guardrails Rune Desktop (`desktop/grdr-desktop/`)**

Automated Accessibility Conformance Reports (ACRs) in VPAT 2.5 INT format are
generated from `crates/grdr-comply/data/regulatory-pack.yaml` (`grdr-comply::generate_vpat_report`):

```text
grdr comply export --format vpat-web
grdr comply export --format vpat-desktop
```

Unobserved criteria default to `Not Evaluated` until automated (`axe-core`) or screen-reader /
AccessKit audit observations are supplied to `generate_vpat_report`.

## Covered WCAG 2.2 Level A / AA Criteria

| Criterion | Level | Title | Surface Applicability | Verification Method |
|---|---|---|---|---|
| `1.1.1` | A | Non-text Content | Web and Desktop | Automated DOM/axe checks and semantic alt/aria labels |
| `1.3.1` | A | Info and Relationships | Web and Desktop | Semantic landmarks, table headers, AccessKit tree roles |
| `1.4.3` | AA | Contrast (Minimum) | Web and Desktop | Porcelain Light and Carbon Obsidian token contrast >= 4.5:1 |
| `1.4.10` | AA | Reflow | Web | Zero horizontal overflow across 390px, 768px, and 1280px viewports |
| `1.4.11` | AA | Non-text Contrast | Web and Desktop | Focus indicators and control borders >= 3:1 |
| `2.1.1` | A | Keyboard | Web and Desktop | Full Tab traversal, Escape dialog close, zero focus traps |
| `2.4.7` | AA | Focus Visible | Web and Desktop | Explicit focus-visible ring tokens on interactive elements |
| `2.5.8` | AA | Target Size (Minimum) | Web | Interactive touch and click targets >= 24x24 CSS px |
| `3.3.1` | A | Error Identification | Web and Desktop | Plain-language inline error text linked via `aria-describedby` |
| `4.1.2` | A | Name, Role, Value | Web and Desktop | ARIA attributes in Console DOM and AccessKit bridge in Rune Desktop |
| `4.1.3` | AA | Status Messages | Web and Desktop | Live-region status updates for approvals, holds, and containment |
