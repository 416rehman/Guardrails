---
id: ar-l10n-status
locale: ar
dir: rtl
stability: alpha
---

# Localization Guide: Arabic (`ar`, RTL)

This directory stores RTL localization documentation and verification rules alongside the mirrored Arabic (`ar`, `direction: rtl`) interface strings under `website/i18n/ar/`.

## Layout & Script Requirements

- `website/docusaurus.config.ts` declares `ar` with `direction: 'rtl'` alongside default `en` (`ltr`).
- Custom styles in `website/src/css/custom.css` apply CSS logical properties (such as `.markdown blockquote` `border-inline-start`, `padding-inline-start`, `margin-inline-start`, and centered `margin-inline: auto` containers) while scoping `[dir="rtl"] pre` and `[dir="rtl"] code` to `direction: ltr` with `unicode-bidi: isolate` so shell commands and JSON receipts stay readable.
- `website/i18n/ar/code.json`, `docusaurus-theme-classic/navbar.json`, `docusaurus-theme-classic/footer.json`, and `docusaurus-plugin-content-docs/current.json` translate all landing page, search, navigation bar, footer, and sidebar category labels using consistent Guardrails terminology.
- Localized UI labels synchronize with `web/packages/i18n/` terminology (`Mode`, `Verdict`, `Assurance level`, `Grant`, `Receipt`, `Finding`, `Incident`).
