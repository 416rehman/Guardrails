# Hosted Unit Economics Model (`OPS-01`, Assumptions `A1`..`A16`)

This document pairs with [model.json](model.json) and `grdr_saas::compute_unit_economics` to verify hosted unit economics before launching paid commercial tiers (`OPS-27`).

## Reference Formula

For a cohort of `N` paid endpoints at price `P` cents/endpoint-month:

- `gross_revenue_cents = N * P`
- `payment_fees_cents = floor(gross_revenue_cents * payment_fee_bps / 10_000)`
- `variable_cogs_cents = compute + storage + egress + model_eval + support_ops + payment_fees_cents`
- `gross_margin_bps = floor((gross_revenue_cents - variable_cogs_cents) * 10_000 / gross_revenue_cents)`

Both reference scenarios (`team_1000_endpoints` at `86.10%` gross margin and `enterprise_5000_endpoints` at `91.47%` gross margin) clear the `70.00%` (`7000 bps`) floor declared in [bounds.toml](../bounds.toml) and are validated automatically by `node scripts/check-docs.mjs`.
