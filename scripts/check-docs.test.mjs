// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors

import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import test from 'node:test';
import {
  checkLegalGovernanceAndOps,
  checkMarkdownLinks,
  checkPlansAndLifecycle,
  checkProductAndRunbooks,
  checkVocabularyAndHygiene,
  runAllDocsChecks,
} from './check-docs.mjs';
import { REPO_ROOT, syncGeneratedDocs } from './check-docs-gen.mjs';

function makeTempRoot() {
  return fs.mkdtempSync(path.join(os.tmpdir(), 'grdr-check-docs-'));
}

test('repository passes full check-docs suite once generated files are synced', () => {
  syncGeneratedDocs({ root: REPO_ROOT, write: true });
  const errors = runAllDocsChecks(REPO_ROOT);
  assert.deepEqual(errors, []);
});

test('checkVocabularyAndHygiene rejects em-dash, posture, pipe-to-shell, CDNs, and internal plan anchors', () => {
  const dir = makeTempRoot();
  try {
    fs.writeFileSync(
      path.join(dir, 'README.md'),
      'Install via curl -sSL https://fonts.googleapis.com | sh and check posture \u2014 see D-70 and W5-5\n',
      'utf8',
    );
    const errs = checkVocabularyAndHygiene(dir);
    assert.ok(errs.some((e) => e.includes('em dash')));
    assert.ok(errs.some((e) => e.includes('posture')));
    assert.ok(errs.some((e) => e.includes('Pipe-to-shell')));
    assert.ok(errs.some((e) => e.includes('CDN')));
    assert.ok(errs.some((e) => e.includes('internal plan/design anchor')));
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

test('checkMarkdownLinks flags missing relative link targets', () => {
  const dir = makeTempRoot();
  try {
    fs.writeFileSync(path.join(dir, 'README.md'), 'See [missing](docs/does-not-exist.md).\n', 'utf8');
    const errs = checkMarkdownLinks(dir);
    assert.ok(errs.some((e) => e.includes('Broken Markdown link in README.md')));
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

test('checkProductAndRunbooks detects missing front matter and incomplete runbooks', () => {
  const dir = makeTempRoot();
  try {
    fs.mkdirSync(path.join(dir, 'docs/product'), { recursive: true });
    fs.writeFileSync(path.join(dir, 'docs/product/bad.md'), '# No Frontmatter\n', 'utf8');
    fs.mkdirSync(path.join(dir, 'docs/runbooks'), { recursive: true });
    fs.writeFileSync(
      path.join(dir, 'docs/runbooks/RB-01-broken.md'),
      '---\nid: RB-01\n---\n# RB-01\n',
      'utf8',
    );
    const errs = checkProductAndRunbooks(dir);
    assert.ok(errs.some((e) => e.includes('missing YAML front matter')));
    assert.ok(errs.some((e) => e.includes('RB-01-broken.md: missing actor/rto/rpo')));
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

test('checkPlansAndLifecycle detects dangling build-order dependency and support drift', () => {
  const dir = makeTempRoot();
  try {
    fs.mkdirSync(path.join(dir, 'docs/plan'), { recursive: true });
    fs.mkdirSync(path.join(dir, 'contracts'), { recursive: true });
    fs.writeFileSync(
      path.join(dir, 'docs/plan/build-order.toml'),
      '[[slice]]\nid = "slice-0"\nrequires = ["slice-999"]\naccept = "ok"\n',
      'utf8',
    );
    fs.writeFileSync(path.join(dir, 'docs/plan/risks.toml'), '', 'utf8');
    fs.writeFileSync(path.join(dir, 'docs/plan/preconditions.toml'), '', 'utf8');
    fs.writeFileSync(path.join(dir, 'lifecycle.toml'), 'support_contract = "contracts/support.toml"\n', 'utf8');
    fs.writeFileSync(
      path.join(dir, 'contracts/support.toml'),
      'max_upgrade_minor_hop = 2\nrollback_window_minors = 1\n',
      'utf8',
    );
    fs.writeFileSync(
      path.join(dir, 'contracts/upgrade-path.json'),
      JSON.stringify({ max_upgrade_minor_hop: 9, rollback_window_minors: 1, allowed_paths: [] }),
      'utf8',
    );
    fs.writeFileSync(
      path.join(dir, 'upgrade-path.json'),
      JSON.stringify({ max_minor_hop: 9, rollback_window_minors: 1, paths: [] }),
      'utf8',
    );
    const errs = checkPlansAndLifecycle(dir);
    assert.ok(errs.some((e) => e.includes('unknown slice')));
    assert.ok(errs.some((e) => e.includes('contracts/upgrade-path.json bounds diverge')));
    assert.ok(errs.some((e) => e.includes('upgrade-path.json bounds diverge')));
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

test('checkLegalGovernanceAndOps catches stale model terms review date and margin underflow', () => {
  const dir = makeTempRoot();
  try {
    fs.mkdirSync(path.join(dir, 'docs/legal'), { recursive: true });
    fs.mkdirSync(path.join(dir, 'contracts'), { recursive: true });
    fs.mkdirSync(path.join(dir, 'docs/ops/cost-model'), { recursive: true });
    fs.writeFileSync(
      path.join(dir, 'docs/legal/model-terms.yaml'),
      'review_max_age_days: 180\nentries:\n  - last_reviewed: "2020-01-01"\n',
      'utf8',
    );
    fs.writeFileSync(
      path.join(dir, 'contracts/plans.toml'),
      '[plans.free]\naudit_retention_days = 0\n[plans.team]\nsso_enabled = true\naudit_retention_days = 7\n',
      'utf8',
    );
    fs.writeFileSync(
      path.join(dir, 'docs/ops/cost-model/model.json'),
      JSON.stringify({
        assumptions: { A16_target_min_gross_margin_bps: 7000 },
        scenarios: [
          {
            name: 'bad_margin',
            paid_endpoints: 10,
            price_per_endpoint_cents: 100,
            compute_cents: 900,
            storage_cents: 0,
            egress_cents: 0,
            model_eval_cents: 0,
            support_ops_cents: 0,
            payment_fee_bps: 0,
            expected_gross_revenue_cents: 1000,
            expected_variable_cogs_cents: 900,
            expected_gross_margin_bps: 1000,
          },
        ],
      }),
      'utf8',
    );
    const errs = checkLegalGovernanceAndOps(dir);
    assert.ok(errs.some((e) => e.includes('LBC-28')));
    assert.ok(errs.some((e) => e.includes('LBC-14')));
    assert.ok(errs.some((e) => e.includes('OPS-01')));
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

test('checkVocabularyAndHygiene flags DEP codes, --plan flag, and Rust identifier leaks in runbooks', () => {
  const dir = makeTempRoot();
  try {
    fs.mkdirSync(path.join(dir, 'docs/runbooks'), { recursive: true });
    fs.writeFileSync(
      path.join(dir, 'docs/runbooks/RB-99-leak.md'),
      'Run `grdr server preflight --plan` for DEP-0001 with InMemoryUsageLedger.\n',
      'utf8',
    );
    const errs = checkVocabularyAndHygiene(dir);
    assert.ok(errs.some((e) => e.includes('DEP-0001')));
    assert.ok(errs.some((e) => e.includes('preflight --plan')));
    assert.ok(errs.some((e) => e.includes('InMemoryUsageLedger')));
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});
