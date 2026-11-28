// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors

import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { REPO_ROOT, syncGeneratedDocs } from './check-docs-gen.mjs';

const REQUIRED_FRONT_MATTER_KEYS = [
  'id',
  'type',
  'personas',
  'shapes',
  'covers',
  'owner_squad',
  'stability',
];
const VALID_DOC_TYPES = new Set(['tutorial', 'how-to', 'explanation', 'reference']);
const REQUIRED_RUNBOOK_HEADINGS = ['## Diagnosis', '## Actions', '## Verification', '## Rollback', '## Escalation'];

function listFilesWithExtensions(dir, extensions, { excludeGenerated = false } = {}, out = []) {
  if (!fs.existsSync(dir)) return out;
  for (const entry of fs.readdirSync(dir, { withFileTypes: true }).sort((a, b) => a.name.localeCompare(b.name))) {
    const full = path.join(dir, entry.name);
    if (entry.isDirectory()) {
      if (entry.name === 'node_modules' || entry.name === 'build' || entry.name === '.docusaurus') continue;
      if (excludeGenerated && entry.name === '_generated') continue;
      listFilesWithExtensions(full, extensions, { excludeGenerated }, out);
    } else if (entry.isFile() && extensions.some((ext) => entry.name.endsWith(ext))) {
      out.push(full);
    }
  }
  return out;
}

function listMarkdownRecursive(dir, opts = {}, out = []) {
  return listFilesWithExtensions(dir, ['.md'], opts, out);
}

export function parseFrontMatter(text) {
  const match = text.match(/^---\r?\n([\s\S]*?)\r?\n---/);
  if (!match) return null;
  const keys = new Map();
  let currentKey = null;
  for (const line of match[1].split(/\r?\n/)) {
    if (/^\s*-/.test(line) && currentKey) {
      const cur = keys.get(currentKey);
      if (Array.isArray(cur)) cur.push(line.replace(/^\s*-\s*/, '').trim());
      continue;
    }
    const kv = line.match(/^([A-Za-z0-9_]+)\s*:\s*(.*)$/);
    if (kv) {
      currentKey = kv[1];
      const val = kv[2].trim();
      keys.set(currentKey, val === '' ? [] : val);
    }
  }
  return keys;
}

export function checkMarkdownLinks(root) {
  const errors = [];
  const docRoots = [
    'README.md',
    'llms.txt',
    'GOVERNANCE.md',
    'CONTRIBUTING.md',
    'CODE_OF_CONDUCT.md',
    'SECURITY.md',
    'rfcs',
    'docs/product',
    'docs/runbooks',
    'docs/extending',
    'docs/training',
    'docs/crates',
    'docs/community',
    'docs/ops',
  ];

  const files = [];
  for (const rel of docRoots) {
    const full = path.join(root, rel);
    if (!fs.existsSync(full)) {
      errors.push(`Missing governed doc path: ${rel}`);
      continue;
    }
    if (fs.statSync(full).isDirectory()) {
      listMarkdownRecursive(full, {}, files);
    } else {
      files.push(full);
    }
  }

  for (const file of files) {
    const raw = fs.readFileSync(file, 'utf8');
    const stripped = raw.replace(/```[\s\S]*?```/g, '');
    const regex = /\[[^\]]*\]\(([^)]+)\)/g;
    let m;
    while ((m = regex.exec(stripped)) !== null) {
      const target = m[1].trim();
      if (
        !target ||
        target.startsWith('#') ||
        target.startsWith('http://') ||
        target.startsWith('https://') ||
        target.startsWith('mailto:')
      ) {
        continue;
      }
      const cleanPath = target.split('#')[0].split('?')[0];
      if (!cleanPath) continue;
      const resolved = path.resolve(path.dirname(file), cleanPath);
      if (!fs.existsSync(resolved)) {
        const fromRel = path.relative(root, file).replace(/\\/g, '/');
        errors.push(`Broken Markdown link in ${fromRel}: (${target})`);
      }
    }
  }
  return errors;
}

const BANNED_CDN_HOSTS = new Set([
  'fonts.googleapis.com',
  'fonts.gstatic.com',
  'cdn.jsdelivr.net',
  'unpkg.com',
  'www.googletagmanager.com',
  'www.google-analytics.com',
]);

export function stripMarkdownCodeAndComments(raw) {
  let out = '';
  let i = 0;
  while (i < raw.length) {
    if (raw.startsWith('```', i)) {
      const end = raw.indexOf('```', i + 3);
      if (end === -1) break;
      i = end + 3;
      continue;
    }
    if (raw[i] === '`') {
      const end = raw.indexOf('`', i + 1);
      if (end === -1) break;
      i = end + 1;
      continue;
    }
    if (raw.startsWith('<!--', i)) {
      const end = raw.indexOf('-->', i + 4);
      if (end === -1) break;
      i = end + 3;
      continue;
    }
    out += raw[i];
    i += 1;
  }
  return out;
}

export function checkVocabularyAndHygiene(root) {
  const errors = [];
  const scanFiles = [
    path.join(root, 'README.md'),
    path.join(root, 'llms.txt'),
    path.join(root, 'GOVERNANCE.md'),
    path.join(root, 'CONTRIBUTING.md'),
    path.join(root, 'CODE_OF_CONDUCT.md'),
    ...listMarkdownRecursive(path.join(root, 'docs/product')),
    ...listMarkdownRecursive(path.join(root, 'docs/runbooks')),
    ...listMarkdownRecursive(path.join(root, 'docs/extending')),
    ...listMarkdownRecursive(path.join(root, 'docs/training')),
  ];

  const bannedRules = [
    { re: /\u2014/, msg: 'Unicode em dash is forbidden' },
    { re: /\bposture\b/i, msg: 'Use Guardrails vocabulary instead of banned term "posture"' },
    { re: /curl\s+[^\n|]*\|\s*(?:ba)?sh/i, msg: 'Pipe-to-shell install commands are forbidden' },
    { re: /\/api\/v1\//, msg: 'Stale prototype /api/v1/ reference detected' },
    { re: /grdr-daemon\s+--bind\b/, msg: 'Stale grdr-daemon --bind flag (daemon uses IPC, not HTTP TCP bind)' },
  ];

  const mdxDirs = [
    path.join(root, 'docs/product'),
    path.join(root, 'docs/runbooks'),
    path.join(root, 'docs/extending'),
    path.join(root, 'docs/training'),
    path.join(root, 'docs/crates'),
    path.join(root, 'docs/community'),
  ];
  for (const d of mdxDirs) {
    for (const file of listMarkdownRecursive(d)) {
      const stripped = stripMarkdownCodeAndComments(fs.readFileSync(file, 'utf8'));
      if (/<[A-Za-z0-9=]/.test(stripped)) {
        errors.push(`${path.relative(root, file).replace(/\\/g, '/')}: unescaped '<' outside code block triggers MDX JSX parser error`);
      }
    }
  }

  const internalAnchorRe =
    /\b(?:D-\d{1,3}|W\d+-\d+|P(?:[1-9]|1[0-7])|OPS-\d+[a-z]?|SP-\d+|LBC-\d+|TRN-\d+|LOC-\d+|LC-\d+|20-X-\d+|24-\d+|30-\d+|ARCH-\d+|DEP-\d{4})\b/;
  const customerFiles = [
    path.join(root, 'README.md'),
    path.join(root, 'llms.txt'),
    ...listMarkdownRecursive(path.join(root, 'docs/product')),
    ...listMarkdownRecursive(path.join(root, 'docs/runbooks')),
    ...listMarkdownRecursive(path.join(root, 'docs/extending')),
    ...listMarkdownRecursive(path.join(root, 'docs/training')),
    ...listMarkdownRecursive(path.join(root, 'docs/crates')),
    ...listMarkdownRecursive(path.join(root, 'docs/community')),
    ...listMarkdownRecursive(path.join(root, 'docs/i18n')),
    ...listFilesWithExtensions(path.join(root, 'website/src'), ['.ts', '.tsx', '.md', '.mdx']),
  ];
  for (const file of customerFiles) {
    if (!fs.existsSync(file)) continue;
    const text = fs.readFileSync(file, 'utf8');
    const rel = path.relative(root, file).replace(/\\/g, '/');
    const hit = text.match(internalAnchorRe);
    if (hit) {
      errors.push(`${rel}: internal plan/design anchor '${hit[0]}' leaked into customer-facing doc`);
    }
  }

  const productRunbookFiles = [
    ...listMarkdownRecursive(path.join(root, 'docs/product'), { excludeGenerated: true }),
    ...listMarkdownRecursive(path.join(root, 'docs/runbooks')),
    ...listMarkdownRecursive(path.join(root, 'docs/extending')),
    ...listMarkdownRecursive(path.join(root, 'docs/training')),
  ];
  const customerTechLeakRe =
    /\b(?:CODE_SAAS_[A-Z_]+|InMemoryUsageLedger|CellRouter::|TenantLifecycleRecord::|CellState::|CELL_SOFT_CAP_PCT|LATE_WINDOW_DAYS|OperationsRunner|OrgMigrationBundle|SignedDeviceRedirect|MonthlyUsageStatement|MeterPeriod)\b/;
  for (const file of productRunbookFiles) {
    const text = fs.readFileSync(file, 'utf8');
    const rel = path.relative(root, file).replace(/\\/g, '/');
    if (/grdr\s+server\s+preflight[^\n]*--plan\b/.test(text)) {
      errors.push(`${rel}: nonexistent CLI flag 'grdr server preflight --plan'`);
    }
    const leak = text.match(customerTechLeakRe);
    if (leak) {
      errors.push(`${rel}: internal Rust identifier '${leak[0]}' leaked into customer doc/runbook`);
    }
  }

  for (const file of scanFiles) {
    if (!fs.existsSync(file)) continue;
    const text = fs.readFileSync(file, 'utf8');
    const rel = path.relative(root, file).replace(/\\/g, '/');
    for (const { re, msg } of bannedRules) {
      if (re.test(text)) {
        errors.push(`${rel}: ${msg}`);
      }
    }
    for (const rawUrl of text.match(/https?:\/\/[^\s)>'"`]+/gi) ?? []) {
      const cleaned = rawUrl.replace(/[.,;:!?]+$/, '');
      try {
        const parsed = new URL(cleaned);
        if (BANNED_CDN_HOSTS.has(parsed.hostname.toLowerCase())) {
          errors.push(`${rel}: Third-party CDN/analytics URLs are forbidden (${parsed.hostname})`);
          break;
        }
      } catch {}
    }
  }
  return errors;
}

export function checkProductAndRunbooks(root) {
  const errors = [];
  for (const file of listMarkdownRecursive(path.join(root, 'docs/product'), { excludeGenerated: true })) {
    const rel = path.relative(root, file).replace(/\\/g, '/');
    const fm = parseFrontMatter(fs.readFileSync(file, 'utf8'));
    if (!fm) {
      errors.push(`${rel}: missing YAML front matter`);
      continue;
    }
    for (const key of REQUIRED_FRONT_MATTER_KEYS) {
      if (!fm.has(key)) errors.push(`${rel}: missing front-matter key '${key}'`);
    }
    const t = fm.get('type');
    if (typeof t === 'string' && !VALID_DOC_TYPES.has(t)) {
      errors.push(`${rel}: invalid Diataxis type '${t}'`);
    }
  }

  for (let n = 1; n <= 12; n += 1) {
    const prefix = `RB-${String(n).padStart(2, '0')}`;
    const rbDir = path.join(root, 'docs/runbooks');
    const matches = fs.existsSync(rbDir) ? fs.readdirSync(rbDir).filter((f) => f.startsWith(`${prefix}-`) && f.endsWith('.md')) : [];
    if (matches.length !== 1) {
      errors.push(`Expected exactly one runbook matching ${prefix}-*.md`);
      continue;
    }
    const content = fs.readFileSync(path.join(rbDir, matches[0]), 'utf8');
    const fm = parseFrontMatter(content);
    if (!fm || !fm.has('actor') || !fm.has('rto') || !fm.has('rpo')) {
      errors.push(`docs/runbooks/${matches[0]}: missing actor/rto/rpo front matter`);
    }
    for (const h of REQUIRED_RUNBOOK_HEADINGS) {
      if (!content.includes(h)) errors.push(`docs/runbooks/${matches[0]}: missing section '${h}'`);
    }
  }
  return errors;
}

export function checkPlansAndLifecycle(root) {
  const errors = [];

  const slicesRaw = fs.readFileSync(path.join(root, 'docs/plan/build-order.toml'), 'utf8');
  const sliceIds = new Set();
  const sliceBlocks = slicesRaw.split(/^\[\[slice\]\]/m).slice(1);
  if (sliceBlocks.length === 0) errors.push('RM-1: docs/plan/build-order.toml has no slices');
  const parsedSlices = [];
  for (const blk of sliceBlocks) {
    const id = blk.match(/^id\s*=\s*"([^"]+)"/m)?.[1];
    const reqMatch = blk.match(/^requires\s*=\s*\[([^\]]*)\]/m)?.[1] ?? '';
    const requires = [...reqMatch.matchAll(/"([^"]+)"/g)].map((m) => m[1]);
    if (!id) errors.push('RM-1: slice missing id');
    else sliceIds.add(id);
    if (!/^accept\s*=/m.test(blk)) errors.push(`RM-1: slice ${id ?? '?'} missing accept criteria`);
    parsedSlices.push({ id, requires });
  }
  for (const s of parsedSlices) {
    for (const dep of s.requires) {
      if (!sliceIds.has(dep)) errors.push(`RM-1: slice ${s.id} requires unknown slice '${dep}'`);
    }
  }

  const risksRaw = fs.readFileSync(path.join(root, 'docs/plan/risks.toml'), 'utf8');
  for (const blk of risksRaw.split(/^\[\[risk\]\]/m).slice(1)) {
    const id = blk.match(/^id\s*=\s*"([^"]+)"/m)?.[1] ?? '?';
    if (!/^owner_role\s*=/m.test(blk) || !/^response\s*=/m.test(blk)) {
      errors.push(`RM-1: risk ${id} missing owner_role or response`);
    }
  }

  const preRaw = fs.readFileSync(path.join(root, 'docs/plan/preconditions.toml'), 'utf8');
  for (const blk of preRaw.split(/^\[\[precondition\]\]/m).slice(1)) {
    const id = blk.match(/^id\s*=\s*"([^"]+)"/m)?.[1] ?? '?';
    if (!/^external_owner\s*=/m.test(blk) || !/^fallback_while_unmet\s*=/m.test(blk)) {
      errors.push(`RM-1: precondition ${id} missing external_owner or fallback_while_unmet`);
    }
  }

  const lifecycleRaw = fs.readFileSync(path.join(root, 'lifecycle.toml'), 'utf8');
  const supportRaw = fs.readFileSync(path.join(root, 'contracts/support.toml'), 'utf8');
  const contractUpgradePath = path.join(root, 'contracts/upgrade-path.json');
  const rootUpgradePath = path.join(root, 'upgrade-path.json');
  if (!fs.existsSync(contractUpgradePath)) {
    errors.push('LC-2: missing contracts/upgrade-path.json');
  }
  if (!fs.existsSync(rootUpgradePath)) {
    errors.push('LC-2: missing upgrade-path.json');
  }
  const supHop = Number(supportRaw.match(/^max_upgrade_minor_hop\s*=\s*(\d+)/m)?.[1] ?? 0);
  const supRollback = Number(supportRaw.match(/^rollback_window_minors\s*=\s*(\d+)/m)?.[1] ?? 0);
  for (const [label, upPath] of [
    ['contracts/upgrade-path.json', contractUpgradePath],
    ['upgrade-path.json', rootUpgradePath],
  ]) {
    if (!fs.existsSync(upPath)) continue;
    const upgrade = JSON.parse(fs.readFileSync(upPath, 'utf8'));
    const hopVal = upgrade.max_upgrade_minor_hop ?? upgrade.max_minor_hop;
    if (hopVal !== supHop || upgrade.rollback_window_minors !== supRollback) {
      errors.push(`LC-2: ${label} bounds diverge from contracts/support.toml`);
    }
    for (const p of upgrade.paths ?? []) {
      if (p.runbook && !fs.existsSync(path.join(root, p.runbook))) {
        errors.push(`LC-2: ${label} runbook missing: ${p.runbook}`);
      }
    }
  }
  if (!lifecycleRaw.includes('contracts/support.toml')) {
    errors.push('LC-1: lifecycle.toml missing support_contract linkage');
  }

  return errors;
}

export function checkLegalGovernanceAndOps(root, referenceDate = new Date()) {
  const errors = [];
  const termsRaw = fs.readFileSync(path.join(root, 'docs/legal/model-terms.yaml'), 'utf8');
  const maxAgeDays = Number(termsRaw.match(/^review_max_age_days\s*:\s*(\d+)/m)?.[1] ?? 180);
  for (const m of termsRaw.matchAll(/last_reviewed\s*:\s*"(\d{4}-\d{2}-\d{2})"/g)) {
    const reviewed = new Date(`${m[1]}T00:00:00Z`);
    const ageDays = (referenceDate.getTime() - reviewed.getTime()) / 86_400_000;
    if (ageDays > maxAgeDays || ageDays < -30) {
      errors.push(`LBC-28: model-terms review date ${m[1]} violates ${maxAgeDays}-day SLA`);
    }
  }

  const plansRaw = fs.readFileSync(path.join(root, 'contracts/plans.toml'), 'utf8');
  if (!/\[plans\.free\]/.test(plansRaw) || !/\[plans\.team\]/.test(plansRaw)) {
    errors.push('LBC-14: plans.toml missing required free or team plan');
  }
  if (/^\s*(?:feature_flags|withheld_features|paid_only_features|sso_enabled|scim_enabled|rbac_enabled)\s*=/m.test(plansRaw)) {
    errors.push('LBC-14: plans.toml must contain zero feature-gate keys (P11 parity)');
  }
  if (/^\s*audit_retention_days\s*=\s*[1-9]/m.test(plansRaw)) {
    errors.push('LBC-14: plans.toml must keep audit_retention_days = 0 across all plans');
  }

  const model = JSON.parse(fs.readFileSync(path.join(root, 'docs/ops/cost-model/model.json'), 'utf8'));
  const minMargin = model.assumptions?.A16_target_min_gross_margin_bps ?? 7000;
  for (const sc of model.scenarios ?? []) {
    const rev = sc.paid_endpoints * sc.price_per_endpoint_cents;
    const fee = Math.floor((rev * sc.payment_fee_bps) / 10_000);
    const cogs = sc.compute_cents + sc.storage_cents + sc.egress_cents + sc.model_eval_cents + sc.support_ops_cents + fee;
    const margin = Math.floor(((rev - cogs) * 10_000) / rev);
    if (
      rev !== sc.expected_gross_revenue_cents ||
      cogs !== sc.expected_variable_cogs_cents ||
      margin !== sc.expected_gross_margin_bps ||
      margin < minMargin
    ) {
      errors.push(`OPS-01: cost-model scenario ${sc.name} math or margin threshold failed`);
    }
  }

  for (const reqFile of [
    'CODE_OF_CONDUCT.md',
    'GOVERNANCE.md',
    'CONTRIBUTING.md',
    'rfcs/README.md',
    'rfcs/0000-template.md',
    'docs/community/health.md',
    'docs/legal/brand-clearance-2026-11-27.json',
    '.github/CODEOWNERS',
  ]) {
    if (!fs.existsSync(path.join(root, reqFile))) {
      errors.push(`30-05: missing governed artifact ${reqFile}`);
    }
  }
  return errors;
}

export function runAllDocsChecks(root = REPO_ROOT) {
  const errors = [];
  const gen = syncGeneratedDocs({ root, write: false });
  if (gen.drifted.length > 0) {
    errors.push(`F1: stale generated artifacts (${gen.drifted.join(', ')})`);
  }
  errors.push(...checkMarkdownLinks(root));
  errors.push(...checkVocabularyAndHygiene(root));
  errors.push(...checkProductAndRunbooks(root));
  errors.push(...checkPlansAndLifecycle(root));
  errors.push(...checkLegalGovernanceAndOps(root));
  return errors;
}

function main() {
  const errors = runAllDocsChecks(REPO_ROOT);
  if (errors.length > 0) {
    console.error(`check-docs FAIL (${errors.length} issue(s)):`);
    for (const err of errors) console.error(`  - ${err}`);
    process.exit(1);
  }
  console.log('check-docs PASS: links, front-matter, RB-01..12, plans/RM-1, lifecycle/upgrade-path, LBC-14/28, OPS-01 verified.');
}

const isMain = process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url);
if (isMain) {
  main();
}
