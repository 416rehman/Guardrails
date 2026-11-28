// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors

import { createHash, randomBytes } from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const THIS_DIR = path.dirname(fileURLToPath(import.meta.url));
export const REPO_ROOT = path.resolve(THIS_DIR, '..');

function normalizeLf(text) {
  return `${text.replace(/\r\n/g, '\n').trimEnd()}\n`;
}

function sha256Hex(content) {
  return createHash('sha256').update(content, 'utf8').digest('hex');
}

function walkMarkdownFiles(dir, out = []) {
  if (!fs.existsSync(dir)) return out;
  const entries = fs.readdirSync(dir, { withFileTypes: true }).sort((a, b) => a.name.localeCompare(b.name));
  for (const entry of entries) {
    const full = path.join(dir, entry.name);
    if (entry.isDirectory()) {
      if (entry.name === '_generated' || entry.name === 'node_modules' || entry.name === 'build') {
        continue;
      }
      walkMarkdownFiles(full, out);
    } else if (entry.isFile() && entry.name.endsWith('.md')) {
      out.push(full);
    }
  }
  return out;
}

function extractTitle(markdown, fallback) {
  const match = markdown.match(/^#\s+(.+)$/m);
  return match ? match[1].trim() : fallback;
}

function parseCodesRegistry(root) {
  const raw = fs.readFileSync(path.join(root, 'contracts/codes/registry.toml'), 'utf8');
  const rows = [];
  for (const line of raw.split(/\r?\n/)) {
    const m = line.match(/^(GRDR-[A-Z0-9]+-\d{4})\s*=\s*\{([^}]+)\}/);
    if (!m) continue;
    const owner = m[2].match(/\bowner\s*=\s*"([^"]+)"/)?.[1];
    const file = m[2].match(/\bfile\s*=\s*"([^"]+)"/)?.[1];
    if (owner && file) {
      rows.push({ code: m[1], owner, file });
    }
  }
  return rows.sort((a, b) => a.code.localeCompare(b.code));
}

function parseArchitectureLayers(root) {
  const raw = fs.readFileSync(path.join(root, 'contracts/architecture.toml'), 'utf8');
  const crates = [];
  let inLayers = false;
  let currentLayer = null;
  for (const line of raw.split(/\r?\n/)) {
    const trimmed = line.split('#')[0].trim();
    if (!trimmed) continue;
    if (trimmed === '[layers]') {
      inLayers = true;
      continue;
    }
    if (inLayers && /^\[/.test(trimmed)) {
      break;
    }
    if (!inLayers) continue;
    const layerStart = trimmed.match(/^([0-9]+|tool)\s*=\s*\[(.*)$/);
    if (layerStart) {
      const layer = layerStart[1];
      const remainder = layerStart[2];
      for (const m of remainder.matchAll(/"([^"]+)"/g)) {
        crates.push({ layer, name: m[1] });
      }
      currentLayer = remainder.includes(']') ? null : layer;
      continue;
    }
    if (currentLayer !== null) {
      for (const m of trimmed.matchAll(/"([^"]+)"/g)) {
        crates.push({ layer: currentLayer, name: m[1] });
      }
      if (trimmed.includes(']')) {
        currentLayer = null;
      }
    }
  }
  return crates;
}

function parseSurfaces(root) {
  const raw = fs.readFileSync(path.join(root, 'contracts/surfaces.toml'), 'utf8');
  const surfaces = [];
  let current = null;
  const flush = () => {
    if (!current) return;
    if (current.kind === 'crate' && current.id) {
      const cleanNotes = (current.notes || '')
        .replace(/\s*\([^)]*(?:ARCH-\d+|D-\d+)[^)]*\)/g, '')
        .replace(/\s+per\s+ADR-\d+[^.]*/gi, '')
        .trim();
      surfaces.push({
        id: current.id,
        kind: 'crate',
        stability: current.stability || 'specified',
        path: cleanNotes || `layer ${current.layer || '?'}`,
      });
    } else if (current.kind === 'protocol' && current.id) {
      surfaces.push({
        id: `protocol:${current.id}`,
        kind: 'protocol',
        stability: current.stability || 'specified',
        path: current.spec ? `${current.spec} (${current.version || 'v1'})` : '-',
      });
    } else if (current.kind === 'proto_package' && current.package) {
      surfaces.push({
        id: `proto:${current.package}`,
        kind: 'proto',
        stability: current.class || 'experimental',
        path: 'contracts/proto/grdr',
      });
    } else if (current.kind === 'surface' && (current.id || current.path)) {
      surfaces.push(current);
    }
    current = null;
  };

  for (const line of raw.split(/\r?\n/)) {
    const trimmed = line.split('#')[0].trim();
    if (!trimmed) continue;
    if (trimmed === '[[surface]]' || trimmed === '[[surfaces]]') {
      flush();
      current = { kind: 'surface', id: '', stability: '', path: '' };
      continue;
    }
    if (trimmed === '[[proto_package]]') {
      flush();
      current = { kind: 'proto_package', package: '', class: '' };
      continue;
    }
    const crateMatch = trimmed.match(/^\[crates\.([^\]]+)\]$/);
    if (crateMatch) {
      flush();
      current = { kind: 'crate', id: crateMatch[1], stability: '', notes: '', layer: '' };
      continue;
    }
    const protoMatch = trimmed.match(/^\[protocols\.([^\]]+)\]$/);
    if (protoMatch) {
      flush();
      current = { kind: 'protocol', id: protoMatch[1], stability: '', spec: '', version: '' };
      continue;
    }
    if (/^\[/.test(trimmed)) {
      flush();
      continue;
    }
    if (!current) continue;
    const strKv = trimmed.match(/^([a-z_]+)\s*=\s*"([^"]*)"/);
    if (strKv) {
      current[strKv[1]] = strKv[2];
      continue;
    }
    const numKv = trimmed.match(/^([a-z_]+)\s*=\s*(\d+)/);
    if (numKv) {
      current[numKv[1]] = numKv[2];
    }
  }
  flush();
  return surfaces;
}

function parseSupportSummary(root) {
  const raw = fs.readFileSync(path.join(root, 'contracts/support.toml'), 'utf8');
  const values = new Map();
  for (const line of raw.split(/\r?\n/)) {
    const trimmed = line.trim();
    if (!trimmed || trimmed.startsWith('#') || trimmed.startsWith('[')) continue;
    const eq = trimmed.indexOf('=');
    if (eq <= 0) continue;
    const key = trimmed.slice(0, eq).trim();
    const val = trimmed.slice(eq + 1).trim();
    if (key && !values.has(key)) {
      values.set(key, val);
    }
  }
  const pick = (key) => values.get(key) ?? 'n/a';
  return {
    cadence: pick('cadence'),
    supportedMinorsBehind: pick('supported_minors_behind'),
    maxUpgradeMinorHop: pick('max_upgrade_minor_hop'),
    rollbackWindowMinors: pick('rollback_window_minors'),
    sensorSkewBehind: pick('sensor_skew_behind'),
    sensorSkewAhead: pick('sensor_skew_ahead'),
    postgresMajor: pick('postgresql_major'),
    k8sVersions: pick('supported_versions'),
  };
}

function buildErrorCodesDoc(root) {
  const codes = parseCodesRegistry(root);
  if (codes.length === 0) {
    throw new Error('check-docs-gen: parsed 0 error codes from contracts/codes/registry.toml');
  }
  const lines = [
    '---',
    'id: ref-error-codes',
    'type: reference',
    'personas:',
    '  - operator',
    '  - developer',
    'shapes:',
    '  - solo',
    '  - team',
    '  - self-hosted',
    '  - hosted',
    'covers:',
    '  - error-codes',
    'owner_squad: architecture',
    'stability: beta',
    'generated: true',
    'title: Registered Error Codes',
    '---',
    '',
    '# Registered Error Codes (`contracts/codes/registry.toml`)',
    '',
    `Generated automatically from \`contracts/codes/registry.toml\` (${codes.length} registered codes).`,
    '',
    '| Code | Owner Crate | Source File |',
    '| --- | --- | --- |',
    ...codes.map((r) => `| \`${r.code}\` | \`${r.owner}\` | \`${r.file}\` |`),
  ];
  return normalizeLf(lines.join('\n'));
}

function buildCrateLayersDoc(root) {
  const crates = parseArchitectureLayers(root);
  if (crates.length === 0) {
    throw new Error('check-docs-gen: parsed 0 workspace crates from contracts/architecture.toml');
  }
  const lines = [
    '---',
    'id: ref-crate-layers',
    'type: reference',
    'personas:',
    '  - extender',
    'shapes:',
    '  - self-hosted',
    '  - embed',
    'covers:',
    '  - architecture',
    '  - layers',
    'owner_squad: architecture',
    'stability: beta',
    'generated: true',
    'title: Workspace Crate Layers',
    '---',
    '',
    '# Workspace Crate Layers (`contracts/architecture.toml`)',
    '',
    `Generated automatically from \`contracts/architecture.toml\` (${crates.length} registered crates).`,
    '',
    '| Layer | Crate |',
    '| --- | --- |',
    ...crates.map((c) => `| \`${c.layer}\` | \`${c.name}\` |`),
  ];
  return normalizeLf(lines.join('\n'));
}

function buildSurfacesDoc(root) {
  const surfaces = parseSurfaces(root);
  if (surfaces.length === 0) {
    throw new Error('check-docs-gen: parsed 0 public surfaces from contracts/surfaces.toml');
  }
  const sup = parseSupportSummary(root);
  const lines = [
    '---',
    'id: ref-surfaces-and-support',
    'type: reference',
    'personas:',
    '  - operator',
    '  - extender',
    'shapes:',
    '  - self-hosted',
    '  - hosted',
    'covers:',
    '  - surfaces',
    '  - support-matrix',
    'owner_squad: release',
    'stability: beta',
    'generated: true',
    'title: Public Surfaces and Support Matrix',
    '---',
    '',
    '# Public Surfaces and Support Matrix',
    '',
    'Generated automatically from `contracts/surfaces.toml` and `contracts/support.toml`.',
    '',
    '## Support Policy Bounds',
    '',
    `- Release cadence: ${sup.cadence}`,
    `- Supported minors behind: ${sup.supportedMinorsBehind}`,
    `- Max direct upgrade hop: ${sup.maxUpgradeMinorHop}`,
    `- Rollback window minors: ${sup.rollbackWindowMinors}`,
    `- Sensor skew tolerance: -${sup.sensorSkewBehind} / +${sup.sensorSkewAhead} minors`,
    `- PostgreSQL major tier 1: ${sup.postgresMajor}`,
    `- Supported Kubernetes versions: ${sup.k8sVersions}`,
    '',
    `## Registered Surfaces (${surfaces.length})`,
    '',
    '| ID / Kind | Stability | Path |',
    '| --- | --- | --- |',
    ...surfaces.map((s) => `| \`${s.id || s.kind || 'surface'}\` | \`${s.stability || 'specified'}\` | \`${s.path || '-'}\` |`),
  ];
  return normalizeLf(lines.join('\n'));
}

export function buildGeneratedArtifacts(root = REPO_ROOT) {
  const outputs = new Map();
  const genDir = 'docs/product/reference/_generated';
  const genFiles = {
    [`${genDir}/error-codes.md`]: buildErrorCodesDoc(root),
    [`${genDir}/crate-layers.md`]: buildCrateLayersDoc(root),
    [`${genDir}/surfaces-and-support.md`]: buildSurfacesDoc(root),
  };
  for (const [rel, body] of Object.entries(genFiles)) {
    outputs.set(rel, body);
  }

  const rootLlms = normalizeLf(fs.readFileSync(path.join(root, 'llms.txt'), 'utf8'));
  outputs.set('website/static/llms.txt', rootLlms);

  const corpusRoots = ['docs/product', 'docs/runbooks', 'docs/extending', 'docs/training'];
  const docFiles = [];
  for (const cr of corpusRoots) {
    for (const full of walkMarkdownFiles(path.join(root, cr))) {
      docFiles.push(full);
    }
  }
  for (const [rel, content] of Object.entries(genFiles)) {
    docFiles.push({ virtualRel: rel, content });
  }

  const indexEntries = [];
  const fullChunks = ['# Guardrails ADR Complete Offline Corpus', ''];

  for (const item of docFiles) {
    const relPath =
      typeof item === 'string'
        ? path.relative(root, item).replace(/\\/g, '/')
        : item.virtualRel;
    const raw = typeof item === 'string' ? normalizeLf(fs.readFileSync(item, 'utf8')) : item.content;
    const title = extractTitle(raw, relPath);
    const digest = sha256Hex(raw);
    indexEntries.push({
      path: relPath,
      title,
      sha256: digest,
      bytes: Buffer.byteLength(raw, 'utf8'),
    });
    fullChunks.push(`<!-- source: ${relPath} sha256:${digest} -->`);
    fullChunks.push(raw.trimEnd());
    fullChunks.push('');
  }

  outputs.set('website/static/llms-full.txt', normalizeLf(fullChunks.join('\n')));
  outputs.set(
    'website/static/docs-index.json',
    normalizeLf(
      JSON.stringify(
        {
          schema: 'grdr.docs-index.v1alpha1',
          total_documents: indexEntries.length,
          documents: indexEntries,
        },
        null,
        2,
      ),
    ),
  );

  return outputs;
}

export function syncGeneratedDocs({ root = REPO_ROOT, write = false } = {}) {
  const expected = buildGeneratedArtifacts(root);
  const drifted = [];
  for (const [rel, content] of expected.entries()) {
    const full = path.join(root, rel);
    let current = null;
    try {
      current = fs.readFileSync(full, 'utf8');
    } catch (err) {
      if (err?.code !== 'ENOENT') throw err;
    }
    if (current !== content) {
      if (write) {
        const dir = path.dirname(full);
        fs.mkdirSync(dir, { recursive: true });
        const tmp = path.join(dir, `.tmp-${path.basename(full)}-${process.pid}-${randomBytes(6).toString('hex')}`);
        try {
          fs.writeFileSync(tmp, content, { encoding: 'utf8', flag: 'wx' });
          fs.renameSync(tmp, full);
        } catch (err) {
          try {
            fs.rmSync(tmp, { force: true });
          } catch {}
          throw err;
        }
      } else {
        drifted.push(rel);
      }
    }
  }
  return { count: expected.size, drifted };
}

function main() {
  const write = process.argv.includes('--write');
  const check = process.argv.includes('--check') || !write;
  const res = syncGeneratedDocs({ root: REPO_ROOT, write });
  if (check && !write && res.drifted.length > 0) {
    console.error(`check-docs-gen FAIL: drifted generated files: ${res.drifted.join(', ')}`);
    process.exit(1);
  }
  console.log(`check-docs-gen PASS: ${res.count} artifacts ${write ? 'written' : 'verified'}.`);
}

const isMain = process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url);
if (isMain) {
  main();
}
