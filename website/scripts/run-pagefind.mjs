// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors

import fs from 'node:fs';
import { createRequire } from 'node:module';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const websiteDir = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
let tempDir = null;

if (process.platform === 'win32' && !process.env.PAGEFIND_EXTENDED_BINARY_PATH) {
  const pfReq = createRequire(fileURLToPath(import.meta.resolve('pagefind')));
  const pkgPath = pfReq.resolve(`@pagefind/windows-${os.arch()}/bin/pagefind_extended.exe`);
  if (pkgPath.length >= 240) {
    tempDir = fs.mkdtempSync(path.join(os.tmpdir(), 'grdr-pf-'));
    const shortExe = path.join(tempDir, 'pagefind_extended.exe');
    fs.copyFileSync(pkgPath, shortExe);
    process.env.PAGEFIND_EXTENDED_BINARY_PATH = shortExe;
  }
}

try {
  const pagefind = await import('pagefind');
  const siteDir = path.join(websiteDir, 'build');
  const outDir = path.join(siteDir, 'pagefind');

  const created = await pagefind.createIndex();
  if (!created.index) {
    throw new Error(`Pagefind createIndex failed: ${(created.errors || []).join('; ')}`);
  }
  const added = await created.index.addDirectory({ path: siteDir });
  if (added.errors?.length) {
    throw new Error(`Pagefind addDirectory failed: ${added.errors.join('; ')}`);
  }
  const written = await created.index.writeFiles({ outputPath: outDir });
  if (written.errors?.length) {
    throw new Error(`Pagefind writeFiles failed: ${written.errors.join('; ')}`);
  }
  await pagefind.close();
  console.log(`Pagefind indexed ${added.page_count} pages into ${path.relative(websiteDir, outDir)}`);
} finally {
  if (tempDir) {
    await new Promise((resolve) => setTimeout(resolve, 200));
    try {
      fs.rmSync(tempDir, { recursive: true, force: true, maxRetries: 5, retryDelay: 100 });
    } catch (cleanupErr) {
      console.warn(`Note: skipped temp cleanup (${cleanupErr.code ?? 'busy'}): ${tempDir}`);
    }
  }
}
