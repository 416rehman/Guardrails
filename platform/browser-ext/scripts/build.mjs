// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors

import { copyFileSync, cpSync, existsSync, mkdirSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { createRequire } from "node:module";
import { dirname, resolve } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

const SCRIPT_DIR = dirname(fileURLToPath(import.meta.url));
const EXT_ROOT = resolve(SCRIPT_DIR, "..");
const REPO_ROOT = resolve(EXT_ROOT, "../..");
const DIST_ROOT = resolve(EXT_ROOT, "dist");

async function loadLucideModeIcons() {
  const req = createRequire(import.meta.url);
  const lucideCjs = req.resolve("lucide-react", { paths: [resolve(REPO_ROOT, "web/packages/ui")] });
  const iconsDir = resolve(dirname(lucideCjs), "../esm/icons");
  const mapping = {
    off: "circle-off.mjs",
    watch: "eye.mjs",
    ask: "hand.mjs",
    block: "ban.mjs",
  };
  const result = {};
  for (const [mode, file] of Object.entries(mapping)) {
    const mod = await import(pathToFileURL(resolve(iconsDir, file)).href);
    result[mode] = mod.__iconData?.node ?? [];
  }
  return result;
}

function createVirtualAssetsPlugin(lucideJson, tokensJson) {
  return {
    name: "grdr-virtual-assets",
    setup(build) {
      build.onResolve({ filter: /^virtual:grdr-lucide-modes$/ }, () => ({
        path: "grdr-lucide-modes",
        namespace: "grdr-virtual",
      }));
      build.onResolve({ filter: /^virtual:grdr-tokens$/ }, () => ({
        path: "grdr-tokens",
        namespace: "grdr-virtual",
      }));
      build.onLoad({ filter: /.*/, namespace: "grdr-virtual" }, (args) => ({
        contents: args.path === "grdr-lucide-modes" ? lucideJson : tokensJson,
        loader: "json",
      }));
    },
  };
}

function loadEsbuildPath() {
  const direct = resolve(REPO_ROOT, "web/node_modules/esbuild/lib/main.js");
  if (existsSync(direct)) return direct;
  const pnpmStore = resolve(REPO_ROOT, "web/node_modules/.pnpm");
  const candidate = resolve(pnpmStore, "esbuild@0.25.12/node_modules/esbuild/lib/main.js");
  if (existsSync(candidate)) return candidate;
  throw new Error("GRDR-EXT-0901 esbuild not found in web/node_modules");
}

function uniqueSorted(values) {
  return [...new Set(values)].sort();
}

export function buildTargetManifest(target, destinationsCatalog, tenantCatalog) {
  const aiContentMatches = uniqueSorted(
    destinationsCatalog.destinations.flatMap((d) => d.hostPermissions),
  );
  const hostPermissions = uniqueSorted([
    ...aiContentMatches,
    ...tenantCatalog.providers.flatMap((p) => p.hostPermissions),
  ]);

  const base = {
    manifest_version: 3,
    name: "__MSG_extTitle__",
    description: "__MSG_extDescription__",
    version: "0.1.0",
    default_locale: "en",
    icons: {
      "16": "ui/assets/guardrails-mark.png",
      "48": "ui/assets/guardrails-mark.png",
      "128": "ui/assets/guardrails-mark.png",
    },
    action: {
      default_title: "Guardrails ADR",
      default_popup: "ui/popup.html",
      default_icon: {
        "16": "ui/assets/guardrails-mark.png",
        "48": "ui/assets/guardrails-mark.png",
      },
    },
    options_ui: {
      page: "ui/options.html",
      open_in_tab: true,
    },
    permissions: ["declarativeNetRequest", "nativeMessaging", "storage", "tabs"],
    host_permissions: hostPermissions,
    storage: {
      managed_schema: "managed_schema.json",
    },
    content_scripts: [
      {
        matches: aiContentMatches,
        js: ["content/bridge.js"],
        run_at: "document_start",
        all_frames: true,
        match_about_blank: true,
        match_origin_as_fallback: true,
        world: "ISOLATED",
      },
      {
        matches: aiContentMatches,
        js: ["content/page-hook.js"],
        run_at: "document_start",
        all_frames: true,
        match_about_blank: true,
        match_origin_as_fallback: true,
        world: "MAIN",
      },
    ],
    content_security_policy: {
      extension_pages: "script-src 'self' 'wasm-unsafe-eval'; object-src 'none';",
    },
  };

  if (target === "firefox") {
    return {
      ...base,
      background: {
        scripts: ["background/service-worker.js"],
        type: "module",
      },
      browser_specific_settings: {
        gecko: {
          id: "adr@guardrails.dev",
          strict_min_version: "128.0",
        },
      },
    };
  }

  return {
    ...base,
    background: {
      service_worker: "background/service-worker.js",
      type: "module",
    },
  };
}

export async function buildAll() {
  const esbuildMod = await import(pathToFileURL(loadEsbuildPath()).href);
  const esbuild = esbuildMod.default ?? esbuildMod;

  const destinations = JSON.parse(
    readFileSync(resolve(EXT_ROOT, "data/ai-destinations.json"), "utf8"),
  );
  const tenantProviders = JSON.parse(
    readFileSync(resolve(EXT_ROOT, "data/tenant-providers.json"), "utf8"),
  );

  const wasmBin = resolve(
    EXT_ROOT,
    "wasm-core/target/wasm32-unknown-unknown/release/grdr_browser_wasm.wasm",
  );
  if (!existsSync(wasmBin)) {
    throw new Error(`GRDR-EXT-0902 Built Wasm binary missing at ${wasmBin}`);
  }
  const tokensCss = resolve(REPO_ROOT, "web/packages/tokens/src/tokens.css");
  const markPng = resolve(REPO_ROOT, "contracts/interface/brand/guardrails-mark.png");

  const tokensJson = readFileSync(resolve(REPO_ROOT, "contracts/interface/tokens.json"), "utf8");
  const lucideJson = JSON.stringify(await loadLucideModeIcons());
  const virtualPlugin = createVirtualAssetsPlugin(lucideJson, tokensJson);

  rmSync(DIST_ROOT, { recursive: true, force: true });
  mkdirSync(DIST_ROOT, { recursive: true });

  const libOutDir = resolve(DIST_ROOT, "lib");
  mkdirSync(libOutDir, { recursive: true });
  await esbuild.build({
    entryPoints: [
      resolve(EXT_ROOT, "src/wasm-host.ts"),
      resolve(EXT_ROOT, "src/native-protocol.ts"),
      resolve(EXT_ROOT, "src/dnr-compiler.ts"),
      resolve(EXT_ROOT, "src/content-page-hook.ts"),
      resolve(EXT_ROOT, "src/content-bridge.ts"),
      resolve(EXT_ROOT, "src/service-worker.ts"),
      resolve(EXT_ROOT, "src/ui-i18n.ts"),
    ],
    outdir: libOutDir,
    bundle: true,
    format: "esm",
    platform: "neutral",
    target: "es2022",
    outExtension: { ".js": ".mjs" },
    plugins: [virtualPlugin],
  });

  const targets = ["chrome", "edge", "firefox"];
  for (const target of targets) {
    const outDir = resolve(DIST_ROOT, target);
    mkdirSync(resolve(outDir, "background"), { recursive: true });
    mkdirSync(resolve(outDir, "content"), { recursive: true });
    mkdirSync(resolve(outDir, "ui/assets"), { recursive: true });
    mkdirSync(resolve(outDir, "wasm"), { recursive: true });

    await esbuild.build({
      entryPoints: [resolve(EXT_ROOT, "src/service-worker.ts")],
      outfile: resolve(outDir, "background/service-worker.js"),
      bundle: true,
      format: "esm",
      platform: "browser",
      target: "es2022",
      plugins: [virtualPlugin],
    });

    await esbuild.build({
      entryPoints: [resolve(EXT_ROOT, "src/content-page-hook.ts")],
      outfile: resolve(outDir, "content/page-hook.js"),
      bundle: true,
      format: "iife",
      platform: "browser",
      target: "es2022",
      plugins: [virtualPlugin],
    });

    await esbuild.build({
      entryPoints: [resolve(EXT_ROOT, "src/content-bridge.ts")],
      outfile: resolve(outDir, "content/bridge.js"),
      bundle: true,
      format: "iife",
      platform: "browser",
      target: "es2022",
      plugins: [virtualPlugin],
    });

    await esbuild.build({
      entryPoints: [resolve(EXT_ROOT, "src/ui-popup.ts")],
      outfile: resolve(outDir, "ui/ui-popup.js"),
      bundle: true,
      format: "esm",
      platform: "browser",
      target: "es2022",
      plugins: [virtualPlugin],
    });

    await esbuild.build({
      entryPoints: [resolve(EXT_ROOT, "src/ui-options.ts")],
      outfile: resolve(outDir, "ui/ui-options.js"),
      bundle: true,
      format: "esm",
      platform: "browser",
      target: "es2022",
      plugins: [virtualPlugin],
    });

    copyFileSync(wasmBin, resolve(outDir, "wasm/grdr_browser_wasm.wasm"));
    copyFileSync(resolve(EXT_ROOT, "ui/popup.html"), resolve(outDir, "ui/popup.html"));
    copyFileSync(resolve(EXT_ROOT, "ui/options.html"), resolve(outDir, "ui/options.html"));
    copyFileSync(resolve(EXT_ROOT, "ui/ui-common.css"), resolve(outDir, "ui/ui-common.css"));
    copyFileSync(tokensCss, resolve(outDir, "ui/tokens.css"));
    copyFileSync(markPng, resolve(outDir, "ui/assets/guardrails-mark.png"));
    copyFileSync(
      resolve(EXT_ROOT, "manifests/managed_schema.json"),
      resolve(outDir, "managed_schema.json"),
    );
    cpSync(resolve(EXT_ROOT, "_locales"), resolve(outDir, "_locales"), { recursive: true });

    const manifest = buildTargetManifest(target, destinations, tenantProviders);
    writeFileSync(
      resolve(outDir, "manifest.json"),
      `${JSON.stringify(manifest, null, 2)}\n`,
      "utf8",
    );
  }

  console.log(`browser-ext build complete: ${targets.join(", ")} -> ${DIST_ROOT}`);
}

if (process.argv[1] && import.meta.url === pathToFileURL(resolve(process.argv[1])).href) {
  await buildAll();
}
