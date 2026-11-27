// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors

import type { AiDestinationSpec, BrowserMode, ExtensionStateSnapshot } from "./types.js";
import {
  applyBidiRoot,
  createBidiEl,
  createPreviewSnapshot,
  getExtRuntime,
  renderModeRadiogroup,
  t,
  unwrapSnapshotResponse,
  verdictBadgeToneClass,
  verdictLabel,
} from "./ui-i18n.js";

function el<K extends keyof HTMLElementTagNameMap>(
  tag: K,
  className = "",
  text?: string,
): HTMLElementTagNameMap[K] {
  const node = document.createElement(tag);
  if (className) node.className = className;
  if (text !== undefined) node.textContent = text;
  return node;
}

function describeCapabilities(dest: AiDestinationSpec): string {
  if (dest.defaultMode === "off") {
    return "Inspection paused (Off)";
  }
  if (dest.defaultMode === "watch") {
    return "Uploads: Observed (Watch) / Secrets: Observed (Watch)";
  }
  if (dest.defaultMode === "ask") {
    const up = dest.blockFileUploads ? "Prompt (Ask)" : "Observed";
    const sec = dest.blockSecretPayloads ? "Prompt (Ask)" : "Observed";
    return `Uploads: ${up} / Secrets: ${sec}`;
  }
  const up = dest.blockFileUploads ? "Blocked" : "Observed";
  const sec = dest.blockSecretPayloads ? "Blocked" : "Observed";
  return `Uploads: ${up} / Secrets: ${sec}`;
}

function renderOptions(
  root: HTMLElement,
  snapshot: ExtensionStateSnapshot,
  onSetMode: (appId: string, mode: BrowserMode) => Promise<void>,
  onReconnect: () => Promise<void>,
): void {
  root.replaceChildren();

  const header = el("header", "ext-options-header");
  const brand = el("div", "ext-brand");
  const mark = document.createElement("img");
  mark.src = "assets/guardrails-mark.png";
  mark.alt = "Guardrails";
  mark.width = 28;
  mark.height = 28;
  mark.className = "ext-mark";
  brand.appendChild(mark);
  const titleGroup = el("div");
  titleGroup.appendChild(
    el("h1", "ext-h1", t("optionsHeading", "Guardrails Browser Protection")),
  );
  titleGroup.appendChild(
    el(
      "p",
      "ext-subtitle",
      t(
        "optionsSub",
        "Local Wasm policy core, Native Messaging host bridge, tenant headers, and WebMCP tool controls.",
      ),
    ),
  );
  brand.appendChild(titleGroup);
  header.appendChild(brand);

  const actions = el("div", "ext-row-gap");
  const connected = snapshot.nativeStatus.kind === "connected";
  actions.appendChild(
    el(
      "span",
      `ext-badge ${connected ? "tone-ok" : "tone-warn"}`,
      connected
        ? t("statusConnected", "Connected")
        : t("statusDegraded", "Degraded (Wasm floor)"),
    ),
  );
  const reconnectBtn = el("button", "ext-btn", t("reconnectHost", "Reconnect host"));
  reconnectBtn.type = "button";
  reconnectBtn.addEventListener("click", () => void onReconnect());
  actions.appendChild(reconnectBtn);
  header.appendChild(actions);
  root.appendChild(header);

  const hostMeta =
    snapshot.nativeStatus.kind === "connected"
      ? `Protocol v${snapshot.nativeStatus.protocolVersion} / Host ${snapshot.nativeStatus.hostVersion}`
      : snapshot.nativeStatus.kind === "degraded"
        ? `${snapshot.nativeStatus.errorCode}: ${snapshot.nativeStatus.message}`
        : "Connecting";

  const mcpBlocked = snapshot.webMcpTools.filter((tool) => tool.lastDecision === "deny").length;
  const mcpConfirm = snapshot.webMcpTools.filter((tool) => tool.lastDecision === "step_up").length;
  const mcpAllowed = snapshot.webMcpTools.filter((tool) => tool.lastDecision === "allow").length;
  const mcpSummary =
    mcpConfirm > 0
      ? `${mcpBlocked} blocked / ${mcpConfirm === 1 ? "1 confirmation" : `${mcpConfirm} confirmations`}`
      : `${mcpBlocked} blocked / ${mcpAllowed} allowed`;

  const kpiGrid = el("section", "ext-options-kpis");
  const kpis: Array<[string, string, string]> = [
    [
      t("kpiNativeHost", "Native messaging host"),
      connected ? "grdr.browser" : t("degradedLabel", "Degraded"),
      hostMeta,
    ],
    [
      t("kpiWasmCore", "Wasm policy core"),
      snapshot.wasmInfo.ready ? `ABI v${snapshot.wasmInfo.abiVersion}` : "Unavailable",
      `${snapshot.wasmInfo.importCount} host imports / ${snapshot.wasmInfo.floorRulesLoaded} floor rules`,
    ],
    [
      t("kpiDnrRules", "Tenant DNR rules"),
      `${snapshot.dnrSummary.ruleCount} / ${snapshot.dnrSummary.maxRules}`,
      `${snapshot.dnrSummary.activeHeaders.length} tenant headers / ${snapshot.dnrSummary.blockedAnonymousFilters.length} anon blocks`,
    ],
    [
      t("kpiWebMcp", "WebMCP registered tools"),
      String(snapshot.webMcpTools.length),
      mcpSummary,
    ],
  ];
  for (const [label, value, meta] of kpis) {
    const card = el("div", "ext-card");
    card.appendChild(el("div", "ext-label", label));
    card.appendChild(el("div", "ext-kpi-value tabular", value));
    card.appendChild(createBidiEl("div", "ext-muted", meta));
    kpiGrid.appendChild(card);
  }
  root.appendChild(kpiGrid);

  const policyCard = el("section", "ext-card");
  policyCard.appendChild(
    el("h2", "ext-h2", t("aiDestinationsHeading", "AI destination controls")),
  );
  const tableWrap = el("div", "ext-table-wrap");
  const table = el("table", "ext-table");
  const thead = el("thead");
  const headRow = el("tr");
  for (const col of ["Destination", "Protected domains", "Uploads & secrets", "Mode"]) {
    headRow.appendChild(el("th", "", col));
  }
  thead.appendChild(headRow);
  table.appendChild(thead);

  const tbody = el("tbody");
  for (const dest of snapshot.destinations) {
    const tr = el("tr");
    tr.appendChild(createBidiEl("td", "ext-td-strong", dest.name));

    const hostCell = el("td");
    for (const host of [...dest.hosts, ...(dest.wildcardHosts ?? [])]) {
      hostCell.appendChild(createBidiEl("code", "ext-mono-tag", host));
    }
    tr.appendChild(hostCell);

    tr.appendChild(el("td", "ext-muted", describeCapabilities(dest)));

    const modeCell = el("td");
    const locked = Boolean(snapshot.managedConfig.appModes[dest.id]);
    modeCell.appendChild(
      renderModeRadiogroup(
        `${dest.name} enforcement mode`,
        dest.defaultMode,
        locked,
        (mode) => void onSetMode(dest.id, mode),
      ),
    );
    tr.appendChild(modeCell);
    tbody.appendChild(tr);
  }
  table.appendChild(tbody);
  tableWrap.appendChild(table);
  policyCard.appendChild(tableWrap);
  root.appendChild(policyCard);

  const twoCol = el("section", "ext-options-2col");

  const dnrCard = el("div", "ext-card");
  dnrCard.appendChild(el("h2", "ext-h2", t("tenantHeadersHeading", "Tenant restriction headers")));
  if (snapshot.dnrSummary.activeHeaders.length === 0) {
    dnrCard.appendChild(
      el("p", "ext-muted", "No enterprise tenant headers configured via managed storage."),
    );
  } else {
    const list = el("ul", "ext-list");
    for (const hdr of snapshot.dnrSummary.activeHeaders) {
      const li = el("li", "ext-list-item");
      const row = el("div", "ext-row-between");
      row.appendChild(createBidiEl("code", "ext-mono-tag", hdr.headerName));
      row.appendChild(createBidiEl("span", "ext-badge tone-watch", `set: ${hdr.value}`));
      li.appendChild(row);
      li.appendChild(createBidiEl("div", "ext-muted", hdr.domains.join(", ")));
      list.appendChild(li);
    }
    dnrCard.appendChild(list);
  }
  twoCol.appendChild(dnrCard);

  const mcpCard = el("div", "ext-card");
  mcpCard.appendChild(el("h2", "ext-h2", t("webMcpHeading", "WebMCP registered tools")));
  if (snapshot.webMcpTools.length === 0) {
    mcpCard.appendChild(
      el("p", "ext-muted", "No active tabs have registered document.modelContext tools yet."),
    );
  } else {
    const list = el("ul", "ext-list");
    for (const tool of snapshot.webMcpTools) {
      const li = el("li", "ext-list-item");
      const row = el("div", "ext-row-between");
      row.appendChild(createBidiEl("span", "ext-item-title", `${tool.serverId} / ${tool.name}`));
      if (tool.lastDecision) {
        row.appendChild(
          el(
            "span",
            `ext-badge ${verdictBadgeToneClass(tool.lastDecision)}`,
            verdictLabel(tool.lastDecision),
          ),
        );
      }
      li.appendChild(row);
      li.appendChild(createBidiEl("div", "ext-muted", tool.description));
      list.appendChild(li);
    }
    mcpCard.appendChild(list);
  }
  twoCol.appendChild(mcpCard);
  root.appendChild(twoCol);

  const scopeCard = el("section", "ext-card");
  scopeCard.appendChild(
    el("h2", "ext-h2", t("scopeHeading", "Inspection boundaries and sensor scope")),
  );
  scopeCard.appendChild(
    el(
      "p",
      "ext-muted",
      "Guardrails inspects outbound fetch, XHR, WebSocket, beacon, FormData uploads, and WebMCP registerTool invocations. Keystroke, paste, and clipboard listeners are never registered. When Chrome DevTools Protocol debugging is attached or the native grdr.browser host is absent, status transitions to Degraded.",
    ),
  );
  root.appendChild(scopeCard);
}

async function init(): Promise<void> {
  applyBidiRoot();
  const root = document.getElementById("app");
  if (!root) return;

  const ext = getExtRuntime();
  const preview = new URLSearchParams(window.location.search).get("preview");
  let snapshot: ExtensionStateSnapshot;
  try {
    snapshot =
      ext?.runtime?.sendMessage && !preview
        ? unwrapSnapshotResponse(await ext.runtime.sendMessage({ type: "ext:get_snapshot" }))
        : createPreviewSnapshot(preview);
  } catch (err) {
    root.replaceChildren();
    const alert = el("section", "ext-degraded-alert");
    alert.appendChild(el("div", "ext-item-title", "GRDR-EXT-0304: Policy state unavailable"));
    alert.appendChild(
      createBidiEl(
        "div",
        "ext-muted",
        err instanceof Error ? err.message : "Background service worker failed responding.",
      ),
    );
    root.appendChild(alert);
    return;
  }

  const onSetMode = async (appId: string, mode: BrowserMode) => {
    if (ext?.runtime?.sendMessage && !preview) {
      const raw = await ext.runtime.sendMessage({ type: "ext:set_app_mode", appId, mode });
      snapshot = unwrapSnapshotResponse(raw);
    } else {
      snapshot = {
        ...snapshot,
        destinations: snapshot.destinations.map((d) =>
          d.id === appId ? { ...d, defaultMode: mode } : d,
        ),
      };
    }
    renderOptions(root, snapshot, onSetMode, onReconnect);
  };

  const onReconnect = async () => {
    if (ext?.runtime?.sendMessage && !preview) {
      const raw = await ext.runtime.sendMessage({ type: "ext:reconnect_host" });
      snapshot = unwrapSnapshotResponse(raw);
      renderOptions(root, snapshot, onSetMode, onReconnect);
    }
  };

  renderOptions(root, snapshot, onSetMode, onReconnect);
}

if (typeof document !== "undefined") {
  void init();
}
