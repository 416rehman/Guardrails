// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors

import type { BrowserMode, ExtensionStateSnapshot } from "./types.js";
import {
  applyBidiRoot,
  createBidiEl,
  createPreviewSnapshot,
  getExtRuntime,
  matchesDestinationHost,
  modeBadgeToneClass,
  modeLabel,
  renderModeRadiogroup,
  t,
  unwrapSnapshotResponse,
  verdictBadgeToneClass,
  verdictLabel,
} from "./ui-i18n.js";

async function loadSnapshot(): Promise<{ snapshot: ExtensionStateSnapshot; activeHost: string }> {
  const ext = getExtRuntime();
  const params = new URLSearchParams(window.location.search);
  const preview = params.get("preview");

  if (!ext?.runtime?.sendMessage || preview) {
    return {
      snapshot: createPreviewSnapshot(preview),
      activeHost: "chatgpt.com",
    };
  }

  let activeHost = "browser";
  try {
    const tabs = await ext.tabs?.query({ active: true, currentWindow: true });
    const rawUrl = tabs?.[0]?.url;
    if (rawUrl) {
      activeHost = new URL(rawUrl).hostname;
    }
  } catch {
    activeHost = "browser";
  }

  const raw = await ext.runtime.sendMessage({ type: "ext:get_snapshot" });
  return { snapshot: unwrapSnapshotResponse(raw), activeHost };
}

function createTextEl<K extends keyof HTMLElementTagNameMap>(
  tag: K,
  className: string,
  text: string,
): HTMLElementTagNameMap[K] {
  const el = document.createElement(tag);
  if (className) el.className = className;
  el.textContent = text;
  return el;
}

function renderPopup(
  root: HTMLElement,
  snapshot: ExtensionStateSnapshot,
  activeHost: string,
  onSetMode: (appId: string, mode: BrowserMode) => Promise<void>,
  onReconnect: () => Promise<void>,
): void {
  root.replaceChildren();

  const header = document.createElement("header");
  header.className = "ext-header";

  const brand = document.createElement("div");
  brand.className = "ext-brand";
  const mark = document.createElement("img");
  mark.src = "assets/guardrails-mark.png";
  mark.alt = "Guardrails";
  mark.width = 22;
  mark.height = 22;
  mark.className = "ext-mark";
  brand.appendChild(mark);
  brand.appendChild(createTextEl("span", "ext-title", t("extTitle", "Guardrails ADR")));

  const isConnected = snapshot.nativeStatus.kind === "connected";
  const statusBadge = createTextEl(
    "span",
    `ext-badge ${isConnected ? "tone-ok" : "tone-warn"}`,
    isConnected
      ? t("statusConnected", "Connected")
      : t("statusDegraded", "Degraded (Wasm floor)"),
  );
  header.appendChild(brand);
  header.appendChild(statusBadge);
  root.appendChild(header);

  if (snapshot.nativeStatus.kind === "degraded") {
    const notice = document.createElement("section");
    notice.className = "ext-degraded-alert";
    notice.appendChild(
      createTextEl(
        "div",
        "ext-item-title",
        `${snapshot.nativeStatus.errorCode}: ${
          snapshot.managedConfig.failClosedOnDegraded
            ? t("degradedFailClosed", "Fail-closed protection active")
            : t("degradedLocalFloor", "Local Wasm policy floor active")
        }`,
      ),
    );
    notice.appendChild(createBidiEl("div", "ext-muted", snapshot.nativeStatus.message));
    root.appendChild(notice);
  }

  const activeDest =
    snapshot.destinations.find((d) => matchesDestinationHost(activeHost, d)) ??
    snapshot.destinations[0];

  const siteCard = document.createElement("section");
  siteCard.className = "ext-card";

  const siteTop = document.createElement("div");
  siteTop.className = "ext-row-between";
  const siteInfo = document.createElement("div");
  siteInfo.appendChild(
    createTextEl("div", "ext-label", t("activeDestination", "Active destination")),
  );
  siteInfo.appendChild(
    createBidiEl(
      "div",
      "ext-site-name",
      activeDest ? `${activeDest.name} (${activeHost})` : activeHost,
    ),
  );
  siteTop.appendChild(siteInfo);
  if (activeDest) {
    siteTop.appendChild(
      createTextEl(
        "span",
        `ext-badge ${modeBadgeToneClass(activeDest.defaultMode)}`,
        modeLabel(activeDest.defaultMode),
      ),
    );
  }
  siteCard.appendChild(siteTop);

  if (activeDest) {
    const isManagedLocked = Boolean(snapshot.managedConfig.appModes[activeDest.id]);
    siteCard.appendChild(
      renderModeRadiogroup(
        `${activeDest.name} enforcement mode`,
        activeDest.defaultMode,
        isManagedLocked,
        (mode) => void onSetMode(activeDest.id, mode),
      ),
    );
    if (isManagedLocked) {
      siteCard.appendChild(
        createTextEl(
          "div",
          "ext-muted",
          t("managedModeLocked", "Mode locked by enterprise managed policy."),
        ),
      );
    }
  }
  root.appendChild(siteCard);

  const statsGrid = document.createElement("section");
  statsGrid.className = "ext-stats-3";
  const metrics: Array<[string, number]> = [
    [t("metricInspected", "Inspected"), snapshot.counters.inspectedSession],
    [t("metricBlocked", "Blocked"), snapshot.counters.blockedSession],
    [t("metricWebMcp", "WebMCP tools"), snapshot.webMcpTools.length],
  ];
  for (const [label, value] of metrics) {
    const cell = document.createElement("div");
    cell.className = "ext-stat-cell";
    cell.appendChild(createTextEl("span", "ext-label", label));
    cell.appendChild(createTextEl("strong", "ext-stat-value tabular", String(value)));
    statsGrid.appendChild(cell);
  }
  root.appendChild(statsGrid);

  const ledgerCard = document.createElement("section");
  ledgerCard.className = "ext-card";
  ledgerCard.appendChild(
    createTextEl("div", "ext-section-title", t("recentDecisions", "Recent decisions")),
  );
  if (snapshot.recentDecisions.length === 0) {
    ledgerCard.appendChild(
      createTextEl(
        "p",
        "ext-muted",
        t("emptyDecisions", "No sensitive outbound transfers observed in this session."),
      ),
    );
  } else {
    const list = document.createElement("ul");
    list.className = "ext-list";
    for (const item of snapshot.recentDecisions.slice(0, 4)) {
      const li = document.createElement("li");
      li.className = "ext-list-item";
      const top = document.createElement("div");
      top.className = "ext-row-between";
      top.appendChild(createBidiEl("span", "ext-item-title", `${item.appName} / ${item.targetLabel}`));
      top.appendChild(
        createTextEl("span", `ext-badge ${verdictBadgeToneClass(item.verdict)}`, verdictLabel(item.verdict)),
      );
      li.appendChild(top);
      li.appendChild(createBidiEl("code", "ext-mono-tag", item.ruleId));
      list.appendChild(li);
    }
    ledgerCard.appendChild(list);
  }
  root.appendChild(ledgerCard);

  const footer = document.createElement("footer");
  footer.className = "ext-footer";
  const optionsBtn = document.createElement("button");
  optionsBtn.type = "button";
  optionsBtn.className = "ext-btn ext-btn-primary";
  optionsBtn.textContent = t("openOptions", "Policy settings");
  optionsBtn.addEventListener("click", () => {
    const ext = getExtRuntime();
    if (ext?.runtime?.openOptionsPage) {
      void ext.runtime.openOptionsPage();
    } else {
      const params = new URLSearchParams(window.location.search);
      const nextParams = new URLSearchParams();
      const prev = params.get("preview");
      if (prev) nextParams.set("preview", prev);
      const theme = params.get("theme");
      if (theme) nextParams.set("theme", theme);
      const suffix = nextParams.toString() ? `?${nextParams.toString()}` : "";
      window.open(`options.html${suffix}`, "_blank", "noopener");
    }
  });

  const reconnectBtn = document.createElement("button");
  reconnectBtn.type = "button";
  reconnectBtn.className = "ext-btn";
  reconnectBtn.textContent = t("reconnectHost", "Reconnect host");
  reconnectBtn.addEventListener("click", () => void onReconnect());

  footer.appendChild(reconnectBtn);
  footer.appendChild(optionsBtn);
  root.appendChild(footer);
}

async function init(): Promise<void> {
  applyBidiRoot();
  const root = document.getElementById("app");
  if (!root) return;

  let state: { snapshot: ExtensionStateSnapshot; activeHost: string };
  try {
    state = await loadSnapshot();
  } catch (err) {
    root.replaceChildren();
    const alert = document.createElement("section");
    alert.className = "ext-degraded-alert";
    alert.appendChild(createTextEl("div", "ext-item-title", "GRDR-EXT-0304: Policy state unavailable"));
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
  const ext = getExtRuntime();
  const isPreview = Boolean(new URLSearchParams(window.location.search).get("preview"));

  const onSetMode = async (appId: string, mode: BrowserMode) => {
    if (ext?.runtime?.sendMessage && !isPreview) {
      const raw = await ext.runtime.sendMessage({
        type: "ext:set_app_mode",
        appId,
        mode,
      });
      state.snapshot = unwrapSnapshotResponse(raw);
    } else {
      state.snapshot = {
        ...state.snapshot,
        destinations: state.snapshot.destinations.map((d) =>
          d.id === appId ? { ...d, defaultMode: mode } : d,
        ),
      };
    }
    renderPopup(root, state.snapshot, state.activeHost, onSetMode, onReconnect);
  };

  const onReconnect = async () => {
    if (ext?.runtime?.sendMessage && !isPreview) {
      const raw = await ext.runtime.sendMessage({ type: "ext:reconnect_host" });
      state.snapshot = unwrapSnapshotResponse(raw);
      renderPopup(root, state.snapshot, state.activeHost, onSetMode, onReconnect);
    }
  };

  renderPopup(root, state.snapshot, state.activeHost, onSetMode, onReconnect);
}

if (typeof document !== "undefined") {
  void init();
}
