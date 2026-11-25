import { spawn, type ChildProcess } from "node:child_process";
import { randomBytes } from "node:crypto";
import { existsSync, mkdtempSync, rmSync } from "node:fs";
import { createServer } from "node:net";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";

const HEALTH_PATH = "/grdr.api.overview.v1alpha1.OverviewService/GetHealth?encoding=json";
const LIST_DEVICES_PATH = "/grdr.api.inventory.v1alpha1.InventoryService/ListDevices";
const DEVICE_CHECKIN_PATH = "/grdr.api.inventory.v1alpha1.InventoryService/DeviceCheckin";
const EVALUATE_PATH = "/grdr.api.verdict.v1alpha1.VerdictService/Evaluate";
const LIST_APPROVALS_PATH = "/grdr.api.response.v1alpha1.ResponseService/ListApprovals";
const STARTUP_TIMEOUT_MS = 30_000;
const POLL_INTERVAL_MS = 250;

function resolveServerBinary(repoRoot: string): string {
  const fromEnv = process.env.GRDR_SERVER_BIN?.trim();
  if (fromEnv && existsSync(fromEnv)) {
    return fromEnv;
  }
  const exe = process.platform === "win32" ? "grdr-server.exe" : "grdr-server";
  const candidates = [
    join(repoRoot, "target", "debug", exe),
    join(repoRoot, "target", "release", exe),
  ];
  for (const candidate of candidates) {
    if (existsSync(candidate)) {
      return candidate;
    }
  }
  throw new Error(
    `Compiled grdr-server binary not found under ${join(repoRoot, "target")}. Run "cargo build --locked --bin grdr-server" first.`,
  );
}

function reserveEphemeralPort(): Promise<number> {
  return new Promise((resolvePort, rejectPort) => {
    const srv = createServer();
    srv.unref();
    srv.on("error", rejectPort);
    srv.listen(0, "127.0.0.1", () => {
      const addr = srv.address();
      if (!addr || typeof addr === "string") {
        srv.close(() => rejectPort(new Error("Failed reserving ephemeral TCP port")));
        return;
      }
      const { port } = addr;
      srv.close((err) => {
        if (err) rejectPort(err);
        else resolvePort(port);
      });
    });
  });
}

async function waitForServerReady(
  baseUrl: string,
  child: ChildProcess | null,
  stderrTail: string[],
): Promise<void> {
  const deadline = Date.now() + STARTUP_TIMEOUT_MS;
  let lastError = "not yet ready";

  while (Date.now() < deadline) {
    if (child && child.exitCode !== null) {
      throw new Error(
        `grdr-server exited early with code ${child.exitCode}: ${stderrTail.join("")}`,
      );
    }
    try {
      const healthResp = await fetch(`${baseUrl}${HEALTH_PATH}`);
      if (healthResp.ok) {
        const indexResp = await fetch(`${baseUrl}/`);
        if (indexResp.ok) {
          const html = await indexResp.text();
          if (html.includes('id="root"')) {
            return;
          }
        }
        lastError = `index status=${indexResp.status}`;
      } else {
        lastError = `health status=${healthResp.status}`;
      }
    } catch (err) {
      lastError = err instanceof Error ? err.message : String(err);
    }
    await new Promise((r) => setTimeout(r, POLL_INTERVAL_MS));
  }

  throw new Error(
    `Timed out waiting for grdr-server at ${baseUrl} (${lastError}): ${stderrTail.join("")}`,
  );
}

async function rpcJson(
  baseUrl: string,
  methodPath: string,
  body: Record<string, unknown>,
  token: string,
): Promise<Record<string, unknown>> {
  const stepUp = process.env.GRDR_E2E_STEP_UP_TOKEN?.trim();
  const resp = await fetch(`${baseUrl}${methodPath}`, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      "Connect-Protocol-Version": "1",
      Authorization: `Bearer ${token}`,
      "X-Grdr-Confirm": "confirmed",
      ...(stepUp ? { "X-Grdr-Step-Up": stepUp } : {}),
    },
    body: JSON.stringify(body),
  });
  if (!resp.ok) {
    throw new Error(`${methodPath} failed with ${resp.status}: ${await resp.text()}`);
  }
  const parsed: unknown = await resp.json();
  if (typeof parsed !== "object" || parsed === null || Array.isArray(parsed)) {
    throw new Error(`${methodPath} returned unexpected JSON payload`);
  }
  return Object.fromEntries(Object.entries(parsed));
}

async function ensureMinimumSeedData(baseUrl: string, token: string): Promise<void> {
  const listRes = await rpcJson(baseUrl, LIST_DEVICES_PATH, { pageSize: 10 }, token);
  const existingDevices = Array.isArray(listRes.devices) ? listRes.devices : [];
  if (existingDevices.length >= 3) {
    return;
  }

  const nowIso = new Date().toISOString();
  const seedDevices = [
    {
      deviceId: "dev-qa-01",
      hostname: "dev-macbook-pro",
      os: "macos",
      arch: "aarch64",
      installProfile: "INSTALL_PROFILE_PROTECTED",
      daemonVersion: "0.2.0",
      hookEffective: true,
      userId: "usr-maya-chen",
      userDisplay: "Maya Chen",
      agents: [
        {
          id: "qa-claude-code",
          name: "Claude Code",
          kind: "claude-code",
          configPath: "~/.claude/settings.json",
          hookInstalled: true,
          mcpCount: 2,
          assuranceLevel: "ASSURANCE_LEVEL_AL3",
          detectedAt: nowIso,
        },
        {
          id: "qa-cursor",
          name: "Cursor",
          kind: "cursor",
          configPath: "~/.cursor/mcp.json",
          hookInstalled: false,
          mcpCount: 1,
          assuranceLevel: "ASSURANCE_LEVEL_AL1",
          detectedAt: nowIso,
        },
      ],
      mcpServers: [
        {
          name: "filesystem",
          transport: "stdio",
          command: "mcp-server-filesystem",
          sourceAgent: "Claude Code",
          configPath: "~/.claude/settings.json",
          pinned: true,
        },
        {
          name: "github",
          transport: "stdio",
          command: "npx",
          sourceAgent: "Cursor",
          configPath: "~/.cursor/mcp.json",
          pinned: false,
        },
      ],
      artifacts: [
        {
          id: "art_qa_skill_1",
          name: "deploy-helper",
          kind: "ARTIFACT_KIND_SKILL",
          scope: "ARTIFACT_SCOPE_USER",
          sourceAgent: "Claude Code",
          path: "~/.claude/skills/deploy-helper",
          contentDigest: "9b71d224bd62f3785d96d46ad3ea3d73319b04a2b1c9e8d7",
          fileCount: 3,
          totalBytes: 18420,
          usageCount: 14,
          pinned: false,
          deviceId: "dev-qa-01",
          deviceName: "dev-macbook-pro",
          detectedAt: nowIso,
        },
      ],
    },
    {
      deviceId: "dev-qa-02",
      hostname: "sec-linux-ws",
      os: "linux",
      arch: "x86_64",
      installProfile: "INSTALL_PROFILE_PROTECTED",
      daemonVersion: "0.2.0",
      hookEffective: true,
      userId: "usr-devon-patel",
      userDisplay: "Devon Patel",
      agents: [
        {
          id: "qa-codex",
          name: "Codex",
          kind: "codex",
          configPath: "~/.codex/config.toml",
          hookInstalled: true,
          mcpCount: 1,
          assuranceLevel: "ASSURANCE_LEVEL_AL3",
          detectedAt: nowIso,
        },
      ],
      mcpServers: [
        {
          name: "postgres",
          transport: "stdio",
          command: "uvx",
          sourceAgent: "Codex",
          configPath: "~/.codex/config.toml",
          pinned: true,
        },
      ],
      artifacts: [
        {
          id: "art_qa_rule_1",
          name: "AGENTS.md",
          kind: "ARTIFACT_KIND_RULE",
          scope: "ARTIFACT_SCOPE_WORKSPACE",
          sourceAgent: "Shared",
          path: "AGENTS.md",
          contentDigest: "6b86b273ff34fce19d6b804eff5a3f5747ada4eaa22f1d49",
          fileCount: 1,
          totalBytes: 5120,
          usageCount: 22,
          pinned: true,
          deviceId: "dev-qa-02",
          deviceName: "sec-linux-ws",
          detectedAt: nowIso,
        },
      ],
    },
    {
      deviceId: "dev-qa-03",
      hostname: "win-build-04",
      os: "windows",
      arch: "x86_64",
      installProfile: "INSTALL_PROFILE_PROTECTED",
      daemonVersion: "0.2.0",
      hookEffective: true,
      userId: "usr-elena-rostova",
      userDisplay: "Elena Rostova",
      agents: [
        {
          id: "qa-win-claude",
          name: "Claude Code",
          kind: "claude-code",
          configPath: "~/.claude/settings.json",
          hookInstalled: true,
          mcpCount: 0,
          assuranceLevel: "ASSURANCE_LEVEL_AL3",
          detectedAt: nowIso,
        },
      ],
      mcpServers: [],
      artifacts: [
        {
          id: "art_qa_cmd_1",
          name: "release-check",
          kind: "ARTIFACT_KIND_COMMAND",
          scope: "ARTIFACT_SCOPE_WORKSPACE",
          sourceAgent: "Claude Code",
          path: ".claude/commands/release-check.md",
          contentDigest: "d4735e3a265e16eee03f59718b9b5d03019c07d8b6c51f90",
          fileCount: 1,
          totalBytes: 980,
          usageCount: 8,
          pinned: true,
          deviceId: "dev-qa-03",
          deviceName: "win-build-04",
          detectedAt: nowIso,
        },
      ],
    },
  ];

  for (const dev of seedDevices) {
    await rpcJson(baseUrl, DEVICE_CHECKIN_PATH, dev, token);
  }

  const approvalsRes = await rpcJson(
    baseUrl,
    LIST_APPROVALS_PATH,
    {
      pageSize: 10,
      filter: 'status = "pending"',
    },
    token,
  );
  const pending = Array.isArray(approvalsRes.approvals) ? approvalsRes.approvals : [];
  if (pending.length === 0) {
    await rpcJson(
      baseUrl,
      EVALUATE_PATH,
      {
        sessionId: "sess-qa-seed-ask",
        deviceId: "dev-qa-01",
        deviceName: "dev-macbook-pro",
        agentName: "Claude Code",
        actionClass: "ACTION_CLASS_FILE_READ",
        target: "~/.ssh/id_rsa",
        summary: "Seed pending approval for QA",
      },
      token,
    );
  }
}

async function stopServerAndCleanup(
  child: ChildProcess,
  dataDir: string,
): Promise<void> {
  if (child.exitCode === null) {
    const exited = new Promise<void>((resolveExit) => {
      child.once("exit", () => resolveExit());
    });
    child.kill("SIGTERM");
    await Promise.race([
      exited,
      new Promise<void>((resolveTimeout) => {
        setTimeout(() => {
          if (child.exitCode === null) {
            child.kill("SIGKILL");
          }
          resolveTimeout();
        }, 5_000);
      }),
    ]);
  }

  for (let attempt = 0; attempt < 5; attempt += 1) {
    try {
      rmSync(dataDir, { recursive: true, force: true });
      return;
    } catch {
      await new Promise((r) => setTimeout(r, 150));
    }
  }
  rmSync(dataDir, { recursive: true, force: true });
}

async function startEphemeralServer(
  serverBin: string,
  repoRoot: string,
  webDistDir: string,
  operatorWebDistDir: string | null,
): Promise<{
  baseUrl: string;
  operatorBaseUrl: string;
  consoleToken: string;
  operatorToken: string;
  stepUpToken: string;
  child: ChildProcess;
  dataDir: string;
}> {
  const consolePort = await reserveEphemeralPort();
  const operatorPort = await reserveEphemeralPort();
  const bindAddr = `127.0.0.1:${consolePort}`;
  const operatorBindAddr = `127.0.0.1:${operatorPort}`;
  const baseUrl = `http://${bindAddr}`;
  const operatorBaseUrl = `http://${operatorBindAddr}`;
  const consoleToken = `e2e-console-${randomBytes(16).toString("hex")}`;
  const operatorToken = `e2e-operator-${randomBytes(16).toString("hex")}`;
  const stepUpToken = `e2e-stepup-${randomBytes(16).toString("hex")}`;
  const dataDir = mkdtempSync(join(tmpdir(), "grdr-e2e-"));
  const stderrTail: string[] = [];

  const cliArgs = [
    "--bind",
    bindAddr,
    "--operator-bind",
    operatorBindAddr,
    "--profile",
    "embedded",
    "--data-dir",
    dataDir,
    "--web-dir",
    webDistDir,
    "--api-token",
    consoleToken,
    "--operator-token",
    operatorToken,
    "--step-up-token",
    stepUpToken,
    "--demo-seed",
  ];
  if (operatorWebDistDir) {
    cliArgs.push("--operator-web-dir", operatorWebDistDir);
  }

  const child = spawn(serverBin, cliArgs, {
    cwd: repoRoot,
    stdio: ["ignore", "pipe", "pipe"],
    env: {
      ...process.env,
      RUST_LOG: process.env.RUST_LOG ?? "grdr_server=warn,tower_http=warn",
    },
  });

  const pushLog = (chunk: Buffer) => {
    stderrTail.push(chunk.toString("utf8"));
    if (stderrTail.length > 40) {
      stderrTail.shift();
    }
  };
  child.stdout?.on("data", pushLog);
  child.stderr?.on("data", pushLog);

  try {
    await waitForServerReady(baseUrl, child, stderrTail);
    if (operatorWebDistDir) {
      await waitForServerReady(operatorBaseUrl, child, stderrTail);
    }
    await ensureMinimumSeedData(baseUrl, consoleToken);
  } catch (err) {
    await stopServerAndCleanup(child, dataDir);
    throw err;
  }

  return { baseUrl, operatorBaseUrl, consoleToken, operatorToken, stepUpToken, child, dataDir };
}

export default async function globalSetup(): Promise<() => Promise<void>> {
  const externalUrl = process.env.GRDR_E2E_BASE_URL?.trim();
  const externalToken = process.env.GRDR_E2E_CONSOLE_TOKEN?.trim() ?? "";
  if (externalUrl) {
    await waitForServerReady(externalUrl, null, []);
    await ensureMinimumSeedData(externalUrl, externalToken);
    return async () => {};
  }

  const webRoot = resolve(__dirname, "..");
  const repoRoot = resolve(webRoot, "..");
  const webDistDir = join(webRoot, "dist");
  if (!existsSync(join(webDistDir, "index.html"))) {
    throw new Error(
      `Static Web Console bundle not found at ${webDistDir}. Run "pnpm --dir web run build" first.`,
    );
  }

  const webDistOperator = join(webRoot, "dist-operator");
  const hasOperatorDist = existsSync(join(webDistOperator, "index.html"));
  const serverBin = resolveServerBinary(repoRoot);
  const srv = await startEphemeralServer(
    serverBin,
    repoRoot,
    webDistDir,
    hasOperatorDist ? webDistOperator : null,
  );
  process.env.GRDR_E2E_BASE_URL = srv.baseUrl;
  process.env.GRDR_E2E_CONSOLE_TOKEN = srv.consoleToken;
  process.env.GRDR_E2E_STEP_UP_TOKEN = srv.stepUpToken;
  if (hasOperatorDist) {
    process.env.GRDR_E2E_OPERATOR_BASE_URL = srv.operatorBaseUrl;
    process.env.GRDR_E2E_OPERATOR_TOKEN = srv.operatorToken;
  }

  return async () => {
    await stopServerAndCleanup(srv.child, srv.dataDir);
  };
}
