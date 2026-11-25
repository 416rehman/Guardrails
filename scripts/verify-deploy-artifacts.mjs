// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors
// Verifies Issue #87 deployment, packaging, Helm, Terraform, Compose, and config registries.

import { execFileSync } from "node:child_process";
import { existsSync, readdirSync, readFileSync, statSync } from "node:fs";
import { join, relative, resolve } from "node:path";

const ROOT = resolve(import.meta.dirname, "..");
const TEST_DIGEST = "sha256:1111111111111111111111111111111111111111111111111111111111111111";
const ZERO_DIGEST = "sha256:0000000000000000000000000000000000000000000000000000000000000000";

const REQUIRED_TOMLS = [
  "contracts/interface/brand/brand.toml",
  "contracts/limits.toml",
  "deploy/release/dist.toml",
  "contracts/support.toml",
  "docs/plan/build-order.toml",
  "docs/plan/spikes.toml",
  "docs/plan/preconditions.toml",
  "docs/plan/risks.toml",
];

const REQUIRED_FILES = [
  ...REQUIRED_TOMLS,
  ".dockerignore",
  "deploy/release/release-manifest.schema.json",
  "deploy/docker/Containerfile.server",
  "deploy/docker/Containerfile.node-sensor",
  "deploy/docker/Containerfile.keys-pkcs11",
  "deploy/compose/embedded.yml",
  "deploy/compose/ha.yml",
  "deploy/helm/grdr-server/Chart.yaml",
  "deploy/helm/grdr-server/values.yaml",
  "deploy/helm/grdr-server/values.schema.json",
  "deploy/helm/grdr-server/templates/service-operator.yaml",
  "deploy/helm/grdr-server/templates/ingress-operator.yaml",
  "deploy/helm/grdr-node-sensor/Chart.yaml",
  "deploy/helm/grdr-node-sensor/values.yaml",
  "deploy/helm/grdr-node-sensor/values.schema.json",
  "deploy/packaging/systemd/sysusers.d/grdr.conf",
  "deploy/packaging/systemd/grdr-daemon.service",
  "deploy/packaging/systemd/grdr-decide.socket",
  "deploy/packaging/systemd/grdr-local.socket",
  "deploy/packaging/systemd/grdr-server.service",
  "deploy/packaging/systemd/user/grdr-daemon.service",
  "deploy/packaging/launchd/com.guardrailshq.grdr.daemon.plist",
  "deploy/packaging/launchd/com.guardrailshq.grdr.agent.plist",
  "deploy/packaging/launchd/com.guardrailshq.grdr.server.plist",
  "deploy/packaging/windows/grdr-services.json",
  "deploy/packaging/windows/guardrails.admx",
  "deploy/packaging/windows/en-US/guardrails.adml",
  "deploy/packaging/deb/nfpm.yaml",
  "deploy/packaging/deb/scripts/postinstall.sh",
  "deploy/packaging/deb/scripts/preremove.sh",
  "deploy/packaging/rpm/nfpm.yaml",
  "deploy/packaging/rpm/scripts/postinstall.sh",
  "deploy/packaging/rpm/scripts/preremove.sh",
  "deploy/packaging/macos-pkg/distribution.xml",
  "deploy/packaging/macos-pkg/entitlements/grdr.entitlements.plist",
  "deploy/packaging/macos-pkg/mobileconfig/com.guardrailshq.grdr.mobileconfig",
  "deploy/packaging/macos-pkg/scripts/preinstall",
  "deploy/packaging/macos-pkg/scripts/postinstall",
  "deploy/packaging/wix/Package.wxs",
  "deploy/packaging/wix/Package.wixproj",
];

const SECRET_PATTERNS = [
  /-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----/,
  /\b(?:ghp|gho|ghu|ghs)_[A-Za-z0-9]{20,}\b/,
  /\bAKIA[0-9A-Z]{16}\b/,
];

function walkFiles(dir) {
  const out = [];
  if (!existsSync(dir)) return out;
  for (const entry of readdirSync(dir)) {
    const full = join(dir, entry);
    if (statSync(full).isDirectory()) out.push(...walkFiles(full));
    else out.push(full);
  }
  return out;
}

function readRel(rel) {
  return readFileSync(join(ROOT, rel), "utf8");
}

function tryCommand(cmd, args, extraEnv = {}) {
  try {
    return execFileSync(cmd, args, {
      cwd: ROOT,
      encoding: "utf8",
      env: { ...process.env, ...extraEnv },
      stdio: ["ignore", "pipe", "pipe"],
    });
  } catch (err) {
    if (err.code === "ENOENT") return null;
    throw new Error(`${cmd} ${args.join(" ")} failed: ${err.stderr || err.message}`);
  }
}

function mustCommand(cmd, args, extraEnv = {}) {
  const out = tryCommand(cmd, args, extraEnv);
  if (out === null) {
    throw new Error(`required CLI "${cmd}" not found on PATH`);
  }
  return out;
}

function assertCommandFails(cmd, args, desc, errors) {
  try {
    execFileSync(cmd, args, { cwd: ROOT, encoding: "utf8", stdio: ["ignore", "pipe", "pipe"] });
    errors.push(`negative test failed (${desc}): expected failure but succeeded`);
  } catch (err) {
    if (err.code === "ENOENT") errors.push(`required CLI "${cmd}" missing for ${desc}`);
  }
}

function findPython() {
  for (const bin of ["python", "python3"]) {
    try {
      const out = execFileSync(bin, ["--version"], { encoding: "utf8", stdio: ["ignore", "pipe", "pipe"] });
      if (out.includes("Python 3.")) return bin;
    } catch {
      // Try next Python binary name on PATH.
    }
  }
  return null;
}

function readBrandDomain() {
  const brandTxt = readRel("contracts/interface/brand/brand.toml");
  const match = brandTxt.match(/^\s*domain\s*=\s*"([^"]+)"/m);
  return match ? match[1] : "";
}

function checkHygiene(errors, targetFiles) {
  const domainAllowed = new Set(["contracts/interface/brand/brand.toml", "deploy/release/dist.toml"]);
  const appleIdAllowedPrefix = ["deploy/packaging/launchd/", "deploy/packaging/macos-pkg/"];
  const brandDomain = readBrandDomain();
  const brandReversePrefix = brandDomain.split(".").reverse().join(".");
  for (const rel of targetFiles) {
    const content = readRel(rel);
    if (content.includes("\u2014")) errors.push(`hygiene (${rel}): contains forbidden em dash`);
    if (brandDomain && !domainAllowed.has(rel)) {
      const allowAppleReverse = appleIdAllowedPrefix.some((p) => rel.startsWith(p));
      let sanitized = content;
      if (allowAppleReverse && brandReversePrefix) {
        const revBase = brandReversePrefix.split(".").slice(0, 2).join(".");
        sanitized = sanitized
          .replaceAll(brandReversePrefix + ".grdr", "")
          .replaceAll("<organization>" + revBase + "</organization>", "");
      }
      if (sanitized.toLowerCase().includes(brandDomain.toLowerCase())) {
        errors.push(`brand (${rel}): hardcoded ${brandDomain} outside contracts/interface/brand/ and deploy/release/dist.toml`);
      }
    }
    for (const pat of SECRET_PATTERNS) {
      if (pat.test(content)) errors.push(`security (${rel}): matched credential pattern ${pat}`);
    }
    const checkSpdx =
      rel.startsWith("deploy/packaging/") || rel === "scripts/verify-deploy-artifacts.mjs";
    if (checkSpdx && (/\.(sh|mjs)$/.test(rel) || rel.endsWith("preinstall") || rel.endsWith("postinstall"))) {
      if (!content.includes("SPDX-License-Identifier: Apache-2.0")) {
        errors.push(`licence (${rel}): missing SPDX-License-Identifier header`);
      }
      if (!content.includes("SPDX-FileCopyrightText: The Guardrails ADR Authors")) {
        errors.push(`licence (${rel}): missing SPDX-FileCopyrightText header`);
      }
    }
  }
}

function checkTomlAndSchemas(errors, pythonBin) {
  if (!pythonBin) {
    errors.push("registry check: Python 3 interpreter with tomllib not found on PATH");
    return;
  }
  const pyCheck = `
import json, plistlib, sys, tomllib, xml.etree.ElementTree as ET
from pathlib import Path

tomls = {}
for p in json.loads(sys.argv[1]):
    tomls[p] = tomllib.loads(Path(p).read_text("utf-8"))

brand = tomls["contracts/interface/brand/brand.toml"]
assert brand["schema"] == "grdr.brand.v1alpha1"
assert brand["identity"]["namespace"] == "grdr"
assert brand["legal"]["copyright_holder"] == "The Guardrails ADR Authors"
assert brand["os_identity"]["windows_msi_upgrade_code"] in Path("deploy/packaging/wix/Package.wxs").read_text("utf-8")

limits = tomls["contracts/limits.toml"]
for sec in ["endpoint", "packs", "uplink", "retry", "server"]:
    assert sec in limits, f"missing {sec} in contracts/limits.toml"

dist = tomls["deploy/release/dist.toml"]
assert dist["phone_home"] is False
assert len(dist["updates"]["sources"]) >= 2

support = tomls["contracts/support.toml"]
assert support["platform"]["databases"]["postgresql_major"] == 18

slices = {s["id"] for s in tomls["docs/plan/build-order.toml"]["slice"]}
assert len(slices) == 11, f"expected 11 slices, got {len(slices)}"
spikes = {s["id"] for s in tomls["docs/plan/spikes.toml"]["spike"]}
assert len(spikes) == 31, f"expected 31 spikes, got {len(spikes)}"
risks = {r["id"] for r in tomls["docs/plan/risks.toml"]["risk"]}
assert len(risks) == 30, f"expected 30 risks, got {len(risks)}"

schema = json.loads(Path("deploy/release/release-manifest.schema.json").read_text("utf-8"))
for req in ["bundle_version", "commit", "channel", "components", "artefacts", "compat", "wire_major", "schema_rev", "trusted_root"]:
    assert req in schema["required"], f"missing {req} in release-manifest.schema.json"

for chart in ["grdr-server", "grdr-node-sensor"]:
    vs = json.loads(Path(f"deploy/helm/{chart}/values.schema.json").read_text("utf-8"))
    assert vs.get("additionalProperties") is False, f"{chart} values.schema.json must set additionalProperties=false"
    assert vs["properties"]["image"]["properties"]["digest"]["not"]["const"] == "${ZERO_DIGEST}"

for plist in Path("deploy/packaging").rglob("*.plist"):
    with plist.open("rb") as fh:
        plistlib.load(fh)
for mc in Path("deploy/packaging").rglob("*.mobileconfig"):
    with mc.open("rb") as fh:
        plistlib.load(fh)
for xml_path in ["deploy/packaging/windows/guardrails.admx", "deploy/packaging/windows/en-US/guardrails.adml", "deploy/packaging/macos-pkg/distribution.xml", "deploy/packaging/wix/Package.wxs", "deploy/packaging/wix/Package.wixproj"]:
    ET.parse(xml_path)
json.loads(Path("deploy/packaging/windows/grdr-services.json").read_text("utf-8"))
`;
  try {
    execFileSync(pythonBin, ["-c", pyCheck, JSON.stringify(REQUIRED_TOMLS)], {
      cwd: ROOT,
      encoding: "utf8",
      stdio: ["ignore", "pipe", "pipe"],
    });
  } catch (err) {
    errors.push(`python validation failed: ${err.stderr || err.message}`);
  }
}

function checkContainersAndCompose(errors) {
  for (const cf of [
    "deploy/docker/Containerfile.server",
    "deploy/docker/Containerfile.node-sensor",
    "deploy/docker/Containerfile.keys-pkcs11",
  ]) {
    const txt = readRel(cf);
    for (const line of txt.split(/\r?\n/)) {
      const m = line.match(/^\s*ARG\s+\w+_IMAGE=(.+)$/);
      if (m && !/@sha256:[0-9a-f]{64}$/.test(m[1].trim())) {
        errors.push(`${cf}: external image arg "${m[1]}" must pin @sha256 digest`);
      }
      if (/^\s*FROM\s+/.test(line) && /:latest\b/.test(line)) {
        errors.push(`${cf}: :latest tag forbidden (${line.trim()})`);
      }
    }
    if (!txt.includes("USER 65532:65532")) errors.push(`${cf}: must run non-root USER 65532:65532`);
  }
  if (!readRel("deploy/docker/Containerfile.server").includes("FROM scratch")) {
    errors.push("deploy/docker/Containerfile.server: runtime stage must use scratch");
  }
  const pkcs11Code = readRel("deploy/docker/Containerfile.keys-pkcs11")
    .split(/\r?\n/)
    .filter((line) => !line.trim().startsWith("#"))
    .join("\n");
  if (pkcs11Code.includes("grdr-server")) {
    errors.push("deploy/docker/Containerfile.keys-pkcs11: must not alias grdr-server");
  }

  for (const comp of ["deploy/compose/embedded.yml", "deploy/compose/ha.yml"]) {
    const txt = readRel(comp);
    if (/:latest\b/.test(txt)) errors.push(`${comp}: :latest tag forbidden`);
    if (!txt.includes("no-new-privileges:true")) errors.push(`${comp}: missing no-new-privileges:true`);
    if (!txt.includes("read_only: true")) errors.push(`${comp}: missing read_only: true`);
  }
  const ha = readRel("deploy/compose/ha.yml");
  if (!/postgres:18[^@\n]*@sha256:[0-9a-f]{64}/.test(ha)) {
    errors.push("deploy/compose/ha.yml: postgres 18 must pin immutable sha256 digest");
  }
  if (!/seaweedfs:4\.53@sha256:[0-9a-f]{64}/.test(ha)) {
    errors.push("deploy/compose/ha.yml: seaweedfs 4.53 must pin immutable sha256 digest");
  }
  const composeEnv = {
    GRDR_API_TOKEN: "verify-placeholder-token",
    GRDR_ENROLL_TOKEN: "verify-placeholder-token",
    GRDR_POSTGRES_PASSWORD: "verify-placeholder-pass",
    GRDR_POSTGRES_DSN: "postgresql://grdr@postgres:5432/grdr?sslmode=verify-full",
  };
  for (const comp of ["deploy/compose/embedded.yml", "deploy/compose/ha.yml"]) {
    try {
      mustCommand("docker", ["compose", "-f", comp, "config", "-q"], composeEnv);
    } catch (err) {
      errors.push(`${comp}: ${err.message}`);
    }
  }
}

function checkHelmCharts(errors) {
  for (const chart of ["grdr-server", "grdr-node-sensor"]) {
    const base = `deploy/helm/${chart}`;
    const valuesTxt = readRel(`${base}/values.yaml`);
    if (/^\s*tag\s*:/m.test(valuesTxt)) errors.push(`${base}/values.yaml: tag field forbidden; pin digest only`);
    if (valuesTxt.includes(ZERO_DIGEST)) errors.push(`${base}/values.yaml: zero placeholder digest forbidden`);
    if (!valuesTxt.includes("imageRegistry:")) errors.push(`${base}/values.yaml: missing global.imageRegistry`);

    for (const full of walkFiles(join(ROOT, base, "templates"))) {
      const rel = relative(ROOT, full).replace(/\\/g, "/");
      const content = readFileSync(full, "utf8");
      if (content.includes("helm.sh/hook")) errors.push(`${rel}: Helm hooks are forbidden`);
      if (/\blookup\s+"/.test(content) || /\{\{-?\s*lookup\b/.test(content)) {
        errors.push(`${rel}: Helm lookup is forbidden`);
      }
      if (/kind:\s*CustomResourceDefinition\b/.test(content)) {
        errors.push(`${rel}: CRDs are forbidden in Helm charts`);
      }
      const relRefs = content.match(/\.Release\.[A-Za-z0-9_]+/g) ?? [];
      for (const r of relRefs) {
        if (r !== ".Release.Name" && r !== ".Release.Namespace") {
          errors.push(`${rel}: disallowed .Release field ${r}`);
        }
      }
    }

    mustCommand("helm", ["lint", base, "--set", `image.digest=${TEST_DIGEST}`]);
  }

  const embeddedOut = mustCommand("helm", [
    "template", "test", "deploy/helm/grdr-server",
    "--set", `image.digest=${TEST_DIGEST}`,
    "--set", "profile=embedded",
    "--set", "storage.embedded.persistence.enabled=false",
    "--set", "ingress.enabled=true", "--set", "ingress.host=app.example.invalid",
    "--set", "ingress.tls.secretName=api-tls",
    "--set", "operator.ingress.enabled=true", "--set", "operator.ingress.host=ops.example.invalid",
    "--set", "operator.ingress.tls.secretName=ops-tls",
    "--set", "global.imageRegistry=mirror.example.invalid/grdr",
  ]);
  if (!embeddedOut.includes("kind: StatefulSet")) errors.push("grdr-server embedded profile must render StatefulSet");
  if (!embeddedOut.includes("mirror.example.invalid/grdr/grdr-server@sha256:")) {
    errors.push("grdr-server global.imageRegistry override did not apply to digest-pinned image");
  }
  if (!embeddedOut.includes("name: test-grdr-server-operator") || !embeddedOut.includes("OverviewService/GetHealth")) {
    errors.push("grdr-server rendered output missing D-70 operator Service or GetHealth probe");
  }
  if (!embeddedOut.includes("runAsNonRoot: true") || !embeddedOut.includes("readOnlyRootFilesystem: true")) {
    errors.push("grdr-server rendered output must enforce Pod Security restricted fields");
  }
  if (!embeddedOut.includes("emptyDir: {}")) {
    errors.push("grdr-server embedded without persistence must mount emptyDir data volume");
  }

  const haOut = mustCommand("helm", [
    "template", "test", "deploy/helm/grdr-server",
    "--set", `image.digest=${TEST_DIGEST}`,
    "--set", "profile=ha",
    "--set", "pkcs11Sidecar.enabled=true",
    "--set", `pkcs11Sidecar.image.digest=${TEST_DIGEST}`,
    "--set", "autoscaling.enabled=true",
  ]);
  if (!haOut.includes("kind: Deployment") || !haOut.includes("kind: PodDisruptionBudget")) {
    errors.push("grdr-server ha profile must render Deployment and PodDisruptionBudget");
  }

  const sensorOut = mustCommand("helm", [
    "template", "sensor", "deploy/helm/grdr-node-sensor",
    "--set", `image.digest=${TEST_DIGEST}`,
    "--set", "mode=hybrid", "--set", "sidecar.enabled=true",
    "--set", "sidecar.validatingPolicy.enabled=true", "--set", "sidecar.mutatingWebhook.enabled=true",
    "--set", "sidecar.mutatingWebhook.certManagerInjectCAFrom=grdr-sensor/webhook-cert",
  ]);
  if (!sensorOut.includes("kind: DaemonSet") || !sensorOut.includes("kind: ValidatingAdmissionPolicy") || !sensorOut.includes("failurePolicy: Ignore")) {
    errors.push("grdr-node-sensor hybrid mode missing DaemonSet, ValidatingAdmissionPolicy, or Ignore webhook");
  }

  assertCommandFails("helm", ["template", "t", "deploy/helm/grdr-server"], "empty image.digest", errors);
  assertCommandFails("helm", ["template", "t", "deploy/helm/grdr-server", "--set", `image.digest=${ZERO_DIGEST}`], "zero image.digest", errors);
  assertCommandFails("helm", ["template", "t", "deploy/helm/grdr-server", "--set", `image.digest=${TEST_DIGEST}`, "--set", "profile=embedded", "--set", "upgrade.strategy=Recreate"], "embedded Recreate", errors);
  assertCommandFails("helm", ["template", "t", "deploy/helm/grdr-server", "--set", `image.digest=${TEST_DIGEST}`, "--set", "storage.database.sslMode=require"], "sslMode=require", errors);
  assertCommandFails("helm", ["template", "t", "deploy/helm/grdr-server", "--set", `image.digest=${TEST_DIGEST}`, "--set", "extraEnv[0].name=GRDR_API_TOKEN", "--set", "extraEnv[0].value=x"], "extraEnv secret override", errors);
  assertCommandFails("helm", ["template", "t", "deploy/helm/grdr-server", "--set", `image.digest=${TEST_DIGEST}`, "--set", "extraEnv[0].name=LD_PRELOAD", "--set", "extraEnv[0].value=/tmp/evil.so"], "extraEnv LD_PRELOAD", errors);
  assertCommandFails("helm", ["template", "t", "deploy/helm/grdr-server", "--set", `image.digest=${TEST_DIGEST}`, "--set", "extraEnv[0].name=SSL_CERT_FILE", "--set", "extraEnv[0].value=/tmp/evil.pem"], "extraEnv SSL_CERT_FILE", errors);
  assertCommandFails("helm", ["template", "t", "deploy/helm/grdr-server", "--set", `image.digest=${TEST_DIGEST}`, "--set", "networkPolicy.allowEgressCidrs={169.254.169.254/32}"], "server IMDS egress CIDR", errors);
  assertCommandFails("helm", ["template", "t", "deploy/helm/grdr-server", "--set", `image.digest=${TEST_DIGEST}`, "--set", "networkPolicy.allowEgressCidrs={::/0}"], "server ::/0 egress CIDR", errors);
  assertCommandFails("helm", ["template", "t", "deploy/helm/grdr-node-sensor", "--set", `image.digest=${TEST_DIGEST}`, "--set", "sidecar.enabled=true", "--set", "sidecar.mutatingWebhook.enabled=true"], "webhook missing CA", errors);
  assertCommandFails("helm", ["template", "t", "deploy/helm/grdr-node-sensor", "--set", `image.digest=${TEST_DIGEST}`, "--set", "networkPolicy.allowEgressCidrs={169.254.169.254/32}"], "sensor IMDS egress CIDR", errors);
  assertCommandFails("helm", ["template", "t", "deploy/helm/grdr-node-sensor", "--set", `image.digest=${TEST_DIGEST}`, "--set", "networkPolicy.allowEgressCidrs={\"\"}"], "sensor empty egress CIDR", errors);
  assertCommandFails("helm", ["template", "t", "deploy/helm/grdr-node-sensor", "--set", `image.digest=${TEST_DIGEST}`, "--set", "networkPolicy.serverNamespace=", "--set", "networkPolicy.allowEgressCidrs={}"], "sensor empty networkPolicy targets", errors);
}

function checkTerraformModules(errors) {
  const clouds = {
    aws: { pgDefault: '"18"', k8sId: "aws_eks_pod_identity_association", kms: "enable_key_rotation", bucketVer: "aws_s3_bucket_versioning", extra: 'mode = "COMPLIANCE"' },
    gcp: { pgDefault: '"POSTGRES_18"', k8sId: "workloadIdentityUser", kms: "rotation_period", bucketVer: "versioning", extra: "is_locked        = true" },
    azure: { pgDefault: '"18"', k8sId: "azurerm_federated_identity_credential", kms: "rotation_policy", bucketVer: "versioning_enabled", extra: "key_size     = 4096" },
  };
  for (const [cloud, reqs] of Object.entries(clouds)) {
    const dir = `deploy/terraform/${cloud}`;
    for (const file of ["versions.tf", "variables.tf", "main.tf", "outputs.tf", "tests/module.tftest.hcl"]) {
      const p = `${dir}/${file}`;
      if (!existsSync(join(ROOT, p))) errors.push(`missing Terraform file: ${p}`);
    }
    const vars = readRel(`${dir}/variables.tf`);
    const main = readRel(`${dir}/main.tf`);
    if (!vars.includes(reqs.pgDefault)) errors.push(`${dir}/variables.tf: missing PostgreSQL 18 default`);
    if (!main.includes(reqs.k8sId)) errors.push(`${dir}/main.tf: missing workload identity resource (${reqs.k8sId})`);
    if (!main.includes(reqs.kms)) errors.push(`${dir}/main.tf: missing KMS rotation config`);
    if (!main.includes(reqs.bucketVer)) errors.push(`${dir}/main.tf: missing object versioning config`);
    if (!main.includes(reqs.extra)) errors.push(`${dir}/main.tf: missing required hardening (${reqs.extra})`);
    if (!main.includes("distinct_operator_host")) errors.push(`${dir}/main.tf: missing D-70 distinct_operator_host check`);
    for (const iacBin of ["tofu", "terraform"]) {
      if (tryCommand(iacBin, ["-chdir=" + dir, "validate"]) !== null) break;
    }
  }
}

function checkPackagingUnits(errors) {
  for (const svc of [
    "deploy/packaging/systemd/grdr-daemon.service",
    "deploy/packaging/systemd/grdr-server.service",
    "deploy/packaging/systemd/user/grdr-daemon.service",
  ]) {
    const txt = readRel(svc);
    if (!txt.includes("[Unit]") || !txt.includes("[Service]") || !txt.includes("[Install]")) {
      errors.push(`${svc}: missing required systemd sections`);
    }
    const execLine = txt.match(/^ExecStart=(.+)$/m);
    if (!execLine || !execLine[1].startsWith("/")) errors.push(`${svc}: ExecStart must be an absolute path`);
    if (!txt.includes("NoNewPrivileges=true")) errors.push(`${svc}: missing NoNewPrivileges=true`);
  }
  const decideSock = readRel("deploy/packaging/systemd/grdr-decide.socket");
  if (!decideSock.includes("SocketMode=0660") || decideSock.includes("SocketMode=0666")) {
    errors.push("deploy/packaging/systemd/grdr-decide.socket: must enforce SocketMode=0660");
  }
  const sysusers = readRel("deploy/packaging/systemd/sysusers.d/grdr.conf");
  if (!sysusers.includes("u grdr 65532") || !sysusers.includes("u grdr-engine")) {
    errors.push("deploy/packaging/systemd/sysusers.d/grdr.conf: missing grdr or grdr-engine accounts");
  }
  for (const nfpm of ["deploy/packaging/deb/nfpm.yaml", "deploy/packaging/rpm/nfpm.yaml"]) {
    const txt = readRel(nfpm);
    if (!txt.includes("bubblewrap") || !txt.includes("socat") || !txt.includes("owner: grdr")) {
      errors.push(`${nfpm}: missing bubblewrap/socat weak deps or grdr ownership`);
    }
  }
  const wxs = readRel("deploy/packaging/wix/Package.wxs");
  if (!wxs.includes('Hidden="yes"') || wxs.includes("MsiHiddenProperties") || !wxs.includes("Administrators")) {
    errors.push("deploy/packaging/wix/Package.wxs: missing Hidden properties, no duplicate MsiHiddenProperties, or DataDir ACLs");
  }
  const launchdDaemon = readRel("deploy/packaging/launchd/com.guardrailshq.grdr.daemon.plist");
  if (launchdDaemon.includes("--config")) {
    errors.push("deploy/packaging/launchd/com.guardrailshq.grdr.daemon.plist: remove unsupported --config flag");
  }
}

function main() {
  const errors = [];
  for (const rel of REQUIRED_FILES) {
    if (!existsSync(join(ROOT, rel))) errors.push(`missing required artifact: ${rel}`);
  }
  const allDeployFiles = walkFiles(join(ROOT, "deploy")).map((f) => relative(ROOT, f).replace(/\\/g, "/"));
  const targetFiles = [...new Set([...REQUIRED_FILES, ...allDeployFiles, "scripts/verify-deploy-artifacts.mjs"])].filter((p) =>
    existsSync(join(ROOT, p)),
  );

  checkHygiene(errors, targetFiles);
  checkTomlAndSchemas(errors, findPython());
  checkContainersAndCompose(errors);
  checkHelmCharts(errors);
  checkTerraformModules(errors);
  checkPackagingUnits(errors);

  if (errors.length > 0) {
    for (const e of errors) process.stderr.write(`ERROR: ${e}\n`);
    process.exitCode = 1;
    return;
  }
  process.stdout.write(`verify-deploy-artifacts: PASS (${targetFiles.length} artifacts verified)\n`);
}

main();
