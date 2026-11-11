# Deployment models, packaging and release engineering for an open-source AIDR platform

_Researched 2026-11-09_

Method note: the web-search budget for this run was exhausted before my first query, so nothing here comes from a search engine. Everything marked **[V]** was read directly today from a primary source (vendor docs, spec repos, GitHub API). Items marked **[R]** are recalled from pre-June-2026 knowledge and were not re-verified; treat them as medium confidence.

## TL;DR

- **Both named competitors ship an endpoint agent plus machine-wide agent hooks, and both are Windows x64 + macOS only.** BeyondTrust Pathfinder: MSI (x64, no ARM64) and a universal macOS pkg with an Endpoint Security extension, a Network Extension transparent proxy, a tenant root CA for TLS inspection, and `pre_tool_use` hooks that **fail open**. Microsoft Defender: discovery is built into the existing sensor, runtime protection is Windows-only preview. Linux endpoints, Windows ARM64, servers, CI and Kubernetes are whitespace. [V]
- **Hooks are deployable as managed policy today.** Claude Code reads `managed-settings.json` + `managed-settings.d/*.json` from system paths, a macOS `com.anthropic.claudecode` plist, and `HKLM\SOFTWARE\Policies\ClaudeCode`; Codex reads `/etc/codex/requirements.toml`, `%ProgramData%\OpenAI\Codex\requirements.toml` and `com.openai.codex:requirements_toml_base64`. A drop-in file is the cleanest integration point. [V]
- **macOS needs MDM for a silent install.** `com.apple.system-extension-policy` is device-channel, user-approved-MDM only, forbidden under User Enrollment; transparent-proxy profiles cannot be installed from the CLI; Screen Capture and input monitoring can never be granted by profile. The Endpoint Security entitlement must be requested from Apple. [V]
- **macOS 15+ gives uninstall protection for free**: `NonRemovableSystemExtensions` and `NonRemovableFromUISystemExtensions`. macOS 26 added declarative `package` and `app.managed`; macOS 27 added declarative `webcontent-filter.plugin`. [V]
- **Windows signing has two tiers.** User-mode: Azure Artifact Signing (renamed from Trusted Signing), organisations in a fixed country list, individuals only US/Canada. Kernel: EV certificate + Hardware Dev Center attestation. The new user-mode Windows endpoint security platform is gated behind MVI, which requires a commercial real-time anti-malware product. [V]
- **Kubernetes baseline is 1.34 to 1.37**; user namespaces and MutatingAdmissionPolicy went GA in 1.36. Helm 4.3.1 is current (server-side apply default, install by OCI digest); Helm 3.22.1 still receives releases. [V]
- **kubernetes-sigs/agent-sandbox is 1.0** (v1.0.0 on 2026-08-28, APIs at `v1beta1`, v1.0.10 current). It is an orchestrator over gVisor/Kata RuntimeClasses, which means a host eBPF DaemonSet sees little inside those sandboxes. [V]
- **Zarf reached 1.0.0 today** (2026-11-10 UTC): single-file air-gap packages, built-in registry, cosign verification, SBOMs. [V]
- **Marketplaces conflict on architecture**: EKS add-ons require amd64 + arm64, no Helm hooks or `lookup`, CRDs in a separate add-on; Azure Kubernetes apps accept Linux AMD64 only, packaged as CNAB. [V]
- **Supply chain defaults**: cosign 3.1.4 (bundle format on by default), GitHub artifact attestations (SLSA Build L2, L3 via reusable workflows), CycloneDX 1.7.2. EU CRA reporting has applied to manufacturers since 2026-09-11 (24 h / 72 h); open-source stewards from 2027-12-11. [V]
- **FIPS in Rust is weaker than in Go**: Go has a native validated module (CMVP #5247); `aws-lc-rs` documents its FIPS 3.x module as submitted, static build on Linux only. [V]
- **Staged rollout is table stakes after July 2024**: Defender exposes Beta, Preview, Staged (~10%), Broad and a 48-hour "Critical: Time Delay" channel, plus rollback; MVI 3.0 mandates gradual rings. [V]

## Findings

### 1. What competitors actually deploy (the bar to clear)

**BeyondTrust AI Agent Security / Pathfinder** [V, fetched 2026-11-09]
- Windows 11 / Server 2022+ x64 only ("Windows on Arm is not supported"); macOS 14, 15, 26 (current + two previous). No Linux. https://docs.beyondtrust.com/bt-docs/docs/ai-agent-security
- Windows: `msiexec /i pathfinder-agent-VERSION-x86_64.msi /qn BACKEND_URL=... DEPLOYMENT_KEY=...`; the MSI masks the key in logs. Tenant root CA goes into LocalMachine Trusted Root, pushed by GPO/Intune or self-installed; the agent re-checks every minute and restores it. https://docs.beyondtrust.com/bt-docs/docs/windows-manual-install
- macOS: `pathfinder-sysext-<version>-darwin-universal.pkg` installs `PathfinderEnforcement.app` with an Endpoint Security extension and a Network Extension filter. One device-level profile trusts the CA, approves both extensions, configures the transparent proxy and grants Full Disk Access. Without MDM the user approves five things by hand, and CA trust must be done at the local console, not SSH. https://docs.beyondtrust.com/bt-docs/docs/mac-manual-install
- Enrolment: console-minted deployment keys, 7-day default expiry, one-time or multi-use; `--key-file` preferred over `--key` (process list exposure); zero-touch via `/var/lib/pathfinder/enrollment.plist` (root:wheel 0600).
- Hooks: installer writes machine-wide managed hooks for Claude Code, Codex, Cursor and Copilot; `pathfinder-agent hook install --all-providers`; `--print` renders config so MDM can own the files. Only `pre_tool_use` is named. **Hooks fail open**; the endpoint is then shown as Degraded. https://docs.beyondtrust.com/bt-docs/docs/coding-hooks-install-and-verify
- Windows security tools must allowlist the installer and CA. This is a direct EDR-coexistence cost.

**Microsoft Defender + Agent 365** [V]
- Agent 365 GA 2026-05-01, per-user licence, E5 expected. Registry is tenant-centric (Copilot Studio, partner agents, uploaded ZIP manifests); "unmanaged agents" is a counter, not an enforcement point. https://learn.microsoft.com/en-us/microsoft-agent-365/overview
- Local discovery needs no extra deployment: Defender AV platform `4.18.26090.9`+ (Windows) or MDE `101.26072.0017`+ (macOS), active mode with real-time protection, Plan 2 licence, commercial cloud only (no sovereign clouds). Around 58 agents listed; MCP config for about half. Data lands in the `AgentsInfo` hunting table with `autoApprove`, `trustedProcess`, `localMcps`. https://learn.microsoft.com/en-us/defender-endpoint/discover-local-ai-agents
- Runtime protection (preview, **Windows only**): `Set-MpPreference -AiAgentProtection Audit|Block` (agent-native event inspection for Claude Code, Codex CLI, Copilot CLI) and `-AiAgentNetworkInspection` (LLM traffic; **no support for certificate pinning or HTTP/3**). Intune has a profile only for the first; the second needs a PowerShell platform script. Terminals must be restarted. Scope is prompt-injection detection, not general policy. https://learn.microsoft.com/en-us/defender-endpoint/configure-ai-agent-runtime-protection

**Ona (ex-Gitpod)** deploys CrowdStrike Falcon as a sidecar into every cloud dev environment by org policy (1 to 3% CPU, 200 to 500 MB RAM) and ships "Veto", an LSM-based executable deny list keyed on content hash. https://ona.com/docs/ona/organizations/policies/security-agents , https://ona.com/docs/ona/guardrails/veto [V]

### 2. Endpoint side

**In-agent hook delivery (verified paths)**

| Agent | File | MDM / registry | Refresh |
|---|---|---|---|
| Claude Code | `/Library/Application Support/ClaudeCode/`, `/etc/claude-code/`, `C:\Program Files\ClaudeCode\` holding `managed-settings.json`, `managed-settings.d/*.json`, `managed-mcp.json` | `com.anthropic.claudecode` plist; `HKLM\SOFTWARE\Policies\ClaudeCode` value `Settings` | files reload on change; MDM every 30 min; server-managed hourly |
| Codex | `/etc/codex/requirements.toml`, `%ProgramData%\OpenAI\Codex\requirements.toml` | `com.openai.codex:requirements_toml_base64` | at launch |

Sources: https://code.claude.com/docs/en/managed-settings , https://developers.openai.com/codex/enterprise/managed-configuration . Relevant locks: `allowManagedHooksOnly`, `allowManagedMcpServersOnly`, `forceRemoteSettingsRefresh` (fail-closed start), `requiredMinimumVersion`. Caveats: a local admin can edit file-based policy; `/etc/claude-code` is user-writable under WSL; an unparseable managed file **blocks Claude Code from starting**, so a bad drop-in from us is an outage. Only server-managed settings reach vendor cloud sessions. Cursor's hooks doc URL returned 404 today.

**macOS** [V, apple/device-management Release-v27.2, 2026-10-27]
- `com.apple.system-extension-policy`: `AllowedSystemExtensions`, `AllowedTeamIdentifiers`, `AllowedSystemExtensionTypes` (`EndpointSecurityExtension`, `NetworkExtension`, `DriverExtension`), `RemovableSystemExtensions` (12.0), `NonRemovableSystemExtensions` and `NonRemovableFromUISystemExtensions` (15.0). Removing the profile deactivates the extension (11.3+).
- `com.apple.TCC.configuration-profile-policy`: `SystemPolicyAllFiles` is grantable by code requirement; `ScreenCapture`, `ListenEvent` and `Microphone` can only be denied or delegated to a standard user.
- `com.apple.webcontent-filter` (`FilterDataProviderBundleIdentifier`, `FilterSockets`, `FilterPackets`) or `com.apple.vpn.managed` with `VPNType=TransparentProxy` for network interception; `com.apple.servicemanagement` (13.0) with a `TeamIdentifier` rule to lock background items; a certificate payload if TLS inspection is used.
- Endpoint Security client entitlement must be requested from Apple; notarisation requires `notarytool` and covers apps, disk images and flat pkgs. https://developer.apple.com/documentation/bundleresources/entitlements/com.apple.developer.endpoint-security.client
- Homebrew casks must pass Gatekeeper without bypass. https://docs.brew.sh/Acceptable-Casks

**Windows**
- Artifact Signing: managed HSM (FIPS 140-3 L3), Basic/Premium SKUs, digest signing; public trust for organisations in US, CA, EU, UK, AU, NZ, JP, KR, SG, CH, NO, IL; individuals US/CA only. https://learn.microsoft.com/en-us/azure/artifact-signing/quickstart [V]
- Kernel drivers: attestation or WHCP submission needs a Partner Center account with an EV certificate. https://learn.microsoft.com/en-us/windows-hardware/drivers/dashboard/code-signing-reqs [V]
- MVI requires a commercially available real-time anti-malware product, industry reputation, NDA, Trusted Signing, and Safe Deployment Practices; the user-mode endpoint security platform went to MVI partners in private preview in July 2025. Its November 2026 status is unverified. https://learn.microsoft.com/en-us/defender-xdr/virus-initiative-criteria [V]
- Distribution: Intune Win32 (`.intunewin`) or MSI line-of-business, Configuration Manager, GPO software install, winget manifest with silent switches. [R]

**Linux**: eBPF with CO-RE; Tetragon requires kernel 4.19+ with BTF and recommends 5.10+ on arm64. https://github.com/cilium/tetragon [V]. Signed apt/yum repositories plus a static musl binary. [R]

**Enrolment, updates, tamper protection, VDI**
- Fleet: `fleetctl package --type=pkg|msi|deb|rpm --fleet-url --enroll-secret [--arch=arm64]`; secret moved to the OS keystore; per-component channels (`--orbit-channel` etc., `stable`/`edge`) over TUF; optional one-time device-bound secrets on Apple MDM. https://fleetdm.com/docs/using-fleet/enroll-hosts [V]
- Elastic: uninstall requires a per-policy uninstall token; paid tier. https://www.elastic.co/docs/solutions/security/configure-elastic-defend/prevent-elastic-agent-uninstallation [V]
- Defender channels and rollback: https://learn.microsoft.com/en-us/defender-endpoint/manage-gradual-rollout [V]
- Non-persistent VDI: never onboard the golden image (duplicate sensor GUID); enrol from a startup script after the final hostname; choose single-entry or multi-entry device model; first report can lag 3 to 4 hours. https://learn.microsoft.com/en-us/defender-endpoint/configure-endpoints-vdi [V]

### 3. Server side

- **Kubernetes**: supported upstream lines 1.34 to 1.37 (1.38 in beta); k3s v1.37.2+k3s1 and RKE2 v1.37.2+rke2r1 track it. https://kubernetes.io/releases/ [V]
- **Helm 4**: SSA default for new releases, kstatus waits, `oci://...@sha256:` installs, Wasm plugins, `--atomic` renamed `--rollback-on-failure`. https://helm.sh/docs/overview/ [V]. AWS still validates with Helm 3.19+.
- **AWS Marketplace containers**: images and charts only in Marketplace-owned ECR; non-root by default; no hard-coded secrets or password auth; image refs only in `values.yaml`; no fields that accept secrets (take Secret names). EKS add-on: amd64 + arm64, no hooks, no `lookup`, only `Release.Name/Namespace`, CRDs split out, must include a Deployment or DaemonSet, no BYOL, IRSA or Pod Identity, 45 days to certify new Kubernetes versions. Images must not carry in-toto attestation layers. https://docs.aws.amazon.com/marketplace/latest/userguide/container-product-policies.html [V]
- **Azure Marketplace Kubernetes apps**: Helm-based, CNAB bundle in ACR, all images by digest, nothing downloaded at runtime, Linux AMD64 only, AKS or Arc (one per offer), delivered as a cluster extension. https://learn.microsoft.com/en-us/partner-center/marketplace-offers/azure-container-technical-assets-kubernetes [V]
- **GKE Autopilot** blocks privileged workloads unless on a Google-managed partner allowlist. https://docs.cloud.google.com/kubernetes-engine/docs/resources/autopilot-partners [V]
- **Air gap**: k3s offers image tarballs in `/var/lib/rancher/k3s/agent/images/`, a private registry, or the embedded Spegel mirror; SELinux RPM first. https://docs.k3s.io/installation/airgap [V]. Zarf 1.0 adds an in-cluster registry, a mutating webhook that rewrites image paths, and Flux/Gitea support. https://github.com/zarf-dev/zarf [V]
- **IaC**: OpenTofu 1.13.9 (MPL-2.0) and Terraform 1.17.1 (BUSL) are both current; modules must work on both. [V]
- **FIPS**: https://go.dev/doc/security/fips140 ; https://github.com/aws/aws-lc-rs [V]

### 4. Agent workloads off the laptop

- **Dev containers**: a Feature is `devcontainer-feature.json` + `install.sh` distributed as an OCI artifact; it can request `privileged`, `capAdd`, `securityOpt`, `mounts`, `entrypoint` and lifecycle commands. Nothing in the spec lets an organisation force a Feature. https://containers.dev/implementors/features/ [V]. Codespaces policy can restrict the **base image**, which is the real enforcement lever. https://docs.github.com/en/codespaces/managing-codespaces-for-your-organization/restricting-the-base-image-for-codespaces [V]
- **Vendor-hosted agents**: Copilot cloud agent runs `.github/workflows/copilot-setup-steps.yml` (job name fixed, default branch only) on hosted, larger or self-hosted runners. Its firewall covers only processes started through the agent's Bash tool, not MCP servers or setup steps. https://docs.github.com/en/copilot/how-tos/use-copilot-agents/coding-agent/customize-the-agent-environment [V]. Claude Code cloud sessions receive only server-managed settings; self-hosted runner images read the managed file. [V]
- **CI**: `anthropics/claude-code-action` (v1.0.271) accepts `settings`, `claude_args`, `plugins` inputs. `step-security/harden-runner` (v2.22.4) is the reference pattern: first step of a job, `egress-policy: audit|block`; free for public repos on hosted runners, paid for self-hosted and ARC, where it is a silent no-op. [V]
- **Kubernetes**: agent-sandbox CRDs `Sandbox`, `SandboxTemplate`, `SandboxClaim`, `SandboxWarmPool`; Kubernetes 1.29+ recommended; conversion webhooks removed in 1.0; Claim name/UID exposed as pod metadata; optional Sandbox Router reverse proxy. https://github.com/kubernetes-sigs/agent-sandbox [V]
- **Serverless**: Lambda external extensions live in `/opt/extensions/` via layers or baked into images, up to 10 per function, 250 MB unzipped total, share the function's IAM role, billed per ms. https://docs.aws.amazon.com/lambda/latest/dg/lambda-extensions.html [V]. Cloud Run allows up to 10 containers per instance, sidecars on localhost with shared in-memory volumes. https://docs.cloud.google.com/run/docs/deploying [V]

### 5. Release engineering

- cosign 3.x: `--bundle` required, OCI 1.1 referrers for container signatures, `--trusted-root` for offline verification. https://github.com/sigstore/cosign/releases [V]
- GitHub artifact attestations: public repos use Sigstore public good (transparency log), private repos use GitHub's instance without a public log; `gh attestation verify`. https://docs.github.com/en/actions/concepts/security/artifact-attestations [V]
- cargo-dist v0.34.0 emits shell, PowerShell, npm, Homebrew and MSI installers; `awslabs/tough` v0.24.0 is a maintained Rust TUF client; syft v1.57.1 for SBOMs. [V]
- CRA: https://digital-strategy.ec.europa.eu/en/policies/cra-reporting [V]

## Matrix: deployment model catalogue

| Model | What runs where | Reference topology | Prerequisites |
|---|---|---|---|
| 1. Solo, local-only | One static binary: sensor + hook shim + embedded store + local console (Rune desktop app) | Single process, loopback API, no network egress | User install; no MDM; hooks-only plus optional OS extension approved by hand |
| 2. Solo with cloud | Same sensor; control plane is our SaaS free tier | Sensor to SaaS over mTLS/443 | Enrolment key via device-code login; outbound 443 |
| 3. Small-team self-host | Docker Compose or the single binary in `server` mode with SQLite/Postgres; 5 to 200 sensors | One VM, Caddy/ACME TLS, object storage optional | 2 vCPU / 4 GB VM, DNS name, MDM optional |
| 4. Enterprise self-host | Helm chart: API, ingest, policy, detection, gateway (MCP/LLM), console; managed Postgres, object store, queue; node DaemonSet and sidecar injector charts separate | Multi-AZ on EKS/GKE/AKS; ingest behind Gateway API; HPA on ingest; PDBs; NetworkPolicy default-deny | Kubernetes 1.34+, OIDC IdP, cert-manager or own PKI, external secrets, Terraform/OpenTofu module, GitOps (Flux/Argo) |
| 5. Our multi-tenant SaaS | Cell-based control plane, tenant ID on every row and stream, per-tenant keys, regional cells | Region to cell to shared services; per-tenant update rings | SOC 2 scope, CRA manufacturer duties, status and SDP process |
| 6. MSP multi-tenant | As 4 or 5 with parent/child tenants, delegated RBAC, per-customer enrolment keys and rings | MSP console over N tenant cells or namespaces | Tenant-scoped API tokens, Terraform provider, white-label config |
| 7. Air-gapped | Zarf package or OCI tarball onto k3s/RKE2; local TUF mirror; offline rule/model bundles | Single enclave; registry mirror; no call-home; sneakernet updates | Offline cosign verification with pinned trusted root; FIPS build flavour; local model or no LLM detection |
| 8. Embedded in a vendor product | Core as Rust library + C ABI + event schema; vendor's own signed sensor hosts it, or we ingest the vendor's telemetry | Vendor agent to vendor cloud to our detection library or sidecar service | Stable ABI and schema versioning, permissive licence, no second system extension |

## Weak points, gaps and risks

- **macOS without MDM is a degraded product.** System extension approval, transparent proxy, Full Disk Access and CA trust all need a profile or manual clicks. Solo users will not do five approvals.
- **Windows kernel access is closed to a new open-source project.** EV certificate plus Partner Center is possible; the MVI-gated user-mode platform is not, absent a commercial AV. Plan for ETW plus hooks plus user-mode proxy first.
- **TLS inspection is fragile and politically costly**: Defender's network path fails on pinning and HTTP/3; BeyondTrust needs a root CA and EDR allowlisting. Hooks are higher fidelity where they exist.
- **Fail-open hooks are bypassable by killing the service; fail-closed hooks or a malformed managed file stop developers working.** Both failure modes need explicit policy and health reporting.
- **Managed settings are admin-editable by local admins** and absent in vendor cloud sessions unless server-managed.
- **gVisor/Kata sandboxes blind host eBPF**; DaemonSet-only designs miss the workloads agent-sandbox was built for.
- **Marketplace rules conflict** (EKS add-on multi-arch, Azure AMD64 only, AWS rejects attestation layers in images, no Helm hooks).
- **Rust FIPS** depends on an AWS-LC validation whose certificate status I could not confirm; Windows and macOS FIPS builds are harder than Linux.
- **CRA**: operating a paid SaaS makes the operator a manufacturer with 24 h reporting duties now.

## Implications for our design

1. **One Rust binary, role-flagged** (`sensor`, `server`, `gateway`, `all-in-one`), static musl on Linux, universal on macOS, x64 + ARM64 on Windows. Models 1 to 4 are the same artefact at different scale. Ship Windows ARM64 and Linux desktop on day one: neither named competitor does.
2. **Three enforcement tiers that degrade gracefully**: hooks-only (no privileges), hooks + user-mode network proxy, hooks + OS sensor (ES/NE on macOS, eBPF-LSM on Linux, ETW then driver on Windows). Report the active tier per endpoint as a health field, as BeyondTrust does with "Hook enforcement: ready/degraded".
3. **Hook install as a subcommand with `--print`**, writing a single `managed-settings.d/50-<product>.json` drop-in for Claude Code and the Codex requirements file; validate JSON/TOML against the vendor schema before writing and keep the previous file for rollback. Emit ready-made mobileconfig, ADMX/registry and Intune/Jamf/Fleet templates so MDM can own the files.
4. **Fail mode is policy**: default fail-open with a loud Degraded state; allow fail-closed per group; pair with `forceRemoteSettingsRefresh`-style startup checks where vendors support them.
5. **macOS package**: one notarised universal pkg, app in `/Applications`, ES + NE extensions; a profile generator that outputs system-extension, TCC, filter/transparent-proxy, service-management and certificate payloads, with `NonRemovable*` keys on 15+. Apply for the Endpoint Security entitlement immediately; it is the longest lead item. Target the macOS 26 declarative `package` configuration for install.
6. **Enrolment**: short-lived keys (default 7 days, single or multi-use), never on argv, MSI property masked in logs, MDM-delivered enrolment file; exchange for a per-device mTLS identity; VDI mode that enrols at boot after rename and deduplicates by hostname.
7. **Updates**: TUF repository (use `tough`) that customers can mirror; channels nightly, beta, stable, LTS; server-side rings named like Defender's (Preview, Staged ~10%, Broad, Critical with 48 h delay); automatic rollback to the last healthy version; **content updates (rules, classifiers) staged separately from binaries**.
8. **Helm chart written to the strictest marketplace**: images only in `values.yaml`, by digest, `values.schema.json`, no hooks or `lookup`, CRDs in a separate chart, non-root, Secret names not values, amd64 + arm64. Publish as OCI and sign. Control plane must run under Pod Security "restricted"; the privileged node sensor is a separate chart and namespace.
9. **Kubernetes coverage in three forms**: DaemonSet (eBPF), sidecar/native-sidecar injected by admission, and an agent-sandbox integration that ships a `SandboxTemplate` with our sidecar and watches `Sandbox`/`SandboxClaim` objects as an inventory source. Use the sidecar form for gVisor/Kata, Autopilot, Fargate, Cloud Run; a Lambda layer for functions.
10. **Cloud dev and CI**: publish a dev container Feature, a hardened base image (for Codespaces image policy), a `copilot-setup-steps` snippet, and a GitHub Action that wraps any agent run and works on self-hosted and ARC runners for free.
11. **Air gap**: first-class Zarf package plus a plain OCI layout tarball; offline cosign verification; no licence server; FIPS flavour built on `aws-lc-rs` behind a feature flag.
12. **Release pipeline**: reusable GitHub workflow for SLSA Build L3 provenance, cosign 3 bundles on every artefact, CycloneDX 1.7 SBOM, attestations stored as OCI referrers rather than image layers, Artifact Signing for Windows, Developer ID + notarytool for macOS, signed apt/yum repos, winget and Homebrew manifests, reproducible-build check in CI.
13. **Embeddable core**: a library crate with C ABI and a versioned event schema so EDR vendors, who already hold ES entitlements, MVI membership and signed drivers, host our logic inside their sensor. Also support a "bring your own telemetry" mode with no sensor at all.

## Ideas worth stealing and whitespace

- BeyondTrust's **policy replay** against recorded activity before enforcing; `--print` for MDM-owned config; CA self-healing; health row per enforcement layer.
- Defender's `AgentsInfo` shape (`autoApprove`, `trustedProcess`, `localMcps`) as a compatibility target for export.
- Ona's **content-hash executable deny list in an LSM**, and org policy that injects a third-party security sidecar into every environment: ask Ona, Coder and Codespaces to list ours.
- harden-runner's audit-then-block baseline flow for CI.
- **Whitespace**: Linux developer endpoints; Windows ARM64; self-hosted and air-gapped operation; CI and Kubernetes agents under the same policy as laptops; enforcement that works without MDM; a free self-hosted runner action; an embeddable core for other EDRs.

## Could not verify / open questions

- Web search was unavailable; no independent confirmation of facts beyond the pages fetched.
- Cursor hook and enterprise distribution paths (docs URL 404). Copilot CLI and VS Code managed-hook locations.
- Current (late 2026) status and access terms of the Windows endpoint security platform outside MVI.
- AWS-LC-FIPS 3.x certificate status; Artifact Signing pricing; whether individual open-source maintainers outside US/Canada have any public-trust route.
- Google Cloud Marketplace Kubernetes listing rules; CrowdStrike, SentinelOne and Jamf/Kandji (now Iru)/Mosyle/Workspace ONE specific deployment guides (not fetched; generic MDM payloads assumed).
- Helm 3 end-of-support date (recalled as 2026-11-11, not re-read).
- Coder's agent governance features (docs path not found); DevPod appears stalled (last release 2025-06, last push 2025-11).
- Whether Apple grants the Endpoint Security entitlement to an open-source project distributing through a foundation or individual account.

## Sources

- https://docs.beyondtrust.com/bt-docs/docs/ai-agent-security (and `/deploy-ais-agent`, `/windows-manual-install`, `/mac-manual-install`, `/coding-hooks-install-and-verify`), fetched 2026-11-09
- https://learn.microsoft.com/en-us/microsoft-agent-365/overview (2026-08-19, updated 2026-10-23); `/admin/agent-registry-overview` (2026-09-21)
- https://learn.microsoft.com/en-us/defender-endpoint/discover-local-ai-agents (2026-11-02); `/configure-ai-agent-runtime-protection` (2026-09-25); `/ai-agent-runtime-protection-overview`; `/ai-agent-support-matrix`; `/manage-gradual-rollout`; `/configure-endpoints-vdi`
- https://learn.microsoft.com/en-us/defender-xdr/security-for-ai/get-started-defender-security-for-ai (2026-10-30)
- https://learn.microsoft.com/en-us/azure/artifact-signing/overview and `/quickstart`
- https://learn.microsoft.com/en-us/windows-hardware/drivers/dashboard/code-signing-reqs
- https://learn.microsoft.com/en-us/defender-xdr/virus-initiative-criteria
- https://blogs.windows.com/windowsexperience/2025/06/26/the-windows-resiliency-initiative-building-resilience-for-a-future-ready-enterprise/ (2025-06-26, may be stale)
- https://github.com/apple/device-management (Release-v27.2, 2026-10-27): `mdm/profiles/com.apple.system-extension-policy.yaml`, `com.apple.TCC.configuration-profile-policy.yaml`, `com.apple.webcontent-filter.yaml`, `com.apple.servicemanagement.yaml`, `declarative/declarations/configurations/*`
- https://support.apple.com/guide/deployment/system-and-kernel-extensions-in-macos-depa5fb8376f/web
- https://developer.apple.com/documentation/security/notarizing-macos-software-before-distribution
- https://code.claude.com/docs/en/settings and `/managed-settings`
- https://developers.openai.com/codex/enterprise/managed-configuration
- https://docs.github.com/en/copilot/how-tos/use-copilot-agents/coding-agent/customize-the-agent-environment and `/customize-the-agent-firewall`
- https://docs.github.com/en/actions/concepts/security/artifact-attestations
- https://helm.sh/docs/overview/ (Helm 4.3.1)
- https://kubernetes.io/releases/ ; `/docs/concepts/workloads/pods/user-namespaces/` ; `/docs/reference/access-authn-authz/mutating-admission-policy/`
- https://github.com/kubernetes-sigs/agent-sandbox (v1.0.0 2026-08-28; v1.0.10 2026-11-06)
- https://github.com/zarf-dev/zarf (v1.0.0, 2026-11-10 UTC); https://docs.k3s.io/installation/airgap
- https://docs.aws.amazon.com/marketplace/latest/userguide/container-product-policies.html
- https://learn.microsoft.com/en-us/partner-center/marketplace-offers/azure-container-technical-assets-kubernetes
- https://docs.cloud.google.com/kubernetes-engine/docs/resources/autopilot-partners ; https://docs.cloud.google.com/run/docs/deploying
- https://docs.aws.amazon.com/lambda/latest/dg/lambda-extensions.html and `/extensions-configuration.html`
- https://containers.dev/implementors/features/
- https://docs.github.com/en/codespaces/managing-codespaces-for-your-organization/restricting-the-base-image-for-codespaces
- https://ona.com/docs/ona/organizations/policies/security-agents ; https://ona.com/docs/ona/guardrails/veto
- https://fleetdm.com/docs/using-fleet/enroll-hosts
- https://www.elastic.co/docs/solutions/security/configure-elastic-defend/prevent-elastic-agent-uninstallation
- https://github.com/step-security/harden-runner (v2.22.4); https://github.com/anthropics/claude-code-action (v1.0.271)
- https://github.com/sigstore/cosign/releases (v3.0.1 2025-10-08; v3.1.4 2026-10-20)
- https://go.dev/doc/security/fips140 ; https://github.com/aws/aws-lc-rs (v1.19.0)
- https://github.com/cilium/tetragon (v1.8.0); https://github.com/axodotdev/cargo-dist (v0.34.0); https://github.com/awslabs/tough (v0.24.0)
- https://github.com/opentofu/opentofu (v1.13.9); https://github.com/hashicorp/terraform (v1.17.1)
- https://digital-strategy.ec.europa.eu/en/policies/cra-reporting
- https://docs.brew.sh/Acceptable-Casks

## Independent verification

_Checked 2026-11-09 by a separate fact-checker. Web search was unavailable (budget exhausted), so every verdict rests on a direct read of primary documentation or source code (GitHub API), not on search results. Nothing above this heading was changed._

| # | Claim | Verdict | Note | Source |
|---|---|---|---|---|
| 1 | `com.apple.system-extension-policy` is device-channel only, needs user-approved MDM, is forbidden under User Enrollment, and gained `NonRemovableSystemExtensions` / `NonRemovableFromUISystemExtensions` in macOS 15.0; silent approval needs MDM | confirmed | Schema reads `devicechannel: true`, `userchannel: false`, `userapprovedmdm: true`, `allowmanualinstall: false`, `userenrollment.mode: forbidden`; both NonRemovable keys `introduced: '15.0'`. `allowmanualinstall: false` means the profile cannot be installed by hand either. | https://github.com/apple/device-management/blob/release/mdm/profiles/com.apple.system-extension-policy.yaml |
| 2 | The Endpoint Security client entitlement must be requested from Apple; without it the client fails to initialise | confirmed | Apple: "You must request this entitlement from Apple"; without it `es_new_client` returns `ES_NEW_CLIENT_RESULT_ERR_NOT_ENTITLED`. Separate failures exist for not running as root (`ERR_NOT_PRIVILEGED`) and missing TCC approval (`ERR_NOT_PERMITTED`). | https://developer.apple.com/documentation/endpointsecurity/es_new_client_result_t |
| 3 | Claude Code managed policy paths, plist domain, HKLM key; unparseable managed document blocks start | confirmed | All paths, `managed-settings.d/`, `com.anthropic.claudecode` and `HKLM\SOFTWARE\Policies\ClaudeCode` (value `Settings`) match. Refusal to start covers file, drop-in, plist and HKLM, "even when another admin source delivers a valid policy". A malformed HKCU value never blocks launch. Legacy `C:\ProgramData\ClaudeCode\` is not read. | https://code.claude.com/docs/en/managed-settings |
| 4 | Codex reads `/etc/codex/requirements.toml`, `%ProgramData%\OpenAI\Codex\requirements.toml`, and MDM `com.openai.codex:requirements_toml_base64`; these can carry managed hooks | confirmed | Verified in source: `loader/mod.rs` (paths), `loader/macos.rs` (domain and key; value must be a forced managed preference), `config_requirements.rs` (`hooks`, `allow_managed_hooks_only`). A cloud-managed requirements layer also exists. The cited docs URL now 308-redirects to `learn.chatgpt.com/docs/enterprise/managed-configuration`. | https://github.com/openai/codex/blob/main/codex-rs/config/src/loader/mod.rs |
| 5 | BeyondTrust agent: Windows 11 / Server 2022+ x64 only, macOS 14/15/26, tenant root CA for TLS inspection, machine-wide fail-open hooks for Claude Code, Codex, Cursor, Copilot | confirmed | The ARM exclusion is Windows-only (macOS pkg is universal). macOS rule is "current major version and the two before it". `pre_tool_use` is the only event named, and only in a Cursor note, so the hook event set is undocumented. The page does not offer a fail-closed option. | https://docs.beyondtrust.com/bt-docs/docs/ai-agent-security |
| 6 | Defender runtime protection: Windows-only preview, Audit and Block; agent-native inspection covers Claude Code, Codex CLI, Copilot CLI; network inspection lacks pinning and HTTP/3 support | corrected | Windows-only preview, Audit/Block (plus Disabled) and the pinning/HTTP/3 limit hold. The support matrix (2026-11-02), which states unlisted combinations are not supported, lists agent-native inspection for Claude Code, GitHub Copilot CLI, GitHub Copilot app, Claude Desktop (Code mode) and the VS Code Copilot and Claude Code extensions. Codex CLI is not in it; only the overview prose names Codex CLI as an example. Network inspection lists OpenClaw, Ollama Desktop, ChatGPT Classic, ChatGPT Desktop. | https://learn.microsoft.com/en-us/defender-endpoint/ai-agent-support-matrix |
| 7 | Kernel driver attestation or WHCP submission needs a Hardware Dev Center account with an EV certificate; MVI needs a commercial real-time anti-malware product, reputation and Trusted Signing | corrected | EV and MVI points hold, but attestation is not a production path: Microsoft documents it "for testing purposes only", attestation-signed drivers cannot go to Windows Update for retail audiences, and Windows Server 2016+ loads only HLK-tested dashboard-signed drivers. A shipping kernel driver, and any server coverage, needs WHCP/HLK. MVI additionally requires yearly certification by an independent test lab (AV-Comparatives, AV-Test, SE Labs, etc.), an NDA and a program licence agreement. | https://learn.microsoft.com/en-us/windows-hardware/drivers/dashboard/driver-signing-offerings |
| 8 | Artifact Signing public trust: organisations in US, CA, EU, UK, AU, NZ, JP, KR, SG, CH, NO, IL; individuals US/CA only | confirmed | Wording matches the quickstart prerequisites note exactly. Also relevant: free, trial and sponsored Azure subscriptions are not accepted, and the service will not issue EV certificates. | https://learn.microsoft.com/en-us/azure/artifact-signing/faq |
| 9 | EKS add-ons: amd64 + arm64, Marketplace ECR, no Helm hooks or `lookup`, no CRDs plus their custom resources in one add-on, no BYOL; Azure Kubernetes apps: Linux AMD64 only, CNAB | confirmed | All points match. Precision on CRDs: one add-on may install CRDs; what cannot share that add-on is custom resource instances of those CRDs (alternative to a second add-on is manual manifests). | https://docs.aws.amazon.com/marketplace/latest/userguide/container-product-policies.html |
| 10 | agent-sandbox v1.0.0 on 2026-08-28 with four kinds at `v1beta1`; isolation delegated to gVisor/Kata via RuntimeClass, limiting host eBPF visibility | confirmed | Release published 2026-08-28T22:12Z; `v1alpha1` and conversion webhooks removed; all four CRDs serve only `v1beta1`. README scope statement matches. The RuntimeClass is optional, so sandboxes on the default runc runtime stay visible to a host sensor; the blind spot applies only where gVisor or Kata is selected. Minimum Kubernetes is 1.25 (1.29+ recommended). | https://github.com/kubernetes-sigs/agent-sandbox/releases/tag/v1.0.0 |

Further statements checked in the brief:

| Statement | Verdict | Note | Source |
|---|---|---|---|
| "Kubernetes baseline is 1.34 to 1.37" / "supported upstream lines 1.34 to 1.37" | corrected | Upstream 1.34 reached end of life on 2026-10-27 (final patch 1.34.13, 2026-10-28). Maintained lines are 1.35, 1.36, 1.37; 1.38.0-beta.0 shipped 2026-11-06. A 1.34 floor is only defensible on managed-provider support windows. | https://kubernetes.io/releases/ |
| Azure Marketplace Kubernetes apps: "all images by digest" | corrected | The page requires image references and digest details in the chart but states "you can utilize tags or digests"; images are retagged into Microsoft's registry. Digest pinning is our choice, not a marketplace rule. | https://learn.microsoft.com/en-us/partner-center/marketplace-offers/azure-container-technical-assets-kubernetes |
| TL;DR and design item 8: EKS add-on needs "CRDs in a separate add-on" / "CRDs in a separate chart" | corrected | Overstated, see claim 9: CRDs can ship in the main add-on; only the custom resources that depend on them must be split out or applied manually. | https://docs.aws.amazon.com/marketplace/latest/userguide/container-product-policies.html |

Spot checks that held: Zarf v1.0.0 published 2026-11-10T03:23Z; Helm v4.3.1 and v3.22.1 both released 2026-10-15; cosign v3.1.4 on 2026-10-20; Go Cryptographic Module v1.0.0 carries CMVP certificate #5247; user namespaces and MutatingAdmissionPolicy are stable since Kubernetes 1.36; Agent 365 generally available 2026-05-01, per-user licensing.
