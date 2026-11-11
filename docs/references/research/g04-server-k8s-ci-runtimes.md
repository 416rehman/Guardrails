# Agents off the laptop: Kubernetes, containers, CI runners, cloud dev environments, VDI and sandbox runtimes

_Researched 2026-11-09_

Evidence tags: **[V]** read in a primary source this session, **[P]** prior knowledge not re-verified, **[I]** inference. Web search was unavailable (shared budget exhausted) and the GitHub API rate limit was hit near the end, so everything here comes from direct fetches of vendor docs and repositories; gaps are listed at the bottom.

## TL;DR

- **Host eBPF is blind inside sandboxed pods, and Google says so in writing.** GKE docs: host-kernel tools "including Security Command Center Container Threat Detection, Falco, and Tetragon, can't observe or alert on syscalls in sandboxed containers"; in microVMs you can run eBPF as a privileged sidecar against the guest kernel. [V]
- **gVisor has its own telemetry path:** `seccheck` trace sessions stream 998 trace points (all syscalls, `container/start`, `sentry/*`) as protobuf over a Unix socket to an external monitor. It is asynchronous, so observe-only. Context includes `container_id`, `credentials`, `process_name`, `is_exec_session`. [V]
- **Fargate removes every privileged option.** EKS Fargate: no DaemonSets, no privileged containers, no HostNetwork, one kernel per pod, no IMDS. GuardDuty Runtime Monitoring does not support EKS on Fargate at all; on ECS Fargate AWS itself uses a sidecar. [V]
- **kubernetes-sigs/agent-sandbox is 1.0** (v1.0.10, 2026-11-06, weekly releases, Apache-2.0). It orchestrates only; isolation is delegated to gVisor/Kata via RuntimeClass. It has no runtime telemetry or policy hook. That gap is ours to fill. [V]
- **OSS kernel sensors that can block:** Tetragon 1.8.0 (in-kernel Override and Signal) and KubeArmor (BPF-LSM/AppArmor/SELinux). Falco 0.45.2 and Kubescape node-agent detect only. Tracee's last release is v0.24.1 (2025-11), effectively stale. [V]
- **Hosted CI runners are root-capable ephemeral VMs.** GitHub: passwordless sudo on Linux/macOS, admin on Windows; GitLab.com: passwordless sudo, VM deleted after the job, 3 h cap. A first-step action can install a full sensor. Exception: GitHub `ubuntu-slim` runs in an unprivileged container. [V]
- **GitHub Agentic Workflows (gh-aw, MIT) is the reference design for agents in CI:** Squid-based Agent Workflow Firewall, containerised MCP gateway, read-only agent job, buffered "safe outputs", separate threat-detection job. [V]
- **Cloud agent runtimes are per-session microVMs with no customer kernel access** (AgentCore Runtime, Foundry hosted agents, Vertex/Gemini Agent Runtime). Control points are OpenTelemetry, the vendor gateway, the vendor identity, and cloud audit logs. [V]
- **Sandbox vendors converge on microVM + SNI allowlist + credential-brokering proxy, and none exposes a decision stream.** E2B, Daytona and Docker document no audit feed; Modal writes blocks to sandbox stdout; Vercel's `forwardURL` with an OIDC token is the only real hook. [V]
- **Identity primitives are ready:** SPIRE k8s selectors (ns, sa, pod-uid, pod-label, container-image, Sigstore), Kubernetes PodCertificateRequest stable in v1.37, Google agent identities as SPIFFE X.509 (24 h), Entra agent identity per Foundry agent. OCSF 1.9.0 has an **AI Operation** profile with `ai_agent`, `ai_capability`, `ai_model`. [V]
- **Named competitors confirm the whitespace.** BeyondTrust AI Agent Security: "supports Windows and macOS endpoints only". Agent 365: registry and Entra/Purview/Defender governance, per-user licence, counts "unmanaged agents" but documents no server-side sensor. [V]

## Findings

### 1. Sensor deployment in clusters and what each mode sees

**DaemonSet with eBPF (runc nodes).** Falco's modern eBPF probe needs BTF and ring buffer (kernel >= 5.8 typical) and, in least-privilege mode, `CAP_BPF`, `CAP_PERFMON`, `CAP_SYS_RESOURCE`, `CAP_SYS_PTRACE` (older kernels need `CAP_SYS_ADMIN`) ([Falco kernel sources](https://falco.org/docs/concepts/event-sources/kernel/)). [V] Tetragon enforces "in the kernel inline with the operation": Override replaces a return value (kprobes need `CONFIG_BPF_KPROBE_OVERRIDE`; `security_*` hooks from 5.7), Signal sends SIGKILL but "does not necessarily stop the operation in progress", so the docs say combine both. LSM-hook policies require BPF LSM enabled at boot (`lsm=...,bpf`); IMA file hashes in LSM events need 5.11+ ([enforcement](https://tetragon.io/docs/concepts/enforcement/), [selectors.md](https://github.com/cilium/tetragon/blob/main/docs/content/en/docs/concepts/tracing-policy/selectors.md)). [V] KubeArmor enforces via AppArmor, SELinux or BPF-LSM and runs on Kubernetes, plain containers and VMs ([README](https://github.com/kubearmor/KubeArmor)). [V] Kubescape node-agent builds per-workload application profiles and network neighbours from Inspektor Gadget tracers and evaluates CEL rules; it requires privileged mode ([node-agent](https://github.com/kubescape/node-agent)). [V]

**gVisor.** Privileged containers, hostPath, seccomp, AppArmor and SELinux are unsupported in GKE sandboxes ([GKE sandbox pods](https://docs.cloud.google.com/kubernetes-engine/docs/concepts/sandbox-pods)). [V] The only syscall-level source is `seccheck`: named sessions enable points with optional fields (for example `fd_path`, `env`) and send to the `remote` sink over a Unix socket; one monitor can serve many sandboxes ([seccheck README](https://github.com/google/gvisor/blob/master/pkg/sentry/seccheck/README.md), [runtime monitoring](https://gvisor.dev/docs/user_guide/runtimemonitor/)). [V] Configuration is a runsc-level concern, so it needs node access; whether managed GKE Sandbox lets customers attach a sink is unverified. Falco's gVisor engine status is unverified this session.

**Kata / microVM pods.** Host sees a VMM process and a tap device, not guest syscalls. GKE: "you can run eBPF tools as a privileged sidecar to monitor the guest kernel"; `hostNetwork` unsupported. [V] So the sensor ships as a sidecar or is baked into the guest image.

**Fargate.** No privileged path exists ([EKS Fargate](https://docs.aws.amazon.com/eks/latest/userguide/fargate.html), [GuardDuty](https://docs.aws.amazon.com/guardduty/latest/ug/runtime-monitoring.html)). [V] Coverage is an unprivileged sidecar plus in-agent hooks plus forced egress through a gateway. Per-pod security groups are available. [V]

**Admission.** agent-sandbox itself recommends `ValidatingAdmissionPolicy` to enforce `automountServiceAccountToken: false` on bare Sandboxes ([threat model](https://github.com/kubernetes-sigs/agent-sandbox/blob/main/docs/security/threat_model.md)). [V] Use admission for placement and injection, never as the runtime control.

### 2. agent-sandbox specifics

CRDs: `Sandbox`, plus extensions `SandboxTemplate`, `SandboxClaim`, `SandboxWarmPool`; requires Kubernetes 1.25+ with CEL (1.29+ recommended); ships `helm/` and `olm/` directories, Go and Python SDKs, and an optional Sandbox Router ([README](https://github.com/kubernetes-sigs/agent-sandbox)). [V] Threat model facts worth designing around: the managed NetworkPolicy (default with templates) restricts ingress to the router and egress to the public internet, blocking RFC1918 and metadata, and **blocks sidecar ports unless explicitly allowed**; the router's default authorizer is `AllowAll`; reserved keys under `agents.x-k8s.io/` are stripped from user templates after a label-spoofing traffic-hijack issue. [V] Identity handles on the pod: label `agents.x-k8s.io/claim-uid`, annotation `agents.x-k8s.io/claim-name`, plus a controller-managed `opentelemetry.io/trace-context` annotation ([configuration.md](https://github.com/kubernetes-sigs/agent-sandbox/blob/main/docs/configuration.md)). [V] GKE Agent Sandbox packages the same CRDs with gVisor and Workload Identity Federation ([GKE how-to](https://docs.cloud.google.com/kubernetes-engine/docs/how-to/agent-sandbox)). [V]

### 3. Identity mapping to an agent identity and to OCSF

- **SPIRE:** node attestors `k8s_psat`, `aws_iid`, `gcp_iit`, `azure_msi`; workload selectors `k8s:ns`, `k8s:sa`, `k8s:pod-uid`, `k8s:pod-label`, `k8s:pod-owner(-uid)`, `k8s:container-image`, `k8s:node-name`, and Sigstore selectors such as `k8s:image-signature:verified` and `k8s:image-signature-subject` ([k8s workload attestor](https://github.com/spiffe/spire/blob/main/doc/plugin_agent_workloadattestor_k8s.md)). SPIRE v1.16.0 released 2026-11-05. [V]
- **Kubernetes native:** PodCertificateRequest and `podCertificate` projected volumes are stable since v1.37 (first in v1.34), embedding pod name/UID, service account name/UID and node name/UID; default max lifetime 24 h. ClusterTrustBundle also stable in v1.37 ([CSR docs](https://kubernetes.io/docs/reference/access-authn-authz/certificate-signing-requests/)). [V]
- **Google:** agent principal `principal://agents.global.org-ORG.system.id.goog/resources/aiplatform/projects/N/locations/L/reasoningEngines/ID`, underlying `spiffe://TRUST_DOMAIN/resources/SERVICE/PATH`, auto-provisioned X.509 valid 24 h, mTLS-bound tokens plus DPoP through Agent Gateway; not impersonable, no long-lived keys ([agent identity](https://docs.cloud.google.com/agent-builder/agent-engine/agent-identity)). [V]
- **Azure:** each Foundry hosted agent gets a dedicated Entra agent identity at deploy; OBO when a user token is present, own identity otherwise ([hosted agents](https://learn.microsoft.com/en-us/azure/foundry/agents/concepts/hosted-agents), 2026-10-19). [V]
- **AWS:** AgentCore Runtime has "a unique identity" per runtime, IAM SigV4 or OAuth inbound, user-delegated or autonomous outbound ([runtime](https://docs.aws.amazon.com/bedrock-agentcore/latest/devguide/runtime-how-it-works.html)). [V] EKS Fargate pods must use IRSA. [V]
- **OCSF:** stable 1.9.0, 1.10.0-dev ([schema](https://schema.ocsf.io/)); profiles include `ai_operation`, `container`, `cloud`, `network_proxy`, `security_control`; objects include `ai_agent`, `ai_capability` (tool/resource/prompt in the MCP sense, with self-declared hints flagged as unverified), `ai_model`, `ai_status`, `message_context` ([ocsf-schema](https://github.com/ocsf/ocsf-schema/tree/main/profiles)). [V]

Proposed canonical tuple [I]: `{cluster_uid, namespace, service_account name+uid, pod uid, container name, image digest, owner (Sandbox / SandboxClaim uid), runtime_class, node, spiffe_id, cloud principal, exec_id, agent_session_id}`. Emit with OCSF `container` + `cloud` + `ai_operation` profiles; put the SPIFFE ID and cloud principal on `ai_agent`/actor, tool calls on `ai_capability`. For gVisor, carry `is_exec_session` to separate `kubectl exec` humans from the workload.

### 4. CI runners

- **GitHub-hosted:** fresh VM per job; passwordless sudo (Linux/macOS), admin with UAC off (Windows). `ubuntu-slim` single-CPU runs in an unprivileged container: no mounts, no Docker-in-Docker, no low-level kernel features ([runner reference](https://docs.github.com/en/actions/reference/runners/github-hosted-runners)). [V]
- **Harden-Runner v2.22.4:** first-step action on hosted runners; baked into images for self-hosted VMs; a DaemonSet for ARC; `egress-policy: audit|block`; correlates network, process and file events to the workflow step. Community tier is public repos on hosted runners only; private repos, self-hosted and ARC are paid, and the action is a silent no-op on self-hosted without a subscription. macOS and Windows lack several detections; CodeBuild needs EC2 compute, kernel 6 and privileged mode ([docs](https://docs.stepsecurity.io/harden-runner), [README](https://github.com/step-security/harden-runner)). [V]
- **gh-aw v1.2.2:** agent container on an internal Docker network; iptables redirects to a Squid allowlist proxy; AWF drops its capabilities before starting the agent; on ARC, egress is enforced by DinD network topology (privileged DinD sidecar, unprivileged runner); Cloud Hypervisor KVM microVM in preview on hosted Ubuntu x86_64. MCP gateway (`gh-aw-mcpg`) spawns one container per MCP server with per-server allowlists. Threat detection defaults to warn mode. Artifacts: `agent_output.json`, `prompt.txt`, `aw.patch`, firewall logs. Engines: Copilot, Claude Code, Codex, Gemini, Pi ([architecture](https://github.github.com/gh-aw/introduction/architecture/)). [V]
- **GitLab.com hosted:** dedicated VM per job, deleted after; passwordless sudo; inbound blocked; 3 h timeout ([hosted runners](https://docs.gitlab.com/ci/runners/hosted_runners/)). [V]
- **Buildkite:** job hooks `environment`, `pre-checkout`, `pre-command`, `command`, `post-command`, `pre-exit`; agent-level hooks on self-hosted and Linux hosted agents (`/buildkite/agent/hooks`), not macOS hosted; on Agent Stack for Kubernetes hooks run in separate containers and exported variables do not cross from checkout to command containers ([hooks](https://buildkite.com/docs/agent/v3/hooks)). [V]

### 5. Dev environments, WSL2, VDI

- **Coder Agent Firewall** (formerly Agent Boundaries, Premium): `nsjail` mode needs `CAP_NET_ADMIN` and, in Docker, a seccomp change or sysbox; `landjail` uses Landlock V4 (Linux 6.7+), needs no capabilities, but is bypassable by connecting straight to the proxy port and cannot control UDP. Per-request allow/deny audit logs stream to the control plane (Coder 2.30+) ([docs](https://coder.com/docs/ai-coder/agent-boundaries)). [V]
- **Ona Veto:** an LSM in the environment kernel; executable deny list by content hash, "rename-resistant and symlink-resistant", check and block in the same kernel call ([veto](https://ona.com/docs/ona/guardrails/veto.md)). Mechanism, network scope and audit output undocumented on that page. [V]
- **Codespaces:** own VM and virtual network per codespace, inbound blocked, outbound open; `devcontainer.json` can run arbitrary commands and Features ([security](https://docs.github.com/en/codespaces/reference/security-in-github-codespaces)). [V] Privilege level inside the container not confirmed.
- **Docker Sandboxes (`sbx`):** microVM with own kernel and private Docker Engine; outbound TCP proxied through the host with deny-by-default policy; UDP and ICMP blocked; host proxy injects credentials; org-level network, filesystem and MCP policy is a paid add-on ([security](https://docs.docker.com/ai/sandboxes/security/)). [V]
- **WSL2:** Defender's WSL plug-in loads into the WSL VM via a plug-in DLL, reports file/process/network events as a separate Linux device linked by `HostDeviceId`; visibility only (no AV, no response actions), unsupported on ARM64, on **multi-session Windows**, and unreliable with custom kernels; onboarding takes up to 30 minutes so short-lived instances may never appear ([doc](https://learn.microsoft.com/en-us/defender-endpoint/mde-plugin-wsl), 2026-09-15). [V]
- **AVD multi-session:** Microsoft recommends one device entry per host; the doc covers onboarding non-persistent hosts from a golden image, not per-user attribution ([doc](https://learn.microsoft.com/en-us/defender-endpoint/onboard-windows-multi-session-device)). [V] Citrix was not researched.

### 6. Agent sandbox products and cloud agent runtimes

| Product | Isolation | Policy hook | Telemetry hook |
|---|---|---|---|
| AgentCore Runtime | microVM per session, 8 h max, 15 min idle | Policy (Cedar or Dogwood, temporal rules) enforced at AgentCore Gateway | CloudWatch metrics/logs for every decision |
| Foundry hosted agents | per-session VM sandbox, 0.5 to 2 vCPU | Toolbox MCP endpoint, Entra | OpenTelemetry to App Insights, injected automatically |
| Gemini Agent Platform runtime | managed | Agent Gateway, IAM, context-aware access | Cloud Trace/Logging; Threat Detection (Preview) via a "watcher process" |
| Vercel Sandbox | not confirmed here | allow/deny domains and CIDRs, live updates, `transform`, `forwardURL`, direct responses | proxy at `forwardURL` receives OIDC token with `sandbox_id` |
| E2B | P: Firecracker | `allowOut`/`denyOut`; Host header on 80, SNI on 443; no QUIC | none documented; blocked TCP can look successful |
| Daytona | not confirmed | `networkBlockAll`, CIDR list (10), `domainAllowList` (100), `outboundProxyUrl` | none documented |
| Modal | gVisor or VM | `block_network`, CIDR allowlist, domain allowlist (beta, 443 only) | blocks in sandbox stdout |
| Cloudflare Sandbox | microVM per container | `enableInternet: false`; credentials stay in the Worker | Workers Logs |
| Anthropic srt v0.0.82 | bubblewrap / Seatbelt / Windows WFP + dedicated user | JSON settings, live update via `--control-fd` | violation store (macOS log tap) |

Sources: [AgentCore Policy](https://docs.aws.amazon.com/bedrock-agentcore/latest/devguide/policy.html), [Foundry](https://learn.microsoft.com/en-us/azure/foundry/agents/concepts/hosted-agents), [Threat Detection](https://docs.cloud.google.com/security-command-center/docs/agent-engine-threat-detection-overview), [Vercel firewall](https://vercel.com/docs/vercel-sandbox/concepts/firewall) (2026-09-16), [E2B](https://docs.e2b.dev/sandbox/internet-access), [Daytona](https://www.daytona.io/docs/en/network-limits/), [Modal](https://modal.com/docs/guide/sandbox-networking), [Cloudflare](https://developers.cloudflare.com/sandbox/) (2026-09-30), [srt](https://github.com/anthropic-experimental/sandbox-runtime). All [V] unless marked.

Vercel's doc is unusually candid: SNI matching permits domain fronting unless TLS is terminated; CIDR allow rules bypass SNI filtering and leave DNS open for exfiltration. [V] Google's Threat Detection detectors are classic container ones (Reverse Shell, Container Escape, Malicious Script Executed, Malicious URL Observed), with script analysis for Bash and Python only. [V]

### 7. Egress controls combined with MCP and LLM gateways

- **Cilium:** `toFQDNs` with `matchName`/`matchPattern` (`*.github.com` does not match the apex), enforced through an in-agent DNS proxy; the standalone DNS proxy for HA is alpha ([dns.rst](https://github.com/cilium/cilium/blob/main/Documentation/security/dns.rst)). [V] Enforcement is by learned IP, so shared CDN IPs over-allow. [P]
- **agentgateway v1.7.0** (Apache-2.0): LLM, MCP and A2A proxy; Gateway API controller; JWT/API key/OAuth; CEL RBAC; guardrails via regex, OpenAI moderation, Bedrock Guardrails, Model Armor and **custom webhooks**; OpenTelemetry ([README](https://github.com/agentgateway/agentgateway)). [V]
- **Agent Router v1.2** (Envoy AI Gateway renamed, now an Agentic AI Foundation project): `MCPRoute` (`aigateway.envoyproxy.io/v1beta1`), tool filtering, multiplexing, OAuth with PKCE, ordered authorization rules over tool targets, JWT claims and CEL, upstream key injection ([docs](https://theagentrouter.ai/docs/capabilities/mcp/)). [V]
- **kagent** reached v1.0.0 on 2026-11-09. [V]

Composition [I]: (1) CNI default-deny egress for agent pods, allowing only DNS and the gateway Service; (2) gateway holds provider and tool credentials, so bypass yields nothing; (3) our policy engine plugs in as the gateway's webhook/CEL/ext_authz decision point; (4) node sensor attributes each connection to pod and process and alerts on direct-to-provider traffic.

## Matrix

Coverage by control point. Y = feasible now, P = partial, N = not possible.

| Runtime | Observe (syscall/process) | Block in-line | Identity source | Network control |
|---|---|---|---|---|
| K8s runc nodes (EKS EC2, GKE Standard, AKS, self-managed) | Y eBPF DaemonSet | Y BPF LSM / override; SIGKILL fallback | SA, pod UID, image digest, SPIFFE, PodCertificate | Y CNI + gateway |
| gVisor pods (self-managed runsc) | P seccheck sink, async | N at syscall level; gateway and hooks only | same | Y NetworkPolicy + gateway |
| GKE Sandbox / GKE Agent Sandbox | N from host; seccheck access unverified | N | SA + Workload Identity, claim-uid | Y managed NetworkPolicy + gateway |
| Kata / microVM pods | P guest sidecar or baked image | P inside guest | same | Y pod-level |
| EKS Fargate | N kernel; sidecar + agent hooks | P hooks and proxy only | IRSA role, SA, pod UID | P security groups + gateway; VPC CNI only |
| ECS Fargate | P sidecar | P | task role | P |
| GitHub-hosted VM runner | Y first-step action with sudo | Y | OIDC claims, run/job/step | Y local firewall/proxy |
| GitHub `ubuntu-slim`, container jobs | N / P | P proxy env only | same | P |
| ARC / self-hosted runners | Y DaemonSet or image-baked | Y | same + pod identity | Y |
| GitLab.com hosted | Y (sudo, `before_script`) | Y | CI job token/ID token | Y |
| Buildkite | Y self-hosted; P hosted Linux via hooks | Y / P | job/pipeline IDs | Y / P |
| Codespaces, devcontainers | P Feature-installed hooks + proxy | P | user + repo | P outbound open by default |
| Coder | P Agent Firewall or our sensor in template | P Landlock/nsjail | workspace, owner, template | Y HTTP allowlist |
| Docker Sandboxes | N inside microVM from host | P vendor policy | local user | Y vendor proxy |
| WSL2 | Y Linux sensor inside VM | Y if kernel has BPF LSM | Windows user + distro | P |
| AVD / Citrix multi-session | Y Windows sensor, must be session-aware | Y | session ID + user SID | N by IP (shared) |
| AgentCore / Foundry / Vertex runtimes | N | P vendor gateway policy | vendor agent identity | P VPC egress + vendor gateway |
| E2B / Daytona / Modal / Vercel / Cloudflare | N (P in-sandbox agent hooks) | P vendor firewall | sandbox ID (Vercel OIDC) | Y vendor firewall, proxy forward |

## Weak points, gaps and risks

- **Sandboxed runtimes invert the usual trust in the kernel sensor.** The most dangerous code (LLM-generated) runs exactly where the DaemonSet sees nothing. Any coverage claim must be reported per pod by RuntimeClass.
- **BPF LSM is not universally on.** It needs a boot parameter; managed node images differ. Enforcement must degrade visibly: LSM, then kprobe override, then SIGKILL, then detect-only.
- **SIGKILL is not prevention** (Tetragon says the write may complete). [V]
- **SNI allowlists are weak alone:** domain fronting, QUIC/UDP, raw-IP CIDR holes, DNS tunnelling (Vercel, E2B, Coder docs). [V]
- **Sidecars collide with agent-sandbox's managed NetworkPolicy**, which blocks sidecar ports by default. [V]
- **Ephemerality beats slow onboarding.** Defender WSL takes up to 30 minutes; Google's watcher up to a minute; AgentCore sessions idle out at 15 minutes. Our sensor must register and ship first events in seconds and buffer-flush on shutdown hooks.
- **Admission webhooks are an availability risk** in other people's clusters; prefer ValidatingAdmissionPolicy and `failurePolicy: Ignore` for injection.
- **Vendor identities do not interoperate.** Entra agent ID, Google agent principal and AgentCore identity are separate namespaces; the join key has to be ours.
- **Tracee looks unmaintained as a release train**; do not build on it.

## Implications for our design

Reference architecture per environment:

1. **Kubernetes, runc nodes.** One Helm chart: (a) `sensor` DaemonSet, the same Rust Linux sensor as the endpoint build, CO-RE eBPF, capability-scoped (`BPF`, `PERFMON`, `SYS_RESOURCE`, `SYS_PTRACE`; `SYS_ADMIN` fallback), `hostPID`, mounts for `/sys/fs/bpf`, `/sys/kernel/btf`, `/sys/kernel/security`, `/proc` and the CRI socket, tolerate-all, `system-node-critical`; (b) `controller` Deployment watching Pods, Namespaces, ServiceAccounts and `agents.x-k8s.io` CRs to build the identity cache and push policy; (c) optional gateway integration. Startup probe reports per-node enforcement tier (BTF, LSM list, override support).
2. **gVisor, Kata, Fargate ("no-kernel tier").** Unprivileged sidecar or init-injected shim providing in-agent hooks, `HTTPS_PROXY` to the cluster gateway, Landlock where the kernel allows, and OTel export. For self-managed runsc, a node-level seccheck sink consumer feeding the same pipeline. For Kata, a guest image with the sensor. Ship `SandboxTemplate` overlays that open the sidecar port explicitly.
3. **CI.** A GitHub Action wrapping the Linux sensor in ephemeral mode (install, attribute by step, flush in `post`); ARC handled by the DaemonSet; GitLab `before_script` component; Buildkite plugin using `environment` and `pre-exit`. Identity from the CI OIDC token. Make self-hosted free; that is Harden-Runner's paywall.
4. **Dev environments.** A devcontainer Feature (hooks, proxy, sensor where privileged) covering Codespaces, Coder, Ona and local Docker; a Coder template module; WSL2 via the Linux sensor inside the VM, linked to the Windows host device ID as Defender does.
5. **VDI multi-session.** The Windows sensor must key every event on logon session and user SID, and policy must be per session, since IP-based gateways cannot attribute.
6. **Cloud agent runtimes.** API connectors for inventory, OTLP ingest, cloud audit log ingest, and policy export (compile our policy to Cedar for AgentCore Policy; to `MCPRoute` rules or agentgateway CEL in-cluster).
7. **Sandbox vendors.** SDK wrappers that set the vendor firewall to forward to our gateway (`forwardURL`, `outboundProxyUrl`) and validate the sandbox OIDC token.

Helm and operator requirements: Kubernetes 1.29+ baseline (CEL stable, matches agent-sandbox); values to select tiers (`daemonset`, `sidecarOnly`, `gvisorSink`); no mandatory webhook; CRDs kept to policy and identity mapping; OLM bundle for OpenShift; documented SCC/PodSecurity exemptions; namespace-scoped install for tenants without cluster-admin.

Phased order: **P1** runc DaemonSet (detect, then enforce), GitHub hosted-runner action and ARC, gateway recipes with Cilium. **P2** sidecar tier for Fargate/gVisor/Kata, agent-sandbox integration, devcontainer Feature, GitLab and Buildkite. **P3** AgentCore/Vertex/Foundry connectors, sandbox-vendor wrappers, WSL2. **P4** multi-session VDI, Kata guest images, seccheck on managed gVisor if it opens up.

## Ideas worth stealing and whitespace

- gh-aw's **read-only agent job plus buffered safe outputs plus separate detection job**: generalise to any runtime as "stage, inspect, then externalise".
- Vercel's **forward-with-OIDC** hook and **live policy update** (open network for install, then lock before running untrusted code).
- Credential brokering at the proxy (Vercel, Docker, Agent Router): secrets never enter the sandbox.
- Ona's **content-hash executable identity** in an LSM; Coder's Landlock mode for zero-capability environments.
- AgentCore's **temporal policies** (session history, budgets, approval-before-action) and automated-reasoning checks on authored policy.
- Tetragon-style capability probing; Harden-Runner's per-step correlation and baseline-diff as a PR check.
- **Whitespace:** a coverage ledger per workload by RuntimeClass; an open sandbox-telemetry contract (decision stream) no vendor offers; a seccheck-to-OCSF consumer; unified identity join across SPIFFE, Entra, Google and AWS agent identities; a free sensor for self-hosted runners; session-aware agent attribution on multi-session hosts.

## Could not verify / open questions

- Falco gVisor engine status in 0.45; whether GKE Sandbox exposes seccheck configuration.
- Kata agent policy and guest-side sensor patterns; AKS and EKS specifics for Kata; GKE Autopilot rules for privileged DaemonSets.
- Sysdig AI workload security docs (404); agentgateway Kubernetes docs page (404), so its CRD names and ext_proc support are unconfirmed; Cilium policy-language page (redirect), so `serverNames` SNI rules and documented `toFQDNs` limitations are from prior knowledge.
- Codespaces container privilege and org-level injection; Citrix; Azure Foundry egress filtering detail; AgentCore observability detail.
- Whether Landlock and seccomp user-notify are usable inside Fargate and gVisor.
- Agent 365: how "unmanaged agents" are discovered; the Observability SDK was deprecated (page dated 2026-10-01) in favour of a Microsoft OpenTelemetry Distro that I did not read.
- Harden-Runner agent source availability and its AI-agent-specific features.

## Sources

- https://docs.cloud.google.com/kubernetes-engine/docs/concepts/sandbox-pods — GKE sandbox pods, fetched 2026-11-09
- https://docs.cloud.google.com/kubernetes-engine/docs/how-to/agent-sandbox — GKE Agent Sandbox, fetched 2026-11-09
- https://github.com/google/gvisor/blob/master/pkg/sentry/seccheck/README.md and https://gvisor.dev/docs/user_guide/runtimemonitor/ — gVisor runtime monitoring (release 20261102.0)
- https://github.com/kubernetes-sigs/agent-sandbox (README, docs/security/threat_model.md, docs/configuration.md) — v1.0.10, 2026-11-06
- https://docs.aws.amazon.com/eks/latest/userguide/fargate.html — EKS Fargate considerations
- https://docs.aws.amazon.com/guardduty/latest/ug/runtime-monitoring.html — GuardDuty Runtime Monitoring
- https://tetragon.io/docs/concepts/enforcement/ and https://github.com/cilium/tetragon (selectors.md) — Tetragon v1.8.0, 2026-10-30
- https://falco.org/docs/concepts/event-sources/kernel/ — Falco 0.45.2, 2026-10-29
- https://github.com/kubearmor/KubeArmor, https://github.com/kubescape/node-agent, https://github.com/aquasecurity/tracee
- https://github.com/spiffe/spire/blob/main/doc/plugin_agent_workloadattestor_k8s.md and https://spiffe.io/docs/latest/deploying/spire_agent/ — SPIRE v1.16.0
- https://kubernetes.io/docs/reference/access-authn-authz/certificate-signing-requests/ — PodCertificateRequest, ClusterTrustBundle
- https://schema.ocsf.io/ and https://github.com/ocsf/ocsf-schema — OCSF 1.9.0
- https://docs.github.com/en/actions/reference/runners/github-hosted-runners — GitHub-hosted runners
- https://docs.stepsecurity.io/harden-runner and https://github.com/step-security/harden-runner — v2.22.4, 2026-11-06
- https://github.github.com/gh-aw/introduction/architecture/ and https://github.com/github/gh-aw — v1.2.2
- https://docs.gitlab.com/ci/runners/hosted_runners/ — GitLab hosted runners
- https://buildkite.com/docs/agent/v3/hooks — Buildkite hooks
- https://coder.com/docs/ai-coder/agent-boundaries — Coder Agent Firewall
- https://ona.com/docs/ona/guardrails/veto.md — Ona Veto
- https://docs.github.com/en/codespaces/reference/security-in-github-codespaces — Codespaces security
- https://docs.docker.com/ai/sandboxes/ and /security/ — Docker Sandboxes
- https://learn.microsoft.com/en-us/defender-endpoint/mde-plugin-wsl — 2026-09-15
- https://learn.microsoft.com/en-us/defender-endpoint/onboard-windows-multi-session-device — 2025-11-17
- https://docs.aws.amazon.com/bedrock-agentcore/latest/devguide/runtime-how-it-works.html and /policy.html — AgentCore
- https://docs.cloud.google.com/agent-builder/agent-engine/overview, /agent-identity, https://docs.cloud.google.com/security-command-center/docs/agent-engine-threat-detection-overview
- https://learn.microsoft.com/en-us/azure/foundry/agents/concepts/hosted-agents — 2026-10-19
- https://vercel.com/docs/vercel-sandbox/concepts/firewall — 2026-09-16
- https://docs.e2b.dev/sandbox/internet-access, https://www.daytona.io/docs/en/network-limits/, https://modal.com/docs/guide/sandbox-networking, https://developers.cloudflare.com/sandbox/ (2026-09-30)
- https://github.com/anthropic-experimental/sandbox-runtime — v0.0.82, 2026-11-09
- https://github.com/cilium/cilium/blob/main/Documentation/security/dns.rst — Cilium DNS policy
- https://github.com/agentgateway/agentgateway (v1.7.0, 2026-10-27), https://theagentrouter.ai/docs/capabilities/mcp/ (v1.2), https://github.com/kagent-dev/kagent (v1.0.0, 2026-11-09)
- https://docs.beyondtrust.com/bt-docs/docs/ai-agent-security — BeyondTrust AI Agent Security
- https://learn.microsoft.com/en-us/microsoft-agent-365/overview (2026-08-19), /admin/agent-registry-overview (2026-09-21), /developer/observability (2026-10-01)

## Independent verification

Checked 2026-11-09 by a second reviewer against primary docs and source code (GitHub API, raw source files, vendor doc pages fetched directly). Web search was unavailable (shared budget exhausted), so nothing here rests on search results. Two of the ten claims need correcting (7 and 9); three further statements in the brief are wrong or overstated.

| # | Claim | Verdict | Note | Source |
|---|---|---|---|---|
| 1 | Host-kernel tools (Container Threat Detection, Falco, Tetragon) cannot see syscalls in GKE sandboxed containers; in microVMs eBPF can run as a privileged sidecar against the guest kernel | confirmed | Page text matches for both gVisor and microVM sandboxes. Feature limits differ by type: privileged and hostPath are listed as unsupported for gVisor, `hostNetwork` for microVM; seccomp/AppArmor/SELinux for both. | https://docs.cloud.google.com/kubernetes-engine/docs/concepts/sandbox-pods |
| 2 | EKS Fargate: no DaemonSets, privileged containers, HostNetwork or HostPort; own kernel per pod; no IMDS. GuardDuty Runtime Monitoring does not support EKS on Fargate | confirmed | All points present verbatim. Also relevant: only the VPC CNI is allowed, and Fargate does not run Arm. | https://docs.aws.amazon.com/eks/latest/userguide/fargate.html ; https://docs.aws.amazon.com/guardduty/latest/ug/runtime-monitoring.html |
| 3 | gVisor seccheck streams 998 trace points as protobuf over a Unix socket, asynchronously; context fields include container_id, credentials, process_name, is_exec_session | confirmed | `ContextData` in `common.proto` has all four fields. 998 is the sample `runsc trace metadata` output in the README, not a stable contract; read the count at runtime. Context fields are opt-in per point in the session config. | https://github.com/google/gvisor/blob/master/pkg/sentry/seccheck/points/common.proto |
| 4 | agent-sandbox v1.0.10 (2026-11-06) is an orchestrator only; managed NetworkPolicy blocks sidecar ports by default; pods carry `agents.x-k8s.io/claim-uid` and `claim-name` | confirmed | Release v1.0.10 published 2026-11-06T22:09Z. `claim-uid` is a label and `claim-name` an annotation, set only on pods owned by a SandboxClaim. Idle warm-pool pods carry `agents.x-k8s.io/warm-pool-sandbox` instead, and bare Sandboxes have neither; the only key on every pod is `agents.x-k8s.io/sandbox-name-hash`. | https://github.com/kubernetes-sigs/agent-sandbox/blob/main/docs/configuration.md ; https://github.com/kubernetes-sigs/agent-sandbox/blob/main/examples/manual-pdb/README.md |
| 5 | Tetragon enforces in-kernel via Override (needs `CONFIG_BPF_KPROBE_OVERRIDE`; `security_` hooks from 5.7; LSM hooks need BPF LSM) and Signal; SIGKILL may not stop the in-flight operation | confirmed | Also: Override only works on functions marked `ALLOW_ERROR_INJECTION()`; BPF LSM needs `CONFIG_BPF_LSM=y` plus `bpf` in the `lsm=` list; `fentries` hooks support neither Override nor Signal. | https://github.com/cilium/tetragon/blob/main/docs/content/en/docs/concepts/tracing-policy/selectors.md ; https://github.com/cilium/tetragon/blob/main/docs/content/en/docs/concepts/tracing-policy/hooks.md |
| 6 | GitHub-hosted Linux/macOS runners have passwordless sudo on a fresh VM per job (Windows admin); `ubuntu-slim` is an unprivileged container; GitLab.com hosted runners give passwordless sudo on a per-job VM | confirmed | `ubuntu-slim` jobs also have a 15-minute timeout and run in a container on a shared VM with "hypervisor level 2 isolation". GitLab: VM deleted after the job, 3 h cap. | https://docs.github.com/en/actions/reference/runners/github-hosted-runners ; https://docs.gitlab.com/ci/runners/hosted_runners/ |
| 7 | AgentCore Runtime runs each session in a dedicated microVM (max 8 h, 15-min idle); AgentCore Policy evaluates Cedar or Dogwood at the Gateway and logs to CloudWatch | corrected | The Policy half holds. The Runtime half is true only for the default microVMs compute type, and both timers are configurable defaults (60 s to 8 h). A second compute type, Instances, runs each session on a dedicated EC2 managed instance in the customer's account and VPC for up to 14 days, with several agents per session and no isolation between them. | https://docs.aws.amazon.com/bedrock-agentcore/latest/devguide/runtime-lifecycle-settings.html ; https://docs.aws.amazon.com/bedrock-agentcore/latest/devguide/runtime-instances-security.html |
| 8 | PodCertificateRequest and `podCertificate` projected volumes are stable since v1.37 with pod/SA/node name+UID; SPIRE k8s attestor offers ns, sa, pod-uid, pod-label, container-image and Sigstore selectors | confirmed | `kube_features.go`: alpha 1.34, beta 1.35 (off by default), GA 1.37 (on by default, locked in 1.38). Latest release is v1.37.2, so this is available only on the newest minor; older and managed clusters will not have it. SPIRE selectors match; v1.16.0 released 2026-11-05. | https://github.com/kubernetes/kubernetes/blob/master/pkg/features/kube_features.go ; https://github.com/spiffe/spire/blob/main/doc/plugin_agent_workloadattestor_k8s.md |
| 9 | OCSF stable is 1.9.0 and its AI Operation profile includes `ai_agent`, `ai_capability` and `ai_model` | corrected | 1.9.0 (2026-08-03) is the latest stable. At the 1.9.0 tag the profile has `ai_agent`, `ai_model`, `delegation` and `message_context` only. `ai_capability` and `ai_status` exist only on main (1.10.0-dev, CHANGELOG "Unreleased", PRs #1729 and #1704). Tool-call events cannot use `ai_capability` on a stable schema yet. | https://github.com/ocsf/ocsf-schema/blob/1.9.0/profiles/ai_operation.json ; https://github.com/ocsf/ocsf-schema/blob/main/CHANGELOG.md |
| 10 | BeyondTrust AI Agent Security supports Windows and macOS endpoints only (Pathfinder agent, kernel and network enforcement); no documented Kubernetes, CI, container or cloud agent platform coverage | confirmed | Nuance: supported Windows is "Windows 11, or Windows Server 2022 or later" on x64, so Windows servers are in scope; macOS 14, 15, 26; no Linux. Sibling pages (visibility, endpoints) describe discovery only on enrolled endpoints. The Pathfinder MCP Gateway is a separate hosted endpoint exposing BeyondTrust product data, not an agent-traffic control point. | https://docs.beyondtrust.com/bt-docs/docs/visibility-ai-agents ; https://docs.beyondtrust.com/bt-docs/docs/welcome-to-pathfinder-mcp-gateway |
| A | Brief: "Cloud agent runtimes are per-session microVMs with no customer kernel access" and matrix row AgentCore "Observe: N" | corrected | Overstated for AgentCore. On the Instances compute type the session is an EC2 managed instance in the customer's account; agents run as containers or host processes, any code on the instance can read every agent's credentials, and VPC Flow Logs and CloudTrail apply. Customer permissions on the instance are restricted, and whether a host sensor can be installed is not documented. Treat as "P, unverified", not "N". | https://docs.aws.amazon.com/bedrock-agentcore/latest/devguide/runtime-instances-how-it-works.html |
| B | Brief: "Kubernetes 1.29+ baseline (CEL stable, matches agent-sandbox)" while preferring ValidatingAdmissionPolicy | corrected | 1.29 makes CRD CEL validation stable, which is what agent-sandbox means. ValidatingAdmissionPolicy is beta and off by default in 1.29 and GA in 1.30. A design that relies on VAP needs a 1.30 baseline or a webhook fallback on 1.29. | https://github.com/kubernetes/kubernetes/blob/release-1.29/staging/src/k8s.io/apiserver/pkg/features/kube_features.go ; https://github.com/kubernetes/kubernetes/blob/release-1.30/staging/src/k8s.io/apiserver/pkg/features/kube_features.go |
| C | Brief: "Falco's gVisor engine status is unverified this session" | corrected | Resolved: Falco deprecated the gVisor engine in 0.43.0 and removed it in 0.44.0 (PR #3797), so Falco 0.45.2 has no gVisor source. No maintained OSS consumer of seccheck remains in Falco; this strengthens the seccheck-to-OCSF whitespace point. | https://github.com/falcosecurity/falco/releases/tag/0.44.0 |
