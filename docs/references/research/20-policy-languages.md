# Policy and rule languages for authorisation and detection in an open-source AIDR

_Researched 2026-11-09_

Method note: the shared web-search budget was already exhausted when this brief started, so nothing here comes from search results. Everything was read directly from vendor docs, specifications and GitHub (via `gh`). "Verified" means I read it in the primary source on 2026-11-09; "inferred" is marked.

## TL;DR

- **Authorisation language: Cedar.** Rust-native (`cedar-policy` 4.14.1, 2026-11-02, language 4.6, Apache-2.0), schema-validated, forbid-overrides-permit, default deny, WASM build, and an SMT-backed analyser (`cedar-policy-symcc` 0.8.1) that proves always-allow, always-deny, implication, equivalence and disjointness with counterexamples.
- **New since mid-2026: Dogwood**, an Amazon-authored, Apache-2.0 Cedar superset (v1.0 on 2026-10-13, v1.1.1 on 2026-11-06) that adds session-history conditions (`when temporal { formerly within 1h ... }`, `since`, `previous`, `count`, `sum`) and "information providers" (ML or content scores called inside `when`). It **lowers to plain Cedar** with hoisted `context.*` slots. AWS AgentCore Policy now tells customers to "Write Dogwood".
- Dogwood is four weeks old and its reference interpreter is explicitly "NOT intended for production". Adopt the **syntax and the lowering model**, keep plain Cedar as the signed, enforced artefact, and own the session monitor.
- **No candidate natively returns more than allow or deny in a way that stays analysable.** Model richer decisions as (a) *attested preconditions* inside Cedar conditions and (b) *transform then re-evaluate*, with annotations only as hints to the enforcement point.
- **Stateful rules cost time.** Dogwood's durable engine measures 1.23 ms per decision at 10 policies (1.18 ms is the fsync floor) and 6.45 ms at 1,000. AgentCore caps temporal policies at 20 per engine, 3 operators per policy, 24 h windows. Sub-millisecond needs monitors updated at observe time, so the decision is a pure Cedar evaluation.
- **Detection language: Sigma** (rules plus correlation spec v2.1.0, 2025-08-02) as the exchange format, **YARA-X** (Rust, BSD-3, v1.23.0) for content, both feeding session labels and risk that Cedar reads. No permissively licensed Rust Sigma streaming engine exists (Hayabusa is AGPL-3.0, Chainsaw GPL-3.0); build a small one.
- **Interop surface: agent-hooks / Agent Control Specification** (Microsoft-affiliated, MIT, Rust; eight interception points; verdicts allow, deny, transform plus warn and escalate) and **AuthZEN Authorization API 1.0** (Final, 2026-01-11) for remote PDP calls.
- **Rego is the main rejected alternative**: not analysable, Go-first. But NVIDIA OpenShell ships it in Rust via `regorus` with a separate Z3 prover, and ACS defaults to OPA, so offer Rego only as an import path.
- Native agent rule formats (Claude Code, Gemini CLI, Codex execpolicy, Cursor hooks) are **compile targets and hook transports, not policy languages**. Claude Code's own docs say a Bash rule "isn't a security boundary".
- Commercial incumbents (BeyondTrust AI Agent Security, Microsoft Defender real-time protection for Agent 365) expose GUI rules only: block, audit, hold for approval, allow. An open, testable, analysable policy language is whitespace.

## Findings

### 1. Cedar (verified)

- Releases: `v4.14.1` and `cedar-policy-symcc-v0.8.1` on 2026-11-02; 4.14.0 (2026-10-17) added `external` declarations and `Schema::schema_link` for linking partial schemas. [Changelog](https://github.com/cedar-policy/cedar/blob/main/cedar-policy/CHANGELOG.md)
- Analysis: SymCC compiles policies to SMT-LIB and checks never-errors, always-allows, always-denies, implies, equivalent, disjoint, each with a counterexample request and entity store. It needs a `cvc5` 1.3.1 binary. The compiler is modelled and verified in Lean. [SymCC README](https://github.com/cedar-policy/cedar/tree/main/cedar-policy-symcc)
- Partial evaluation: type-aware partial evaluation (RFC 95) is still behind the experimental `tpe` feature flag in 4.14.
- Gaps for our use: no regex (only `like` with `*`), no set quantifiers, no path type (RFC PR 115 "path extension type" open since 2026-06-05), templates only have `?principal` and `?resource` slots (generalised templates, PR 98, open since 2025-05), no decision attestation yet (PR 114, `decision_id` plus `policy_set_hash`, open). [RFC PRs](https://github.com/cedar-policy/rfcs/pulls)
- Agent tooling: `cedar-policy-mcp-schema-generator` 0.7.0 (2026-10-22; Rust, WASM, Python) turns MCP tool descriptions into a Cedar schema; `cedar-analysis-mcp-server` exposes analysis to agents. [cedar-for-agents](https://github.com/cedar-policy/cedar-for-agents)
- Performance: the Cedar paper says it "performs far better" than OpenFGA and Rego; I did not verify a microsecond figure. Benchmark before promising sub-millisecond. [arXiv 2403.04651](https://arxiv.org/abs/2403.04651)

### 2. Cedar in agent products (verified)

- **AWS Bedrock AgentCore Policy**: enforced at the AgentCore Gateway; schema auto-generated from tool definitions; one action per tool (`<Target>___<tool>`), arguments at `context.input.*`; principals `AgentCore::OAuthUser` (JWT `sub`, claims as tags) or `AgentCore::IamEntity`; `LOG_ONLY` and `ENFORCE` modes; natural language to Cedar with schema validation and automated-reasoning findings (overly permissive, overly restrictive, unsatisfiable). [Overview](https://docs.aws.amazon.com/bedrock-agentcore/latest/devguide/policy.html), [Core concepts](https://docs.aws.amazon.com/bedrock-agentcore/latest/devguide/policy-core-concepts.html)
- AgentCore adds a third effect, `suppressOutput`, which withholds a tool response after a guardrail check on `context.output.*`. It is not in the open-source Dogwood repository (code search returns 0 hits), although the open grammar parses the effect as any identifier. [Guardrails in policies](https://docs.aws.amazon.com/bedrock-agentcore/latest/devguide/policy-guardrails-in-policies.html)
- AWS states the analyser "cannot interpret a guardrail condition": a `forbid` gated only by a guardrail looks unconditional and is reported "Overly Restrictive". Analysis is blind inside provider and temporal slots.
- **StrongDM Leash** (Apache-2.0, v1.1.7 on 2026-03-11, last push 2026-04-06): Cedar is linted to an enforceable subset and transpiled to an IR loaded into eBPF LSM programs and an HTTP MITM proxy. Actions: `FileOpen`, `ProcessExec`, `NetworkConnect`, `HttpRewrite`, `McpCall`. Documented deviations: statements are "evaluated in the order they appear. The first matching rule … wins" (not Cedar semantics), exec matches path only, MCP `permit` is informational. [CEDAR.md](https://github.com/strongdm/leash/blob/main/docs/design/CEDAR.md)

### 3. Dogwood (verified; new)

- Repository created 2026-07-27, 515 stars, Apache-2.0, "Copyright Amazon.com". Crates: `dogwood-syntax`, `dogwood-language`, `dogwood-formatter`, CLI with `validate`, `lower`, `replay`, `explain`, `format`, `schema mcp`. [Repo](https://github.com/dogwood-policy/dogwood), [Guide](https://dogwood-policy.github.io/dogwood/index.html)
- Temporal sublanguage: a bounded, past-only fragment of metric first-order temporal logic. Operators `formerly`, `previous`, `since`, each with a mandatory `within` window (default cap 24 h); `exists`, `tp(t)`, `count`, `sum`; only `&&` and `!`, no `||`. Event patterns are `Ns::Action::"X"::request|response{ field: pattern }` and can pin to the current request or scope (`eventResource: resource`).
- Lowering: `permit(...) when { context.policy_0__temporal_0 }`. The temporal engine fills the slot; Cedar validates the lowered set.
- Information providers: any `Ns::Fn(args)` call in `when`; hoisted to `context.providers.<id>`; must be pure; run unconditionally on every decision; the reference interpreter fails closed, but a wrong-shaped output can leave a `forbid` unsatisfied, which allows.
- `dogwood explain` is a deterministic policy-to-English translator with no language model. `dogwood replay` runs a policy over a recorded trace.
- `dogwood-local-engine` (created 2026-08-31, 41 stars): incremental and durable, with a demo daemon on two Unix sockets. Benchmarks on a 16-core Xeon: reference 0.30 ms and server 1.23 ms at 10 policies; server 1.70 ms at 100, 6.45 ms at 1,000, 72.4 ms at 10,000. [Benchmarks](https://github.com/dogwood-policy/dogwood-local-engine/blob/main/dogwood-performance/README.md)
- AgentCore limits: 20 temporal policies per engine, 3 temporal operators per policy, 24 h window; changing a temporal policy invalidates open sessions (HTTP 409); rate limits are per caller-supplied session ID, so a new session resets the count. [Temporal policies](https://docs.aws.amazon.com/bedrock-agentcore/latest/devguide/policy-temporal.html)

### 4. Rego, CEL, relationship engines, AuthZEN

- **OPA** v1.22.2 (2026-11-06), active; six of ten listed maintainers are now at Apple. Bundles are tarballs with `.signatures.json` (JWTs over file hashes), OCI distribution and a WASM target. Delta bundles carry data only and are rejected under signature verification unless explicitly allowed. [Bundles](https://www.openpolicyagent.org/docs/management-bundles), [Maintainers](https://github.com/open-policy-agent/opa/blob/main/MAINTAINERS.md)
- **regorus** (Microsoft, Rust, v0.15.0 on 2026-11-09): `no_std` capable, many bindings, README claims OPA v1.2.0 conformance "barring a few builtins"; its sample tests take about 3.6 to 3.9 ms each. [regorus](https://github.com/microsoft/regorus)
- **CEL**: `cel-rust` v0.15.0 (2026-10-06, MIT, 716 stars), conformance work still open. In use for Santa rules, Tetragon `matchCEL`, OpenFGA conditions and SpiceDB caveats. It is an expression language with no combining semantics or analysis tooling.
- **OpenFGA** v1.22.1 and **SpiceDB** v1.57.0 are Go servers (OpenFGA is embeddable as a Go library; SQLite support is beta). Wrong shape for a Rust endpoint.
- **AuthZEN Authorization API 1.0**: Final, 2026-01-11. Subject, action, resource, context in; boolean `decision` plus free-form `context` out (reasons, advice, obligations, step-up hints). Batch endpoint with `deny_on_first_deny`. Discovery at `/.well-known/authzen-configuration`. [Spec](https://openid.net/specs/authorization-api-1_0.html)

### 5. Agent-specific formats (verified unless noted)

- **Agent Control Specification (ACS) and agent-hooks** (`responsibleai/*`, MIT, Rust, ACS v0.4.0-beta.2 on 2026-11-04; consumed by Microsoft Agent Governance Toolkit, 6.5k stars): stateless, deterministic, fail-closed runtime. Eight interception points (`agent_startup`, `input`, `pre_model_call`, `post_model_call`, `pre_tool_call`, `post_tool_call`, `output`, `agent_shutdown`). Policy types `rego` (OPA default) and `cedar`. Cedar gets richer verdicts through an `advice` annotation (`warn`, `escalate`, `transform`). `escalate` is a "liftable deny" resolved by a host approval path bound to `enforced_identity`, a SHA-256 of the post-transform input. Information-flow labels travel as `ifc.source_labels` in and `result_labels` out; the host owns taint. [Spec](https://github.com/microsoft/agent-governance-toolkit/blob/main/policy-engine/spec/SPECIFICATION.md)
- **NVIDIA OpenShell** (21.3k stars, v0.1.7 on 2026-11-03, Rust): YAML sandbox policy (filesystem, Landlock, per-binary network endpoints with L7 REST presets) evaluated by an embedded Rego file through `regorus` 0.9, plus `openshell-prover`, a Z3-based "formal policy verification" crate. RFC 0002 has agents draft narrow policy changes that a human approves; org ceilings and trusted auto-apply are deferred. [RFC 0002](https://github.com/NVIDIA/OpenShell/tree/main/rfc/0002-agent-driven-policy-management)
- **Gemini CLI policy engine**: TOML rules with `toolName`, `mcpName`, `argsPattern` (regex over stable JSON), `commandPrefix` or `commandRegex`, `subagent`, `toolAnnotations`, `modes`, `denyMessage`; decisions `allow`, `deny`, `ask_user`; tiers Default, Extension, Workspace (currently disabled), User, Admin with `tier_base + priority/1000`; admin directories must be root-owned. [Docs](https://github.com/google-gemini/gemini-cli/blob/main/docs/reference/policy-engine.md)
- **Codex execpolicy** (Rust, "still in preview"): Starlark `prefix_rule(pattern, decision = allow|prompt|forbidden, justification, match, not_match)`; inline examples are checked at load time; strictest decision wins. [README](https://github.com/openai/codex/blob/main/codex-rs/execpolicy/README.md)
- **Claude Code**: `Tool(specifier)` rules evaluated deny, then ask, then allow; an allow cannot carve an exception out of a deny; managed settings cannot be overridden; `PreToolUse` hooks return `allow`, `deny`, `ask` or `defer` plus `updatedInput`, and cannot bypass deny or ask rules; `PostToolUse` can replace output with `updatedToolOutput`. Docs warn argument-constraining Bash patterns are "fragile". [Permissions](https://code.claude.com/docs/en/permissions), [Hooks](https://code.claude.com/docs/en/hooks)
- **Cursor hooks**: `beforeShellExecution`, `beforeMCPExecution`, `beforeReadFile`, `preToolUse` and others return `permission: allow|deny|ask`, `user_message`, `agent_message`, `updated_input`. Hooks **fail open by default**; `failClosed: true` is per hook and unavailable for dashboard-distributed hooks. No built-in allow-list language. [Hooks](https://cursor.com/docs/agent/hooks)
- **Invariant Guardrails** (Apache-2.0; last code push 2025-07, docs moved 2026-01): Python-like `raise "msg" if: (call: ToolCall) -> (call2: ToolCall)` flow rules with `prompt_injection(...)` detectors. Expressive for sequences, raise-only, Python runtime. [Repo](https://github.com/invariantlabs-ai/invariant)
- **AgentSpec** (ICSE 2026): trigger, predicate, enforcement rules; over 90% prevention on code agents; millisecond overhead. **Progent** (arXiv v3, 2026-05-14): symbolic rules over tool names and arguments; an SMT solver classifies each policy update as narrowing (auto-apply) or expansion (needs approval). Abstracts only were read.

### 6. Runtime-security and detection formats

- **Tetragon** v1.8.0: selectors now include `matchCEL` (in-kernel CEL), `matchStates` with `UpdateState`, and `matchBinaries` with `followChildren`; hard limits of 5 selectors per hook and 4 values per argument filter. [Selectors](https://tetragon.io/docs/concepts/tracing-policy/selectors/)
- **Santa** 2026.9: CEL rules over `target.*` (cacheable) and `args`, `envs`, `euid`, `cwd`, `ancestors` (uncacheable); return values include `REQUIRE_TOUCHID`, `REQUIRE_SECURITY_KEY` and `..._with_cooldown_minutes(N)`; `add_annotation(['claude-code-{session}', ...])` tags a process tree. Several helpers need the paid Workshop server. [Binary authorization](https://northpole.dev/features/binary-authorization/)
- **Falco** 0.45.2 and **KubeArmor** 1.7.x: stateless single-event conditions; KubeArmor actions Allow, Audit, Block.
- **Sigma correlations** v2.1.0: `event_count`, `value_count`, `temporal`, `temporal_ordered`, plus `value_sum`, `value_avg`, `value_percentile`; `group-by`, `timespan`, `aliases`. [Spec](https://github.com/SigmaHQ/sigma-specification/blob/main/specification/sigma-correlation-rules-specification.md)
- **EQL** sequences (`sequence by … with maxspan`, `until`, missing events, `runs`) are richer, but the docs admit sequences "do not find all possible matches", and there is no Rust engine. **YARA-L 2.0** has `match: $user over 5m` and aggregation outcomes; Google SecOps only. [EQL](https://www.elastic.co/docs/reference/query-languages/eql/eql-syntax), [YARA-L](https://docs.cloud.google.com/chronicle/docs/detection/yara-l-2-0-syntax)
- **Commercial reference points**: BeyondTrust AI Agent Security (Windows and macOS) applies policy "to actions, not prompts or shell commands" at kernel, network and hook level, with block, audit, held-for-approval, allow, and replays recorded activity before a policy is saved; no syntax is published. Microsoft Defender real-time protection (Agent 365 generally available 2026-05-01) offers a default audit rule plus custom block rules made of agent scope and four fixed detection types. [BeyondTrust](https://docs.beyondtrust.com/bt-docs/docs/ai-agent-security), [Defender](https://learn.microsoft.com/en-us/defender-xdr/security-for-ai/ai-agent-real-time-protection)

## Matrix

| Candidate | Decisions | Stateful | Analysable | Rust and WASM | Layering | Verdict |
|---|---|---|---|---|---|---|
| Cedar 4.14 | permit, forbid | No | Yes (SymCC) | Native | None built in | **Core** |
| Dogwood 1.1 | permit, forbid | Yes, bounded past | Lowered Cedar only | Native (young) | `lower_many` | **Front-end syntax** |
| Rego / regorus | Any JSON | Via data | No | regorus | Bundle roots | Import only |
| CEL / cel-rust | Any value | No | No | Yes | None | Sensor predicates |
| OpenFGA, SpiceDB | Boolean | No | Limited | No | Per store | Optional sync source |
| ACS / agent-hooks | allow, deny, transform, warn, escalate | Host-owned | Depends on backend | Native | `extends` | **Wire contract** |
| Invariant | raise | Trace flows | No | No | No | Ideas only |
| Gemini TOML | allow, deny, ask_user | No | No | n/a | 5 tiers | Compile target |
| Codex execpolicy | allow, prompt, forbidden | No | Inline tests | Rust | File order | Compile target |
| Claude Code rules | allow, ask, deny | No | No | n/a | Managed over user | Compile target |
| Tetragon | Sigkill, Override, Post | `matchStates` | No | n/a | CRDs | Compile target (Linux) |
| Santa | allow, block, require presence | Annotations | No | n/a | Sync server | Compile target (macOS) |
| Sigma + correlations | Alert | Windows, ordered | No | Build it | Rule repos | **Detections** |
| EQL, YARA-L, KQL | Alert | Yes | No | No | SIEM | Conversion targets |
| YARA-X | Match | No | No | Native | Rule files | **Content** |

## Weak points, gaps and risks

- **Dogwood maturity and control.** Single vendor, four weeks past 1.0, a breaking Rust API change already in 1.1, reference interpreter not for production. Mitigation: the signed artefact is lowered Cedar; Dogwood is a replaceable front end.
- **Analysis stops at slots.** SymCC sees temporal and provider slots as opaque booleans. Treat them as free variables (sound over-approximation) and cover the rest with trace replay.
- **Cedar expressiveness.** No regex, quantifiers or path type. Path canonicalisation, shell parsing and SQL classification must happen in normalisers that emit typed facts. That code is security-critical and outside the analyser.
- **Transpiled enforcement can drift from Cedar semantics** (Leash's first-match ordering). A kernel compile step must preserve forbid-overrides or refuse to compile.
- **Session identity is caller-supplied** in AgentCore. Bind sessions to process-tree identity from the OS sensor, not to anything the agent reports.
- **Provider failure polarity**: a failed scorer can silently disable a `forbid`. Normalise provider errors to deny in our engine.
- **Hook transports fail open** (Cursor by default; Claude hook timeouts unless `onFailure: "block"`). OS sensors are the backstop.
- **`cvc5` is an external binary**, so analysis is a control-plane and CLI feature first.

## Implications for our design

**Layer 0, one typed action model.** A Cedar schema `AIDR::` with principal `Session` (in `Agent`, in `Group`, in `Tenant`; attributes `agent`, `sponsor`, `device`, `workspace`, `risk`, `labels`), human principal `User`, resources `File`/`Dir` (ancestor chain supplied per request), `Host`, `Repo`, `Secret`, `McpServer`, `ModelEndpoint`, and actions `FileRead`, `FileWrite`, `FileDelete`, `Exec`, `NetConnect`, `PromptSubmit`, `ToolResult`, `Approve`, plus one generated action per MCP tool under `Action::"CallTool"`. Agent versus human is the principal type.

**Layer 1, authorisation.** Author in Cedar, with Dogwood `temporal` blocks and provider calls where needed. Compile to plain Cedar plus a slot manifest. On the endpoint: `cedar-policy` evaluator, an incremental in-memory session monitor that updates slots when events are observed (durability asynchronous), and provider results cached per content hash.

**Layer 2, obligations without a new effect.** Two mechanisms, both pure Cedar:
1. *Attested preconditions*: `forbid … unless { evidence }`, where evidence is something the enforcement point or approval service produced (`context.enforcement.sandboxed`, a recorded `Approve` event, `context.auth.step_up_age_s`, `context.credential.ephemeral`).
2. *Transform then re-evaluate*: the enforcement point applies a remedy (redact, rewrite arguments, swap in a just-in-time credential) and asks again about the transformed request.

`@obligation("…")`, `@message("…")` and `@steer("…")` annotations only tell the enforcement point which remedy to try. Ignoring an annotation yields a plain deny, never an unsafe allow. Map outcomes to host vocabularies: ask (Claude `ask`, Gemini `ask_user`, Codex `prompt`, ACS `escalate`), transform (`updatedInput`, `updated_input`, ACS `transform`), steer (deny plus `agent_message`).

**Layer 3, composition.** Each tier (MSP, tenant, group, device, user) publishes a policy set tagged `@tier` and `@mode("locked"|"default")`. The compiler builds one effective set per device. Locked forbids are emitted as written. Default rules can be replaced by ID lower down. An exception rewrites its target to `forbid … unless { <scope> && context.now < datetime("…") }` and is garbage-collected after expiry. Publish gate: SymCC `check_implies(child, parent_ceiling)`; narrowing changes auto-apply, expansions need approval (Progent's rule).

**Layer 4, detections.** Sigma rules and correlations over our event taxonomy, evaluated by our own Rust streaming matcher; YARA-X and classifiers as providers. Detections write session labels and risk, which Cedar reads. Convert the same Sigma to KQL, EQL or SPL with pySigma for customers' SIEMs.

**Layer 5, compile targets and distribution.** From the effective Cedar set, generate coarse native configs (Claude managed settings, Gemini admin TOML, Codex `.rules`, Cursor `hooks.json`) and kernel tables (Tetragon TracingPolicy, Santa rules), refusing constructs that cannot be preserved. Ship a signed bundle (lowered Cedar, schema, slot manifest, Sigma, YARA-X) and stamp `policy_set_hash` and a decision ID on every decision. Expose the PDP through agent-hooks/ACS locally and AuthZEN remotely.

### Worked examples

Syntax is Cedar plus Dogwood temporal and provider forms. `unless temporal` is accepted by the published grammar; confirm each example with `dogwood validate` before relying on it.

```cedar
def temporal approved(?w) {
  formerly within ?w AIDR::Action::"Approve"::response{
    input.digest: context.digest, output.granted: true }
};

// 1. Block destructive deletes outside the workspace.
// The shell normaliser turns rm -rf, Remove-Item -Recurse and git clean into
// FileDelete requests; the OS sensor raises the same action on unlink.
@id("fs.delete-outside-workspace") @tier("tenant") @mode("locked")
@message("Deletes outside the session workspace are blocked.")
forbid (principal is AIDR::Session, action == AIDR::Action::"FileDelete", resource)
when { context.recursive || resource is AIDR::Dir }
unless { resource in principal.workspace || resource in AIDR::Dir::"session-tmp" };

// 2. Deny agent reads of cloud credentials unless approved just in time.
@id("secrets.cloud-creds-jit") @obligation("approve")
forbid (principal is AIDR::Session, action == AIDR::Action::"FileRead", resource)
when { resource has labels && resource.labels.contains("cloud-credential") }
unless temporal { approved(15m) };

// Approvals are authorised by the same engine: the sponsor, not the agent.
@id("approve.sponsor-only")
permit (principal is AIDR::User, action == AIDR::Action::"Approve", resource is AIDR::Session)
when { principal == resource.sponsor && context.auth.step_up_age_s < 300 };

// 3. MCP server allow-list with per-tool argument constraints.
@id("mcp.allowlist") @mode("locked")
forbid (principal is AIDR::Session, action in AIDR::Action::"CallTool", resource is AIDR::McpServer)
unless { resource.approved && resource.manifest_digest == resource.pinned_digest };

@id("mcp.github.create-issue")
permit (principal in AIDR::Group::"engineering",
        action == McpGitHub::Action::"create_issue",
        resource == AIDR::McpServer::"github")
when { context.input.owner == "acme" &&
       ["web", "api", "infra"].contains(context.input.repo) &&
       !(context.input.body like "*PRIVATE KEY*") };

@id("mcp.postgres.read-only")
permit (principal in AIDR::Group::"engineering",
        action == McpPostgres::Action::"query",
        resource == AIDR::McpServer::"postgres-staging")
when { context.sql.kind == "select" && !context.sql.tables.containsAny(["users_pii"]) };

// 4. Lethal-trifecta egress gate: untrusted input, private data, external send.
@id("trifecta.egress-gate") @obligation("approve")
@steer("This session mixed untrusted content with private data. Summarise what you want to send and ask the user.")
forbid (principal is AIDR::Session, action in AIDR::Action::"Egress", resource)
when { principal.labels.containsAll(["untrusted_input", "private_data"]) }
unless { resource in AIDR::HostSet::"tenant-trusted" }
unless temporal { approved(10m) };

// 5. Human approval for production deploys; the approver is not the sponsor.
@id("deploy.prod-needs-human") @obligation("approve")
forbid (principal is AIDR::Session, action in AIDR::Action::"Deploy", resource is AIDR::Environment)
when { resource.stage == "production" }
unless temporal { approved(30m) };

@id("approve.release-managers")
permit (principal in AIDR::Group::"release-managers", action == AIDR::Action::"Approve", resource is AIDR::Session)
when { principal != resource.sponsor };

// 6. Redact secrets in prompts: liftable by transform, then re-evaluated.
@id("prompt.redact-secrets") @obligation("redact")
forbid (principal, action in [AIDR::Action::"PromptSubmit", AIDR::Action::"ToolResult"], resource is AIDR::ModelEndpoint)
when { Content::Secrets(context.input.text).count > 0 };
```

The detection half of example 4, which sets the labels and raises an alert:

```yaml
title: Untrusted content then private read then external send
correlation:
  type: temporal_ordered
  rules: [agent_untrusted_tool_result, agent_private_file_read, agent_external_egress]
  group-by: [session.id]
  timespan: 24h
```

### Rejected alternatives

- **Rego as the core**: decisions are arbitrary JSON, so conflicts, shadowing and effect diffs cannot be proven; OPA is Go; signed delta bundles are unsupported. Keep an importer because ACS and OpenShell users will arrive with Rego.
- **CEL as the core**: no principal, action, resource model, no combining algorithm, no analyser. Good for single-event predicates inside sensors.
- **OpenFGA or SpiceDB on the endpoint**: Go servers with a datastore. Cedar entity hierarchies cover sponsor and delegation edges locally; sync from a relationship store in the control plane if a tenant has one.
- **A new effect such as `ask` or `suppressOutput`**: forks the language and loses SymCC. AgentCore's `suppressOutput` is not in open-source Dogwood.
- **XACML-style obligations returned by the engine**: Cedar has none, and ACS's `advice` annotation makes safety depend on the host honouring it. Preconditions re-checked by the policy do not.
- **Invariant, AgentSpec, Colang as the language**: Python runtimes, raise-only or dialogue-oriented, no layering or analysis. Take the flow-rule idea, expressed as Dogwood temporal conditions.
- **Running the Dogwood engines as shipped**: the reference interpreter rescans history, and the durable engine pays an fsync per event.
- **EQL, YARA-L or KQL as the native detection format**: tied to one vendor's backend, no Rust engine. Reach them by conversion from Sigma.
- **Native agent rule files as the source of truth**: each is lossy and agent-specific; generate them.

## Ideas worth stealing and whitespace

- **Deterministic back-translation** (`dogwood explain`) as the verification step for natural-language authoring: generate, validate, SMT-check, explain, replay, shadow, enforce.
- **Replay before save** (BeyondTrust; `dogwood replay`; AgentCore `LOG_ONLY`): show which past actions a draft would have blocked.
- **Inline `match` and `not_match` examples** as load-time unit tests (Codex execpolicy).
- **Approval bound to a hash of the post-transform action** (ACS `enforced_identity`).
- **Narrowing auto-applies, expansion needs approval**, decided by SMT (Progent), for agent-drafted policy changes (OpenShell RFC 0002).
- **Process-tree annotation in the sensor** (Santa `add_annotation`) as the anchor for session identity.
- **Deny bodies that carry `next_steps`** for the agent (OpenShell), turning denials into steering.
- Whitespace: nobody ships one policy that is analysable, compiles to both hook and kernel enforcement, composes across MSP tiers with proofs, and runs offline on a laptop. AgentCore is closest and is cloud-gateway-only.

## Could not verify / open questions

- Cedar evaluation latency in microseconds on endpoint hardware; no primary number read.
- Whether `unless temporal { … }` and a negated closed temporal formula pass Dogwood's monitorability checks; grammar accepts them, semantics untested.
- Whether Dogwood provider outputs may be set-typed in the open-source implementation.
- AgentCore Policy general-availability date and non-temporal quotas.
- Full Progent and AgentSpec rule grammars (abstract pages only); NeMo Colang 2 agent rails; KQL; Kubernetes admission CEL status were not re-read.
- Invariant's roadmap after its docs moved; treat as stale.
- BeyondTrust policy syntax and Agent 365 pricing are not public on the pages read.
- Licence of `cvc5` for bundling (believed BSD-3; not checked).

## Sources

- Cedar changelog and releases, 2026-11-02: https://github.com/cedar-policy/cedar/blob/main/cedar-policy/CHANGELOG.md
- Cedar SymCC README: https://github.com/cedar-policy/cedar/tree/main/cedar-policy-symcc
- Cedar RFC pull requests (98, 114, 115): https://github.com/cedar-policy/rfcs/pulls
- cedar-for-agents, 2026-10-22: https://github.com/cedar-policy/cedar-for-agents
- Cedar paper, 2024-03: https://arxiv.org/abs/2403.04651
- AgentCore Policy overview, core concepts, temporal, guardrails, enforcement modes (read 2026-11-09): https://docs.aws.amazon.com/bedrock-agentcore/latest/devguide/policy.html
- Dogwood repo, guide, release notes, 2026-10 to 2026-11: https://github.com/dogwood-policy/dogwood and https://dogwood-policy.github.io/dogwood/index.html
- Dogwood local engine and benchmarks: https://github.com/dogwood-policy/dogwood-local-engine
- StrongDM Leash Cedar reference, 2026-03: https://github.com/strongdm/leash/blob/main/docs/design/CEDAR.md
- OPA bundles and maintainers: https://www.openpolicyagent.org/docs/management-bundles
- regorus: https://github.com/microsoft/regorus
- cel-rust, 2026-10-06: https://github.com/cel-rust/cel-rust
- AuthZEN Authorization API 1.0, 2026-01-11: https://openid.net/specs/authorization-api-1_0.html
- Agent Governance Toolkit and ACS spec, 2026-11: https://github.com/microsoft/agent-governance-toolkit/tree/main/policy-engine
- NVIDIA OpenShell, 2026-11-03: https://github.com/NVIDIA/OpenShell
- Gemini CLI policy engine: https://github.com/google-gemini/gemini-cli/blob/main/docs/reference/policy-engine.md
- Codex execpolicy: https://github.com/openai/codex/blob/main/codex-rs/execpolicy/README.md
- Claude Code permissions and hooks: https://code.claude.com/docs/en/permissions and https://code.claude.com/docs/en/hooks
- Cursor hooks: https://cursor.com/docs/agent/hooks
- Invariant Guardrails: https://github.com/invariantlabs-ai/invariant
- AgentSpec, ICSE 2026: https://arxiv.org/abs/2503.18666
- Progent v3, 2026-05-14: https://arxiv.org/abs/2504.11703
- Tetragon selectors, v1.8.0: https://tetragon.io/docs/concepts/tracing-policy/selectors/
- Santa binary authorization, 2026.9: https://northpole.dev/features/binary-authorization/
- Sigma correlation spec v2.1.0, 2025-08-02: https://github.com/SigmaHQ/sigma-specification/blob/main/specification/sigma-correlation-rules-specification.md
- Elastic EQL syntax: https://www.elastic.co/docs/reference/query-languages/eql/eql-syntax
- YARA-L 2.0 syntax: https://docs.cloud.google.com/chronicle/docs/detection/yara-l-2-0-syntax
- YARA-X, v1.23.0: https://github.com/VirusTotal/yara-x
- BeyondTrust AI Agent Security: https://docs.beyondtrust.com/bt-docs/docs/ai-agent-security
- Microsoft Agent 365 overview, updated 2026-10-23: https://learn.microsoft.com/en-us/microsoft-agent-365/overview
- Microsoft Defender real-time protection for AI agents, updated 2026-10-20: https://learn.microsoft.com/en-us/defender-xdr/security-for-ai/ai-agent-real-time-protection

## Independent verification

_Checked 2026-11-09 by a separate fact-checker against primary sources (GitHub API and raw files via `gh`, crates.io API, vendor docs). Nothing above this heading was changed._

Two items need a change in the plan: the Sigma tooling claim (9, and the "build a small one" conclusion that follows from it) and the description of Leash's rule ordering (8). Everything else held.

| # | Claim | Verdict | Note | Source |
|---|---|---|---|---|
| 1 | Cedar crate 4.14.1 (2026-11-02, language 4.6); `cedar-policy-symcc` 0.8.1 proves always-allows, always-denies, implies, equivalent, disjoint with counterexamples; needs external cvc5 1.3.1 | confirmed | GitHub release and crates.io both show 4.14.1 and symcc 0.8.1 on 2026-11-02; changelog says "Cedar Language Version: 4.6". README lists the five checks plus never-errors, each with a `_with_counterexample` variant, and tells you to download cvc5-1.3.1 and set `CVC5`. SymCC is a separate crate in the same repo and spawns cvc5 as a process. cvc5 upstream is already at 1.4.2. | https://github.com/cedar-policy/cedar/blob/main/cedar-policy/CHANGELOG.md ; https://crates.io/crates/cedar-policy-symcc |
| 2 | Dogwood: Apache-2.0, Amazon copyright, Cedar superset, v1.0 2026-10-13, v1.1.1 2026-11-06, lowers to Cedar with context slots, reference interpreter not for production | confirmed | LICENSE Apache-2.0; NOTICE "Copyright Amazon.com, Inc. or its affiliates". Releases: v1.0 2026-10-13, v1.1 2026-10-14, v1.0.1 and v1.1.1 2026-11-06. README: "policies lower to standard Cedar; the temporal and provider fields become `context.*` slots" and "This reference interpreter is **NOT** intended for production use". "Superset" is AWS's wording ("every valid Cedar policy is also a valid Dogwood policy"); the repo itself says "supports Cedar policies and adds temporal conditions". | https://github.com/dogwood-policy/dogwood/blob/main/README.md ; https://github.com/dogwood-policy/dogwood/releases |
| 3 | AgentCore Policy enforces Cedar and Dogwood at the gateway, recommends Dogwood, limits 20 temporal policies per engine, 3 temporal operators per policy, 24 h window | confirmed | Core concepts page: "**Write Dogwood.** Dogwood is a superset of Cedar". Temporal page quota table: 20 / 3 / 24 hours. Enforcement is at AgentCore Gateway. The overview page still describes Cedar as the base language and Dogwood as "also supported", so the docs are not fully consistent on emphasis. | https://docs.aws.amazon.com/bedrock-agentcore/latest/devguide/policy-core-concepts.html ; https://docs.aws.amazon.com/bedrock-agentcore/latest/devguide/policy-temporal.html |
| 4 | Dogwood durable engine: 1.23 ms at 10 policies (1.18 ms fsync floor), 1.70 ms at 100, 6.45 ms at 1,000, 72.4 ms at 10,000 on a 16-core Xeon | confirmed | Exact figures. Conditions: Xeon 8259CL at 2.50 GHz, NVMe/ext4, 200 events of history, sequential. README says "Machine-specific; re-run before trusting these". The in-memory reference engine is 0.30 ms at 10 policies and 233 ms at 10,000. Under load, 1,000 policies are "at the edge" at 100 rps (p99 171 ms). | https://github.com/dogwood-policy/dogwood-local-engine/blob/main/dogwood-performance/README.md |
| 5 | AWS validation cannot interpret guardrail conditions, so a forbid gated only by a guardrail is treated as unconditional; analysis is blind inside hoisted slots | confirmed (first half); second half is inference | AWS: "Policy validation analyzes the whole policy set in your engine, and it cannot interpret a guardrail condition. A `forbid` whose only gate is a guardrail therefore looks unconditional". AWS documents this for guardrails only; I found no AWS statement about temporal conditions, and the temporal authoring example is created with `FAIL_ON_ANY_FINDINGS`. Note AWS drops the condition (treats it as true), which is different from the free-variable treatment the brief recommends; SymCC run on lowered Cedar would see the slot as an unconstrained context attribute. | https://docs.aws.amazon.com/bedrock-agentcore/latest/devguide/policy-guardrails-in-policies.html ; https://docs.aws.amazon.com/bedrock-agentcore/latest/devguide/policy-validation-overview.html |
| 6 | ACS runtime is stateless and fail-closed, eight interception points, `rego` and `cedar` policy types, verdicts allow, deny, transform plus warn and escalate, approvals bound to SHA-256 `enforced_identity` | confirmed, with refinements | All elements are in the spec. Refinements: (a) the verdict set is closed at three; `warn` and `escalate` are policy intents normalised to `allow` plus `warnings[]` and `deny` plus an `approval` block. (b) The schema defines four policy types: `rego`, `cedar`, `test`, and `custom` (a host adapter, "the extension point through which a host adds any other backend"). (c) The cited file is AGT's compatibility profile and pins `agent-control-spec` at 0.4.0-alpha.4; upstream is 0.4.0-beta.2 (2026-11-04). (d) The spec says "intervention points"; agent-hooks says "interception points". | https://github.com/microsoft/agent-governance-toolkit/blob/main/policy-engine/spec/SPECIFICATION.md ; https://github.com/responsibleai/agent-control-spec/releases |
| 7 | Cedar has no path type, generalised templates or decision attestation; RFC PRs 115, 98, 114 still open | confirmed | GitHub API on 2026-11-09: PR 98 "Generalized Cedar Templates" open since 2025-05-19; PR 114 "Decision attestation fields (decision_id, policy_set_hash)" open since 2026-04-21; PR 115 "Propose a path extension type" open since 2026-06-05, last updated 2026-10-27. None merged. `tpe` is still in the `experimental` feature set in `cedar-policy/Cargo.toml`. | https://github.com/cedar-policy/rfcs/pull/115 ; https://github.com/cedar-policy/rfcs/pull/98 ; https://github.com/cedar-policy/rfcs/pull/114 |
| 8 | Leash transpiles Cedar to eBPF LSM and proxy rules, first match in statement order wins, exec matches path only, MCP permit is informational | corrected | The quotes are accurate, but the ordering is not what the doc's sentence says. The same CEDAR.md also states "Default posture is deny; `forbid` wins over a conflicting permit", and the code (`internal/lsm/file_open.go`, `proc_exec.go`) sorts rules by path length, longest first, then the BPF program returns the first prefix match. So the effective rule is most-specific-path wins, not statement order and not forbid-overrides: a broad `forbid` can be overridden by a narrower `permit`. Exec path-only and MCP permit informational are confirmed. The conclusion (deviates from Cedar semantics) stands and is stronger than stated. | https://github.com/strongdm/leash/blob/main/internal/lsm/file_open.go ; https://github.com/strongdm/leash/blob/main/docs/design/CEDAR.md |
| 9 | Sigma correlation spec v2.1.0 (2025-08-02) has event_count, value_count, temporal, temporal_ordered with group-by and timespan; mature Rust Sigma tools are copyleft (Hayabusa AGPL-3.0, Chainsaw GPL-3.0) | corrected | Spec version, date, types, `group-by` and `timespan` confirmed (the GitHub release tag v2.1.0 is dated 2025-09-12). Hayabusa AGPL-3.0 and Chainsaw GPL-3.0 confirmed. But permissively licensed Rust Sigma engines exist: `timescale/rsigma` (MIT, v0.26.0 on 2026-11-02, 186 stars, created 2026-02) ships parser, evaluator, a correlation engine covering all correlation types with sliding windows and group-by, a streaming daemon and SQLite state persistence, and `rsigma-eval` builds for `wasm32`; `jopohl/sigma-rust` (MIT OR Apache-2.0, 106k crate downloads, detection only); `Karib0u/rustinel` (Apache-2.0, 531 stars, endpoint Sigma plus YARA). | https://github.com/timescale/rsigma ; https://crates.io/crates/rsigma-eval ; https://github.com/SigmaHQ/sigma-specification/blob/main/specification/sigma-correlation-rules-specification.md |
| 10 | Hook transports are not reliable enforcement: Cursor hooks fail open by default; Claude Code says Bash permission rules are not a security boundary around a program | confirmed | Cursor: "Crashes, timeouts, and non-zero exit codes other than `2` fail open by default"; `failClosed: true` is per hook; "Dashboard hooks don't take per-hook options such as `failClosed`". Nuance: invalid JSON or a schema-invalid response blocks even without `failClosed`. Claude Code permissions: a Bash rule "isn't a security boundary around the program"; hooks page: on failure "Claude Code still carries out the action" unless `onFailure: "block"` (v2.1.295 or later). | https://cursor.com/docs/agent/hooks ; https://code.claude.com/docs/en/permissions ; https://code.claude.com/docs/en/hooks |

### Further statements checked in the brief

| Statement in brief | Verdict | Note | Source |
|---|---|---|---|
| TL;DR and Layer 4: "No permissively licensed Rust Sigma streaming engine exists ... build a small one" | refuted | See row 9. `rsigma` (MIT) already provides a Rust Sigma evaluator, correlation engine and streaming runtime as separate crates (`rsigma-parser`, `rsigma-ir`, `rsigma-eval`, `rsigma-runtime`). It is nine months old and pre-1.0, so evaluate it (API stability, memory bounds, embedding without the daemon) before deciding to build. The "Sigma + correlations: Build it" matrix cell should become "evaluate rsigma first". | https://github.com/timescale/rsigma |
| Open question: whether `unless temporal { … }` passes Dogwood's checks ("grammar accepts them, semantics untested") | corrected | The language guide documents it: "`unless temporal { φ }` blocks when `φ` holds — which is the idiomatic way to express absence". Macro calls are valid atoms inside a temporal block and `within ?w` is legal in a `def temporal` body. The worked examples still need a `dogwood validate` run, because every variable must be range-restricted by a positive atom and AgentCore additionally requires `eventResource: resource` in each predicate. | https://github.com/dogwood-policy/dogwood/blob/main/dogwood-docs/guide/04-temporal-expressions.md |
| Open question: cvc5 licence "believed BSD-3; not checked" | confirmed | cvc5 `COPYING`: modified BSD licence. It "can be configured (however, by default it is not) to link against some GPLed libraries" (CLN, glpk-cut-log, CoCoALib, Normaliz), so ship a non-GPL build. It links GMP (LGPL v3) by default. SymCC calls it as a subprocess, so there is no linking into our binary. | https://github.com/cvc5/cvc5/blob/main/COPYING |

Also spot-checked and found accurate: OPA v1.22.2 (2026-11-06) with six of ten maintainers at Apple; OPA delta bundles are data-only and "do not support bundle signing"; regorus v0.15.0 (2026-11-09); cel-rust v0.15.0 (MIT, 716 stars); YARA-X v1.23.0 (BSD-3-Clause); OpenShell v0.1.7 with `regorus = "0.9"` and a `z3` dependency; Tetragon v1.8.0; Santa 2026.9; OpenFGA v1.22.1; SpiceDB v1.57.0; Falco 0.45.2; AuthZEN Authorization API 1.0 Final, published 11 January 2026, with `deny_on_first_deny`; Dogwood provider contract (unconditional execution, wrong-shaped non-enum output can leave a `forbid` unsatisfied); `suppressOutput` has zero code-search hits in the `dogwood-policy` org; BeyondTrust AI Agent Security (Windows and macOS only, four outcomes, replay before save, no published syntax); Microsoft Defender real-time protection (default audit rule, custom block rules, four detection types); Agent 365 generally available 2026-05-01.
