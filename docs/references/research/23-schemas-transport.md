# Event schema, tamper-evident audit, sensor transport and fleet management for an open-source AIDR

_Researched 2026-11-09_

Method note: the web-search quota for this run was exhausted before this brief started, so everything below comes from reading primary sources directly (GitHub repositories and release notes through `gh`, spec and docs pages through fetch). Items I could only state from prior knowledge are marked "unverified".

## TL;DR

- **OCSF 1.9.0 (3 Aug 2026) is now agent-aware.** It adds an `ai_agent` object (stable `uid` plus restart-sensitive `instance_uid`, `charter`, `ai_model`), a `delegation` object, and applies the `ai_operation` profile to every System, Network, Application and IAM class, so a normal Process Activity can carry "which agent did this". 1.10.0-dev has already merged `ai_capability` (MCP tool/resource/prompt metadata with schema fingerprints) and `ai_status` (stop reason, permission result).
- **OCSF 1.9.0 also added a `record_integrity` profile**: an `attestation` object with `fingerprint`, `signatures`, `prev_event`, `chain_uid`, `authority_uid`. A per-event hash chain is now a standard field set, not a private extension.
- **OpenTelemetry GenAI conventions are still "Development" and were moved to a new repo** (`open-telemetry/semantic-conventions-genai`, created May 2026). It has no tagged release, its README says "Schema URL: TODO", and its changelog directory holds about 20 pending breaking changes. Treat it as an ingest/export dialect, never as the stored schema.
- OTel GenAI now covers what we need semantically: `invoke_agent`, `execute_tool` (with skill-load, skill-resource and command-execution refinements), MCP client/server spans, A2A spans, `gen_ai.conversation.id`, and a `gen_ai.main_agent` entity. MCP trace context travels in `params._meta` (`traceparent`, `tracestate`, `baggage`).
- **ECS 9.5 and Microsoft Agent 365 both reuse OTel `gen_ai.*` names verbatim.** Agent 365 ingestion is OTLP/HTTP, 1 MB bodies, and only accepts four `gen_ai.operation.name` values. OTel names are the lingua franca for interop; OCSF is the lingua franca for SIEM.
- **OTLP alone is not enough for a security sensor**: the spec only mandates gzip, forbids retry on partial success, accepts duplicates by design, and says nothing about ordering. OTel Arrow beats OTLP+zstd only on large batches in stream mode and is worse at batch size 10.
- **Recommended data plane**: our own protobuf batch stream over gRPC/HTTP/2 with per-batch acks, device sequence numbers and zstd with a trained dictionary, plus a unary HTTP POST fallback and an OTLP ingest/export edge.
- **Recommended control plane**: OpAMP (spec v0.20.0, Beta) for config, health and package offers; TUF (spec 1.0.37, Rust `tough` 0.24) for update metadata, because OpAMP explicitly leaves code-signing to the agent.
- **TLS**: rustls 0.23 with aws-lc-rs prefers hybrid `X25519MLKEM768` by default since 0.23.27 (May 2025) and enables ML-DSA certificates by default since 0.23.44 (Sep 2026). FIPS builds exist but static FIPS is Linux-only and macOS is not listed.
- **Audit**: tile-based transparency logs are the current design (C2SP tlog-tiles, Tessera 1.0.4, Rekor v2 2.4.2); SCITT architecture is now RFC 9943 (June 2026). Regulators ask for complete, time-stamped, attributable records, not Merkle trees, so cryptographic proof is a differentiator rather than a compliance requirement.
- **Nobody ships a standard agent/MCP bill of materials.** CycloneDX closed the Agent BOM and ASBOM proposals (work moved to 2.0 working groups), SPDX 3.1 is still RC1 with agent proposals open, and Sigma's taxonomy has no AI log source at all.

## Findings

### 1. Security event schemas

**OCSF.** Latest release 1.9.0, 2026-08-03; main is `1.10.0-dev` ([releases](https://github.com/ocsf/ocsf-schema/releases), [version.json](https://github.com/ocsf/ocsf-schema/blob/main/version.json)). Verified in the 1.9.0 tree (88 event files, 192 objects):

- `ai_operation` profile attributes: `ai_agent`, `ai_model`, `delegation`, `message_context` ([profile](https://github.com/ocsf/ocsf-schema/blob/1.9.0/profiles/ai_operation.json)). Introduced in 1.8.0 (2026-03-18, PR #1488); extended to the `system`, `network`, `application` and `iam` base classes plus `email_activity` in 1.9.0 (PR #1641).
- `ai_agent`: `uid` (stable, from the authoritative registry or IdP), `instance_uid` (one conversation/run), `name`, `version`, `type_id` (Native, LangChain, AutoGen, CrewAI, Other), `charter`, `ai_model`. `process` gained `ai_agent` and `hosted_ai_agent_list`; `evidences` gained `ai_agent` ([object](https://github.com/ocsf/ocsf-schema/blob/1.9.0/objects/ai_agent.json)).
- `delegation`: `uid`, `issuer_uid`, `parent_uid`, `created_time` (PR #1665).
- `message_context`: `uid`, `ai_role_id`, `application`, `service`, token counts, and `prompt_text` / `response_text` (PR #1674).
- `record_integrity` profile on `base_event` with `attestation_list` (PR [#1661](https://github.com/ocsf/ocsf-schema/pull/1661)). `digital_signature.serialization_id` enumerates Flat, JCS, JWS, COSE, DSSE. Its `algorithm_id` enum has only DSA, RSA, ECDSA and code-signing kinds, so Ed25519 and ML-DSA must be sent as "Other".
- Merged after 1.9.0 (unreleased): `ai_capability` (PR #1729, 2026-10-07) with `type_id` Tool/Resource/Prompt Template, `source_id` MCP/Function/Built-in, `transport_id` stdio/Streamable HTTP/HTTP+SSE, `is_destructive`/`is_readonly`/`is_open_world`/`is_idempotent` hints, `desc_fingerprint`, `input_schema_fingerprint`, `baseline_fingerprint`, `transaction_uid` (JSON-RPC id), `task_uid`; and `ai_status` (PR #1704, 2026-10-13) with `stop_reason_id` and `permission_result_id` (Allowed/Denied).
- Open: draft `AI Agent Activity` class (PR #1754), agent containment / `accounting_decision` (PR #1765, tied to CoSAI WS4), RFC for agent control-plane activity (#1753), "Map Agent Harness Behavior to OCSF" (#1736).

**Sigma.** Specification v2.1.0; taxonomy appendix lists no AI, LLM, agent or MCP product or category ([appendix](https://github.com/SigmaHQ/sigma-specification/blob/main/specification/sigma-appendix-taxonomy.md)). A code search of SigmaHQ rules for such categories returned zero.

**ECS.** ECS 9.5.0 (2026-08-04) has 32 `gen_ai.*` fields, all beta, names matching OTel; content fields (`gen_ai.input.messages`, `gen_ai.tool.call.arguments`, etc.) are `flattened`. The repo pins `otel-semconv-version` v1.38.0. No MCP fields ([schema](https://github.com/elastic/ecs/blob/v9.5.0/schemas/gen_ai.yml), [RFC 0052](https://github.com/elastic/ecs/blob/v9.5.0/rfcs/text/0052-gen_ai-additional-fields.md)).

**STIX/TAXII, OpenC2, CACAO (unverified versions, from prior knowledge).** STIX 2.1 and TAXII 2.1 are OASIS Standards; the `cti-stix2` and `cti-taxii2` repos were pushed in Aug/Sep 2026. OpenC2 repos are mostly dormant (language spec repo last pushed May 2024; the endpoint-response actuator profile Sep 2023). CACAO v2.0 repo last pushed Jan 2024 ([oasis-tcs](https://github.com/oasis-tcs)). Use STIX for intel in/out; do not build the response channel on OpenC2.

**CloudEvents.** Still v1.0.2 (Feb 2022). Useful only as a webhook/bus envelope.

### 2. Observability schemas

**OTel GenAI.** `open-telemetry/semantic-conventions` v1.45.0 (2026-11-02) contains only "Moved" stubs; live docs are in [semantic-conventions-genai](https://github.com/open-telemetry/semantic-conventions-genai). Every signal is "Development". Relevant definitions:

- Agent spans: create agent, invoke agent (client and internal), plan; `invoke_workflow` is being merged into invoke-agent; attributes `gen_ai.agent.id|name|version|description`, `gen_ai.conversation.id`, `gen_ai.conversation.compacted`.
- [Execute tool](https://github.com/open-telemetry/semantic-conventions-genai/blob/main/docs/gen-ai/execute-tool.md): `gen_ai.tool.name`, `gen_ai.tool.call.id`, `gen_ai.tool.type`, opt-in `gen_ai.tool.call.arguments|result`; refinements for agent-as-tool (`gen_ai.transfer.mode`), load skill / read skill resource (`gen_ai.skill.name`, `gen_ai.skill.source.uri`), and command execution.
- [MCP](https://github.com/open-telemetry/semantic-conventions-genai/blob/main/docs/gen-ai/mcp.md): `mcp.method.name`, `mcp.session.id`, `mcp.protocol.version`, `mcp.resource.uri`, `jsonrpc.request.id`, `network.transport`; metrics `mcp.client|server.operation.duration` and `.session.duration`.
- A2A: `a2a.task.id`, `a2a.task.state`, `a2a.message.id`, `a2a.tenant`.
- Entity `gen_ai.main_agent` whose id must be a provider-assigned stable identifier and must not be process-local.
- Content can be externalised with `gen_ai.input.messages_ref` / `gen_ai.output.messages_ref` / `gen_ai.tool.definitions_ref`.

**OpenInference.** Span kinds Chain, Retriever, Reranker, LLM, Embedding, Agent, Tool, Guardrail, Evaluator, Prompt, with its own `llm.*`, `tool.*`, `input.value` namespace ([spec](https://github.com/Arize-ai/openinference/tree/main/spec)). Second ingest dialect; it has a Guardrail kind that OTel lacks.

**Microsoft Agent 365** (GA 1 May 2026). Ingestion is OTLP/HTTP traces with OTel `gen_ai.*` plus `microsoft.a365.agent.blueprint.id`, `microsoft.a365.caller.agent.*`, `microsoft.session.id`, `microsoft.tenant.id`. Limits: 1 MB body, `api-version=1`, `Retry-After: 1` on 429; spans whose `gen_ai.operation.name` is not one of `invoke_agent`, `execute_tool`, `chat`, `output_messages` are dropped; every span must carry `gen_ai.agent.id` equal to the token's appId. Data lands in Defender `CloudAppEvents` with `ActionType` values `InvokeAgent`, `InferenceCall`, `ExecuteToolBySDK`, `ExecuteToolByGateway`, `ExecuteToolByMCPServer` ([concepts](https://learn.microsoft.com/en-us/microsoft-agent-365/developer/observability-concepts), updated 2026-10-23). The original Agent 365 Observability SDK is already deprecated in favour of the "Microsoft OpenTelemetry Distro".

**BeyondTrust AI Agent Security.** Docs describe entities AI agent, agent skill, agentic process, MCP server, AI session, event, finding; kernel and network enforcement plus tool-call hooks; policy replay against recorded activity; Windows 11/Server 2022 x64 and macOS 14 to 26 only; HTTPS inspection needs a tenant root certificate. No export schema, SIEM format or API is documented ([docs](https://docs.beyondtrust.com/bt-docs/docs/ai-agent-security)).

### 3. Inventory and provenance schemas

- **CycloneDX**: 1.7.2 (2026-09-17) is current; 2.0 is in development branches. Agent BOM (#895) and ASBOM (#941) issues were closed with the note that agentic AI is handled by the Blueprints and Threat Modeling working groups; an AI/ML 2.0 schema PR (#948) closed 2026-10-30 ([repo](https://github.com/CycloneDX/specification)).
- **SPDX**: 3.0.1 is the latest final; 3.1 is RC1 (2026-01-24); AI-agent proposals are open in `spdx-3-model` (#1256, #1257).
- **MCP registry**: `server.json` schema dated 2025-12-11; fields `name` (reverse-DNS), `version`, `repository`, `packages[]` (`registryType`, `identifier`, `version`, `transport.type`, `environmentVariables[].isSecret`), `_meta`. Registry release v1.8.8. Tool-signature pinning issue #82 is still open; no attestation field exists ([spec](https://github.com/modelcontextprotocol/registry/blob/main/docs/reference/server-json/generic-server-json.md)).
- **A2A** v1.0.1 (2026-05-28): `AgentCard` has `name`, `version`, `supported_interfaces`, `capabilities`, `security_schemes`, `skills`, and `signatures` (JWS) ([proto](https://github.com/a2aproject/A2A/blob/v1.0.1/specification/a2a.proto)).
- **AGNTCY OASF** 1.1.0 (2026-07-10): OCSF-derived record schema with skills, domains, modules; 1.1 renumbered 61 skills and removed 44, so it is not yet stable enough to key on ([release](https://github.com/agntcy/oasf/releases/tag/v1.1.0)).
- **in-toto attestation** v1.2.0 (2026-03-18): predicates include SLSA provenance, SPDX 3, CycloneDX, SCAI, VSA, SVR, release, and `runtime-trace` v0.2; Rust bindings added. SLSA spec is at v1.2.

### 4. Tamper-evident audit

- **tlog-tiles** ([C2SP](https://c2sp.org/tlog-tiles)): static HTTP GET API; `/checkpoint`, `/tile/<L>/<N>`, `/tile/entries/<N>`; 256 hashes per tile; RFC 6962 SHA-256; partial tiles; explicit pruning rules requiring a published retention policy. Companion specs: tlog-checkpoint, tlog-cosignature, signed-note (all v1.1.0).
- **Tessera** v1.0.4: Go library, GA, POSIX/AWS/GCP drivers, successor to Trillian v1 ([repo](https://github.com/transparency-dev/tessera)). **Trillian** v1.8.0 still released but legacy.
- **Rekor v2** (`rekor-tiles` v2.4.2): binaries per backend including `rekor-server-posix`; only `hashedrekord` and `dsse` entry types; public instance shards about every 6 months, located through TUF ([repo](https://github.com/sigstore/rekor-tiles)).
- **SCITT**: architecture is [RFC 9943](https://datatracker.ietf.org/doc/rfc9943/) (June 2026); SCRAPI draft -11 is in the RFC Editor queue; CCF receipt profile -06 awaiting AD go-ahead.
- **What regulators ask for.** SEC Rule 17a-4 (amended Oct 2022, compliance May 2023) accepts either WORM or a "complete time-stamped audit trail" of all modifications and deletions with date, time and individual identity ([SEC](https://www.sec.gov/investment/amendments-electronic-recordkeeping-requirements-broker-dealers)). EU AI Act Art. 12 requires high-risk systems to "technically allow for the automatic recording of events (logs) over the lifetime of the system"; the page consulted shows application from 2 Dec 2027 for Annex III systems ([Art. 12](https://artificialintelligenceact.eu/article/12/)). Neither names a cryptographic mechanism (inference: object-lock storage plus access control passes audits; proofs are extra assurance).

### 5. Transport

- **OTLP 1.11.1**: gRPC (4317) and HTTP (4318), protobuf or JSON; servers must support `none` and `gzip` only; 64 MiB default request limit; client must not retry on `partial_success`; retryable codes are a fixed list; duplicates are an accepted trade-off; ordering unspecified ([spec](https://opentelemetry.io/docs/specs/otlp/)).
- **OTel Arrow / OTAP**: spec status Draft; bidirectional gRPC stream of `BatchArrowRecords` with per-batch `BatchStatus` acks. Phase-1 benchmark tables show stream-mode Arrow+zstd at 1.6x to 6.4x smaller than OTLP+zstd for batches of 100 to 1000, but 0.27x to 0.95x (larger) for unary batches of 10; a plain "OTLP with dictionary + zstd in stream mode" column reaches 1.4x to 3.4x by itself ([benchmarks](https://github.com/open-telemetry/otel-arrow/blob/main/docs/benchmarks-phase1.md)). The Rust "OTAP Dataflow Engine" (v0.65.0, 2026-11-09) is embeddable, thread-per-core, with a durable-buffer processor.
- **QUIC**: `quinn` is maintained (quinn-udp 0.6.3, Sep 2026) and inherits rustls key exchange. Inference: UDP/443 is frequently blocked or inspected on corporate networks, so QUIC cannot be the only path.

### 6. Fleet management

- **OpAMP** v0.20.0 (2026-08-12), status Beta. WebSocket and plain-HTTP transports; 64 MiB recommended message limit (added in v0.19.0); `instance_uid` is UUIDv7; Beta: status, remote config, packages, connection-settings offers, commands; Development: agent-initiated CSR flow, custom messages, available components, heartbeat. Package hashes are opaque to the agent, and signing is "Agent specific and is outside the concerns of the OpAMP specification" ([spec](https://github.com/open-telemetry/opamp-spec/blob/main/specification.md)). Go reference `opamp-go` v0.25.0; the only maintained Rust client found is `newrelic/newrelic-opamp-rs`.
- **TUF** spec 1.0.37 (2026-10-08); Rust `tough` 0.24.0.
- **osquery 5.24.1 + Fleet 4.94**: enroll secret to `node_key`; TLS config/logger/distributed endpoints; RocksDB-buffered logs dropped on overflow; TLS 1.2 client. Fleet's `fleetd` auto-updates orbit, osqueryd and Desktop through TUF channels (`stable`, `edge`, pins) and offers TPM 2.0-backed host identity certificates with HTTP message signatures (P-384, 365-day certs, Linux only, Premium) ([guide](https://fleetdm.com/guides/enroll-hosts)).
- **Elastic Agent**: agent-initiated HTTP long-poll check-in to a stateless Fleet Server that reads policy from Elasticsearch indices ([docs](https://www.elastic.co/docs/reference/fleet/fleet-server)).
- **Wazuh 5.0.0-rc2** (2026-10-30) replaces its legacy agent protocol with HTTPS for connection, config, task dispatch, upgrade and events, and adds enrollment tokens plus a per-agent re-enrollment secret ([changelog](https://github.com/wazuh/wazuh/blob/v5.0.0-rc2/CHANGELOG.md)).
- **Tetragon 1.8.0**: JSON file export (rotated, compressed) and local gRPC socket; allow/deny export filters with CEL, field masks, regex redaction; 1.8 added `tetragon_events_export_failed_total` after export errors were previously silently counted as exported ([events](https://tetragon.io/docs/concepts/events/)).

## Matrix

**Mapping from the proposed canonical model to OCSF and OTel GenAI**

| Canonical entity (key ids) | OCSF 1.9.0 (1.10-dev marked *) | OTel GenAI (Development) |
|---|---|---|
| Tenant (`tenant_id`) | `metadata.tenant_uid` | resource attr; `a2a.tenant`; `microsoft.tenant.id` |
| Device (`device_id` = SHA-256 of device public key) | `device.uid`, Device Inventory Info 5001 | `host.id` resource |
| User (`user_id`, IdP subject) | `actor.user`, `actor.session` | `user.id` |
| Agent (`agent_uid`, `agent_instance_uid`, `version`, `framework`) | `ai_agent.uid`, `.instance_uid`, `.version`, `.type_id`, `.charter`; `process.ai_agent` | `gen_ai.agent.id|name|version`; entity `gen_ai.main_agent.id` |
| Session (`session_id`) | `message_context.uid`; `ai_agent.instance_uid` | `gen_ai.conversation.id`; `mcp.session.id` |
| Turn (`trace_id`) | `trace` profile: `trace.uid` | trace; root `invoke_agent` span |
| LLM request (`span_id`, `response_id`) | API Activity 6003 + `ai_operation`; `ai_model`, `message_context.*_tokens`, `ai_status.stop_reason_id`* | `chat` span; `gen_ai.request.model`, `gen_ai.response.id`, `gen_ai.usage.*`, `gen_ai.response.finish_reasons` |
| Model (`provider`, `name`, `version`) | `ai_model.ai_provider|name|version` | `gen_ai.provider.name`, `gen_ai.request|response.model` |
| Tool call (`tool_call_id`, `span_id`) | API Activity 6003; `ai_capability.transaction_uid`*; `ai_status.permission_result_id`* | `execute_tool` span; `gen_ai.tool.call.id`, `gen_ai.tool.name` |
| MCP server and tool (`server_name`, `tool_name`, schema hash) | `ai_capability.service`, `.name`, `.type_id`, `.transport_id`, `.input_schema_fingerprint`* | `mcp.method.name`, `gen_ai.tool.name`, `network.transport`, `server.address` |
| Skill or plugin (`name`, `source_uri`, digest) | Software Inventory Info 5020; Module Activity 1005; `file.hashes` | `gen_ai.skill.name`, `gen_ai.skill.source.uri` |
| Process (`pid`, start time, `process_uid`) | Process Activity 1007, `process.hosted_ai_agent_list` | `process.*`; command-execution tool span |
| File | File System Activity 1001 | none (tool arguments only) |
| Network flow / DNS | Network Activity 4001, HTTP 4002, DNS 4003 | `server.address`, `network.*` on client spans |
| Credential / delegation (`credential_id`, `delegation_id`) | `delegation.uid|issuer_uid|parent_uid`; `session.credential_uid`; Authorize Session 3003 | none |
| Data asset (`asset_id`, classification) | `data_classification` profile; Datastore Activity 6005; Data Security Finding 2006 | `gen_ai.data_source.id`, `mcp.resource.uri` |
| Detection (`finding_uid`) | Detection Finding 2004, `evidences[].ai_agent` | `gen_ai.evaluation.result` event (weak fit) |
| Decision (`decision_id`, `policy_id`, verdict) | `security_control` profile: `action_id`, `disposition_id`, `policy`, `authorizations` | none |
| Approval (`approval_id`, approver) | no native object; `authorizations[].decision` + `unmapped` | none |
| Response action (`action_id`, target) | Remediation Activity 7001 to 7004 | none |
| Integrity (`chain_id`, `seq`, `prev_hash`, `sig`) | `record_integrity`: `attestation.chain_uid`, `.prev_event`, `.fingerprint`, `.signatures` | none |

**Transport options**

| | OTLP gRPC/HTTP | OTel Arrow (OTAP) | Custom protobuf stream (recommended) |
|---|---|---|---|
| Bandwidth | gzip mandated; zstd by convention | best at batches of 100+ in stream mode; worse at batch 10 | zstd with trained dictionary; near OTAP for small batches (inference) |
| CPU on endpoint | low | Arrow builders, more memory | lowest: prost encode plus zstd level 3 |
| Loss handling | retry on fixed codes; drop otherwise | per-batch ack/nack | per-batch ack, disk spool, replay from last acked sequence |
| Duplicates / order | duplicates accepted; no ordering | not specified | `(device_id, boot_id, seq)` idempotency key; server dedups and detects gaps |
| Backpressure | 429/503 + `Retry-After`, `RetryInfo` | stream flow control + status | HTTP/2 flow control plus server credit and priority shedding |
| Ecosystem | universal | Collector contrib, Rust engine | ours only; bridged to OTLP at the gateway |

## Weak points, gaps and risks

- OTel GenAI has no released version to pin. Fields we map today (`gen_ai.transfer.*`, `gen_ai.skill.*`, `invoke_workflow`) are mid-rename. ECS pins 1.38, Agent 365 accepts four operation names; three "OTel-compatible" consumers already disagree.
- OCSF's MCP metadata and permission result exist only on main; a 1.10 release date is not published. `ai_agent.type_id` knows four frameworks and no coding agents.
- OCSF has no approval object and no explicit agent-versus-human attribution confidence. We must carry these in an extension.
- OCSF `record_integrity` defines fields but not a canonicalisation test suite; JCS over JSON is fragile if our wire format is protobuf.
- OpAMP is Beta, its CSR flow and custom messages are Development, and Rust support is one vendor's client.
- FIPS: aws-lc-rs README says `aws-lc-fips-sys` binds AWS-LC-FIPS 4.x, while AWS-LC's FIPS.md lists v4.0 as still "in process" with certificates issued through v3.1; static FIPS builds are Linux-only, shared builds Linux and Windows. No macOS FIPS path is documented.
- Device-bound keys are uneven: Fleet only ships TPM identity on Linux. Windows (CNG platform provider) and macOS (Secure Enclave, P-256 only) need separate code paths and cannot hold ML-DSA keys today (inference).
- Hybrid PQ key shares enlarge the ClientHello; rustls documents possible middlebox failures.

## Implications for our design

**(1) Canonical event model.** Own protobuf IDL, one `Event` envelope plus typed payloads, entities referenced by id and upserted through separate inventory records. Envelope: `event_id` (UUIDv7), `tenant_id`, `device_id`, `boot_id`, `seq` (monotonic per device and boot), `observed_time`, `monotonic_ns`, `sensor` (hook, gateway, OS, cloud, browser), `class`, `trace_id`, `span_id`, `parent_span_id`, `principal` {`user_id`, `agent_uid`, `agent_instance_uid`, `delegation_id`, `attribution` enum (declared, inferred-process-lineage, inferred-network, unknown) and confidence}, `schema_version`, `integrity` {`chain_id`, `prev_hash`, `hash`, `sig`}. Entities and keys are those in the mapping table. Content (prompts, tool arguments) goes in a separate, optionally encrypted or hashed `content_ref` blob, mirroring OTel `*_ref`.

**(2) Mappings.** Ship the table above as versioned, data-driven mapping files: OCSF 1.9.0 as the default export and lake schema, with an `aidr` OCSF extension for approval, attribution confidence and anything from 1.10-dev; OTel GenAI and OpenInference as ingest dialects and as an OTLP trace export. Emit Agent 365-compatible spans as a named export profile.

**(3) Wire, compression, security, management.**
- Data: gRPC bidirectional stream (tonic + rustls + aws-lc-rs) carrying `EventBatch{batch_id, first_seq, count, dict_id, zstd payload}` with `BatchAck`. Unary HTTP/2 POST of the same message as fallback through proxies. Batch by 1 s or 512 events or 256 KiB; priority lanes so detections and decisions bypass bulk telemetry. Reason: acks, ordering and idempotency that OTLP lacks, without Arrow's small-batch penalty.
- Spool: append-only segment files with the same framing, bounded by size and age, oldest low-priority first to drop, and an explicit `gap` event when anything is discarded (Tetragon's silent-loss bug is the cautionary case).
- Compression: zstd level 3 with a dictionary trained per schema version and distributed as an OpAMP package; `dict_id` in every batch; fall back to no dictionary.
- Clock: send wall clock, monotonic clock and `boot_id`; server records receive time and computes skew per device; order by `(boot_id, seq)`, never by timestamp.
- Identity: enrollment token to CSR, key generated in TPM 2.0 / Secure Enclave / CNG where present, software key otherwise with the fact recorded; short-lived client certs; TLS 1.3 only; `X25519MLKEM768` preferred; optional `fips` cargo feature as a separate build.
- Management: OpAMP over WebSocket with plain-HTTP polling fallback for config, health, effective config and package offers. Updates verified against TUF metadata (root and targets keys offline; server compromise cannot ship code). Response actions go over a dedicated signed command message, not OpenC2.
- Gateway: accept OTLP/gRPC and OTLP/HTTP for third-party agents; optionally speak OTAP between gateway and backend for large tenants.

**(4) Schema evolution rules.**
1. Protobuf field numbers and enum values are never reused or renumbered; removed fields are `reserved`.
2. Additive changes are minor; any semantic change of an existing field is a new field. Major versions are new packages (`aidr.v2`), and servers accept N and N-1.
3. Every enum has 0 = Unknown and 99 = Other with a sibling string, as OCSF does.
4. Unknown fields are preserved end to end; sensors older than the server are always valid.
5. Each batch declares `schema_version`; each exported record declares the OCSF version and, for OTel, the semconv commit used.
6. Mappings are data with their own version and golden-file tests against the OCSF validator and OTel Weaver.
7. Identifiers are opaque strings with a type prefix; never parse them.
8. Hashes in the integrity chain are computed over the exact serialized bytes as sent (deterministic protobuf encoding by our own encoder), not over a re-serialization.

## Ideas worth stealing and whitespace

- OCSF `ai_capability` fingerprints (description, input schema, baseline) are a ready-made rug-pull detector for MCP tools; nobody ships it yet.
- BeyondTrust's policy replay against recorded sessions: our ordered, gap-aware event log makes this cheap.
- Agent 365's rule that the in-payload agent id must match the authenticated identity; apply it to `device_id` and `tenant_id` on every batch.
- Fleet's TUF channels plus TPM-backed HTTP message signatures.
- Whitespace: a published agent/MCP/skill BOM profile (CycloneDX component set plus in-toto attestation), Sigma log sources for agent activity, an OCSF approval object, and an open reference tile log for security telemetry with SCITT receipts. Contributing these upstream would make our schema the default.

## Could not verify / open questions

- Web search was unavailable; no independent survey of 2026 vendor announcements was possible.
- Current OASIS version numbers for STIX, TAXII, OpenC2 and CACAO; any AI-specific STIX extensions.
- EU AI Act Art. 19 and 26(6) retention text and the exact effect of the Digital Omnibus on dates.
- osquery logger buffer flag names and defaults; Elastic Agent upgrade signature verification and disk-queue behaviour.
- Measured zstd-dictionary gains on our event mix; needs a benchmark with real hook and OS events.
- Whether OCSF 1.10 ships before our first release, and whether the draft `AI Agent Activity` class lands.
- Licence of `newrelic-opamp-rs` (GitHub reports no detected SPDX id).
- ML-DSA support in TPMs and platform keystores.

## Sources

- https://github.com/ocsf/ocsf-schema/releases/tag/1.9.0 — OCSF 1.9.0 release notes, 2026-08-03
- https://github.com/ocsf/ocsf-schema/pull/1661 — record_integrity / attestation, 2026
- https://github.com/ocsf/ocsf-schema/pull/1729 , /pull/1704 , /pull/1754 , /pull/1765 — ai_capability, ai_status, AI Agent Activity draft, containment, Sep to Nov 2026
- https://github.com/open-telemetry/semantic-conventions/releases/tag/v1.45.0 — semconv 1.45.0, 2026-11-02
- https://github.com/open-telemetry/semantic-conventions-genai — GenAI conventions (main, read 2026-11-09)
- https://github.com/elastic/ecs/releases/tag/v9.5.0 — ECS 9.5.0, 2026-08-04
- https://github.com/Arize-ai/openinference/tree/main/spec — OpenInference spec
- https://learn.microsoft.com/en-us/microsoft-agent-365/overview and /developer/observability-concepts — updated 2026-10-23
- https://docs.beyondtrust.com/bt-docs/docs/ai-agent-security — read 2026-11-09
- https://github.com/SigmaHQ/sigma-specification — v2.1.0 taxonomy
- https://github.com/CycloneDX/specification — 1.7.2, issues #895 #941 #948
- https://github.com/spdx/spdx-spec/releases — 3.1-RC1, 2026-01-24
- https://github.com/modelcontextprotocol/registry — v1.8.8, server.json 2025-12-11
- https://github.com/a2aproject/A2A/blob/v1.0.1/specification/a2a.proto — 2026-05-28
- https://github.com/agntcy/oasf/releases/tag/v1.1.0 — 2026-07-10
- https://github.com/in-toto/attestation/releases/tag/v1.2.0 — 2026-03-18
- https://c2sp.org/tlog-tiles — tiled transparency logs
- https://github.com/transparency-dev/tessera — v1.0.4; https://github.com/sigstore/rekor-tiles — v2.4.2
- https://datatracker.ietf.org/wg/scitt/documents/ — RFC 9943, SCRAPI -11
- https://www.sec.gov/investment/amendments-electronic-recordkeeping-requirements-broker-dealers — Rule 17a-4 amendments
- https://artificialintelligenceact.eu/article/12/ — EU AI Act Art. 12
- https://opentelemetry.io/docs/specs/otlp/ — OTLP 1.11.1
- https://github.com/open-telemetry/otel-arrow — OTAP spec (Draft), benchmarks, v0.65.0
- https://github.com/open-telemetry/opamp-spec/blob/main/specification.md — OpAMP v0.20.0, 2026-08-12
- https://github.com/theupdateframework/specification/releases — TUF 1.0.37; https://github.com/awslabs/tough — 0.24.0
- https://github.com/rustls/rustls/releases — 0.23.27, 0.23.44, 0.23.46; rustls manual "defaults"
- https://github.com/aws/aws-lc-rs and https://github.com/aws/aws-lc/blob/main/crypto/fipsmodule/FIPS.md — FIPS status
- https://osquery.readthedocs.io/en/stable/deployment/remote/ ; https://fleetdm.com/guides/enroll-hosts — osquery and Fleet
- https://www.elastic.co/docs/reference/fleet/fleet-server — Fleet Server
- https://github.com/wazuh/wazuh/blob/v5.0.0-rc2/CHANGELOG.md — Wazuh 5.0.0-rc2, 2026-10-30
- https://tetragon.io/docs/concepts/events/ ; https://github.com/cilium/tetragon/releases/tag/v1.8.0 — Tetragon

## Independent verification

_Checked 2026-11-09 by a separate fact-checker against the tagged source trees and specs (read through `gh`), crates.io, rfc-editor.org, NIST CMVP and Microsoft Learn. Web search was unavailable (budget exhausted), so every verdict rests on primary sources fetched directly._

| # | Claim | Verdict | Note | Source |
|---|---|---|---|---|
| 1 | OCSF 1.9.0 (2026-08-03) adds `ai_agent` (uid, instance_uid, version, type_id, charter, ai_model) and `delegation`, and applies `ai_operation` to the system, network, application and iam base classes | Confirmed | Both objects are absent at tag 1.8.0 and present at 1.9.0; the four base classes list `ai_operation` at 1.9.0. The profile itself dates from 1.8.0. `instance_uid` is a session/run id that "may persist across restarts" when a session is resumed, so do not treat it as a process-lifetime id. | https://github.com/ocsf/ocsf-schema/blob/1.9.0/objects/ai_agent.json ; https://github.com/ocsf/ocsf-schema/blob/1.9.0/events/system/system.json |
| 2 | OCSF 1.9.0 adds `record_integrity` on `base_event` with `attestation` (fingerprint, signatures, prev_event, chain_uid, authority_uid); `serialization_id` includes JCS, JWS, COSE, DSSE | Confirmed | Also has `uid` and an at-least-one constraint on fingerprint/signatures. Full enum: Flat, JCS, JWS, COSE, DSSE, Authenticode, Code Signing, App Package. `algorithm_id` still has no EdDSA or ML-DSA value, on main as well. | https://github.com/ocsf/ocsf-schema/blob/1.9.0/objects/attestation.json ; https://github.com/ocsf/ocsf-schema/blob/1.9.0/objects/digital_signature.json |
| 3 | `ai_capability` (MCP metadata) and `ai_status` are merged on main as 1.10.0-dev, not in any release | Confirmed | PR #1729 merged 2026-10-07, #1704 merged 2026-10-13; neither object exists at tag 1.9.0; no 1.10 tag or branch exists. The third type is captioned "Prompt Template". | https://github.com/ocsf/ocsf-schema/blob/main/objects/ai_capability.json ; https://github.com/ocsf/ocsf-schema/blob/main/version.json |
| 4 | OTel GenAI conventions moved to `semantic-conventions-genai` (May 2026); all Development, no tagged release, Schema URL TODO, many pending breaking changes | Confirmed | Repo created 2026-05-05; zero releases and zero tags; `model/manifest.yaml` is `stability: development`; 20 `*.breaking.md` fragments in `changelog.d`. RELEASING.md defines a `vX.Y.Z-dev` prerelease channel (manifest already says `gen-ai-dev/1.42.0-dev`), so a pinnable dev tag may appear; until then pin a commit. | https://github.com/open-telemetry/semantic-conventions-genai/blob/main/model/manifest.yaml ; https://github.com/open-telemetry/semantic-conventions-genai/blob/main/RELEASING.md |
| 5 | OTLP 1.11.1: servers must support only `none` and `gzip`; no client retry on `partial_success`; duplicates accepted; ordering unspecified | Confirmed | Checked in the spec at tag v1.11.1 (2026-09-29). The spec contains no ordering or sequencing guarantee. | https://github.com/open-telemetry/opentelemetry-proto/blob/v1.11.1/docs/specification.md |
| 6 | OTel Arrow phase 1: stream Arrow+zstd 1.6x to 6.4x smaller than OTLP+zstd at batch 100 to 1000; unary batch 10 is 0.27x to 0.95x; OTAP spec is Draft | Corrected | Stream range and Draft status hold (compressed rows: 1.65x to 6.35x). For unary batch 10 the compressed range is 0.41x to 0.95x; 0.27x is an uncompressed-size figure (logs). The penalty is unary-only: in stream mode at batch 10, Arrow+zstd is still 1.03x to 2.79x smaller than OTLP+zstd. The "OTLP dict + zstd stream" column is 1.12x to 3.10x on compressed rows (3.4x is uncompressed). These are phase-1 numbers; the project now publishes phase-2 engine benchmarks instead. | https://github.com/open-telemetry/otel-arrow/blob/main/docs/benchmarks-phase1.md ; https://github.com/open-telemetry/otel-arrow/blob/main/docs/otap-spec.md |
| 7 | OpAMP v0.20.0 (2026-08-12) is Beta; remote config, status, packages, commands Beta; CSR flow and custom messages Development; code signing outside the spec | Confirmed | Verified at tag v0.20.0. Nuance: packages, commands, health, connection-settings offers and own telemetry carry an explicit Beta label; `remote_config`, `remote_config_status` and `effective_config` carry no label, which per the "Protobuf Schema Stability" section gives them the stronger schema guarantees. The spec does define a detached `DownloadableFile.signature` field and a SHA-256 `content_hash`; only the signing and verification method is left to the agent. | https://github.com/open-telemetry/opamp-spec/blob/v0.20.0/specification.md |
| 8 | rustls + aws-lc-rs prefers X25519MLKEM768 by default since 0.23.27 (May 2025); ML-DSA certificates on by default since 0.23.44 (Sep 2026) | Confirmed | 0.23.27 published 2025-05-05 (`prefer-post-quantum` added to default features); 0.23.44 published 2026-09-07. Pin 0.23.46 or later: 0.23.45 and 0.23.46 fix advisories including GHSA-w44r-93j7-qv28, where an unauthenticated ServerHello makes later ClientHellos carry only a classical X25519 share. 0.24 is still `0.24.0-dev.2`. | https://github.com/rustls/rustls/releases/tag/v%2F0.23.27 ; https://github.com/rustls/rustls/releases/tag/v%2F0.23.44 ; https://github.com/rustls/rustls/releases/tag/v%2F0.23.46 |
| 9 | AWS-LC static FIPS builds Linux only, shared FIPS builds Linux and Windows; certificates through v3.1, v4.0 in process | Confirmed | NIST's Modules In Process list (updated 2026-11-09) shows "AWS-LC 4 Cryptographic Module" static and dynamic at "Comment Resolution - CMVP", and AWS-LC 5 static and dynamic already in "Review". Certificate #5314 (AWS-LC 3 static) is Active, validated 2026-06-05. | https://csrc.nist.gov/Projects/cryptographic-module-validation-program/modules-in-process/Modules-In-Process-List ; https://csrc.nist.gov/projects/cryptographic-module-validation-program/certificate/5314 |
| 10 | SCITT architecture is RFC 9943 (June 2026); tile-based logs implemented by Tessera v1.0.4 and Rekor v2 (rekor-tiles v2.4.2, POSIX backend) | Confirmed | RFC 9943 is Standards Track, dated June 2026. Tessera v1.0.4 published 2026-07-16 with GCP, AWS, POSIX and MySQL storage directories. rekor-tiles v2.4.2 was published 2026-11-10 00:55 UTC and ships `rekor-server-posix` binaries. SCRAPI is draft -11 in the RFC Editor queue. | https://www.rfc-editor.org/rfc/rfc9943.txt ; https://github.com/transparency-dev/tessera/releases/tag/v1.0.4 ; https://github.com/sigstore/rekor-tiles/releases/tag/v2.4.2 |
| A | TL;DR and design rationale: OTel Arrow "is worse at batch size 10" / "Arrow's small-batch penalty" | Corrected | Overstated. Arrow is worse than OTLP+zstd at batch 10 only in unary RPC mode. On a long-lived stream it is still smaller at batch 10 in every phase-1 dataset. The case for a custom stream should rest on acks, ordering and idempotency, not on a small-batch size penalty. | https://github.com/open-telemetry/otel-arrow/blob/main/docs/benchmarks-phase1.md |
| B | "FIPS builds exist but ... macOS is not listed" / "No macOS FIPS path is documented" | Corrected | aws-lc-rs documents the `fips` feature as built and tested on `aarch64-apple-darwin` and `x86_64-apple-darwin`, with pre-generated FIPS bindings (Windows MSVC needs bindgen). AWS-LC's own FIPS.md platform list names only Linux and Windows, so a macOS FIPS build compiles but whether it is a validated operating environment must be checked against the security policy (not verified here). aws-lc-rs docs also disagree on the bound module: the crate README says 4.x, the repo README and `aws-lc-fips-sys` README still say 3.x. | https://github.com/aws/aws-lc-rs/blob/main/book/src/platform_support.md ; https://github.com/aws/aws-lc-rs/blob/main/aws-lc-fips-sys/README.md |
| C | Agent 365: GA 1 May 2026; OTLP/HTTP, 1 MB body, `api-version=1`, `Retry-After: 1`; only four `gen_ai.operation.name` values kept; `gen_ai.agent.id` must equal the token appId; legacy SDK deprecated | Confirmed | All stated on Microsoft Learn (pages updated 2026-10-23). Two additions: a rejected span is reported in `partialSuccess.rejectedSpans`, and an unlicensed tenant gets `200 OK` with per-span `tenant_not_licensed`, so a 200 is not proof of ingestion. A run without a root `invoke_agent` span is visible only in Defender advanced hunting. | https://learn.microsoft.com/en-us/microsoft-agent-365/developer/observability-concepts ; https://learn.microsoft.com/en-us/microsoft-agent-365/overview |
