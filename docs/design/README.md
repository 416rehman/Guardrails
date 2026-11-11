# Design documents

_Index of `design/`. Start with [00-decisions.md](00-decisions.md), the binding principles (P1 to P17) and decisions; every other document expands part of it. The plan describes the complete product: there are no milestones or timelines, and dependencies are stated as prerequisites. The review record is in [_review/](_review/00-resolution.md): `00-resolution.md` settles the architecture review, `01-document-rulings.md` settles the objections the documents raised, `02-owner-answers.md` records the owner's answers, `03-models-and-orchestration.md` sets the agent team's models, and `04-owner-kit-instructions.md` records the owner's instructions of 2026-11-11, which name the product Guardrails ADR and add principles P14 to P17 and decisions D-69 to D-71._

## Foundations

| Document | Words |
|---|---|
| [00 Architecture decisions](00-decisions.md) | 22,646 |
| [01 Competitive capability map](01-competitive-capability-map.md) | 7,368 |
| [02 Threat model](02-threat-model.md) | 10,870 |
| [03 System architecture and modularity](03-system-architecture-and-modularity.md) | 12,509 |
| [04 Event model and schemas](04-event-model-and-schemas.md) | 15,619 |

## Endpoint and control points

| Document | Words |
|---|---|
| [05 Discovery and inventory](05-discovery-and-inventory.md) | 11,272 |
| [06 Attribution and the session graph](06-attribution-and-session-graph.md) | 10,418 |
| [07 Control points and the hook broker](07-control-points-and-hook-broker.md) | 15,539 |
| [08 Windows sensor](08-sensor-windows.md) | 10,207 |
| [09 macOS sensor](09-sensor-macos.md) | 8,994 |
| [10 Linux sensor: endpoints, containers, Kubernetes and CI](10-sensor-linux-containers-ci.md) | 12,744 |
| [11 Endpoint engineering: processes, self-protection, performance, coexistence](11-endpoint-engineering.md) | 13,250 |

## Decisions, detection and response

| Document | Words |
|---|---|
| [12 Policy engine](12-policy-engine.md) | 10,847 |
| [13 Detection engine and content](13-detection-engine-and-content.md) | 9,121 |
| [14 Threat intelligence and reputation](14-threat-intelligence-and-reputation.md) | 11,193 |
| [15 Identity and the credential broker](15-identity-and-credential-broker.md) | 11,618 |
| [16 Data protection and secrets](16-data-protection.md) | 11,253 |
| [17 Network control: endpoint proxy, MCP broker, gateway and browser](17-network-proxy-mcp-broker-gateway-browser.md) | 10,190 |
| [18 Response, approvals and SOC operations](18-response-approvals-and-soc-operations.md) | 10,331 |
| [19 AI and ML inside the product](19-ai-and-ml.md) | 9,111 |

## Platform

| Document | Words |
|---|---|
| [20 Server platform and storage](20-server-platform-and-storage.md) | 20,475 |
| [21 Tenancy, keys and access](21-tenancy-keys-and-access.md) | 15,278 |
| [22 Transport, fleet management and updates](22-transport-fleet-and-updates.md) | 17,575 |
| [23 API, policy as code and the MCP server](23-api-policy-as-code-and-mcp-server.md) | 9,582 |
| [24 Deployment models, packaging and release engineering](24-deployment-and-packaging.md) | 20,718 |
| [32 Hosted service operations, day-2 for self-hosters, and economics](32-saas-operations-and-economics.md) | 14,098 |

## Ecosystem and business

| Document | Words |
|---|---|
| [25 Integrations, imports and exports](25-integrations-imports-exports.md) | 12,693 |
| [26 Embedding, OEM and white-label](26-embedding-oem-and-white-label.md) | 9,401 |
| [30 Open-source governance and community](30-open-source-governance-and-community.md) | 13,823 |
| [34 Documentation, support and product lifecycle](34-documentation-support-and-lifecycle.md) | 10,617 |
| [35 Product security programme](35-product-security-programme.md) | 10,257 |
| [36 Legal, brand and commercial](36-legal-brand-and-commercial.md) | 10,682 |

## Experience

| Document | Words |
|---|---|
| [27 Web console: experience and front-end architecture](27-web-console-ux.md) | 13,138 |
| [28 Desktop apps in Rune and the developer experience](28-desktop-and-developer-experience.md) | 12,342 |

## Assurance and build order

| Document | Words |
|---|---|
| [29 Compliance and privacy](29-compliance-and-privacy.md) | 10,069 |
| 31 Efficacy evaluation and the test lab: not written; D-45 and D-64 in the decisions file are the current source | |
| [33 Build order, experiments and risks](33-build-order-and-risks.md) | 8,858 |

## Team documents

| Document | Words |
|---|---|
| [01 Agent team operating model](../team/01-operating-model.md) | 12,717 |
| [02 Agent roster](../team/02-agent-roster.md) | 10,874 |
| [03 Skills, hooks, plugins and workflows for the agent team](../team/03-skills-hooks-and-plugins.md) | 10,788 |
| [04 Power-prompt library](../team/04-power-prompts.md) | 11,498 |
| [05 Quality gates and continuous integration](../team/05-quality-gates-and-ci.md) | 11,187 |
| [06 Repository bootstrap](../team/06-repository-bootstrap.md) | 14,765 |
