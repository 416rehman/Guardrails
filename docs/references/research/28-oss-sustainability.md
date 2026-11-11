# Open-source sustainability: licences, governance, contribution model, business model

_Researched 2026-11-09_

Method note: web search was unavailable for this run (shared search budget exhausted), so everything below comes from primary documents fetched directly and from the GitHub API. Claims marked **[memory]** are from pre-2026 knowledge and were not re-verified today.

## TL;DR

- **Use Apache-2.0 for every code component** (sensor, engine, SDKs, server, console, schemas, rules, model weights). It is the only choice that satisfies all three constraints at once: OSI-approved, embeddable by proprietary EDR vendors, and admissible to a Linux Foundation home. CNCF requires Apache-2.0, OpenSSF requires Apache-2.0 or MIT, and AAIF requires an "OSI-approved permissive license".
- **AGPL on the server closes the foundation path** and is the configuration (AGPL plus CLA) that MinIO, Element and Plausible used for dual licensing or feature withdrawal. MinIO's AGPL repository is now archived and marked "no longer maintained".
- **DCO, no CLA.** Every licence rug-pull studied (HashiCorp, Redis, Elastic) was enabled by a CLA or copyright assignment. DCO disperses copyright so nobody can relicense inbound code.
- **A permissive licence cannot itself stop the steward closing future versions.** What makes "never relicense" credible is who owns the trademark, domain and GitHub organisation. The NATS/Synadia dispute (2025) shows foundation ownership holds under pressure.
- **Fork outcomes are decisive evidence.** OpenTofu (30.8k stars, 351 contributors, v1.13), OpenBao (373 contributors, v2.7, OpenSSF sandbox) and Valkey (27.7k stars, 382 contributors, v9) are all healthy. Redis re-added AGPL in May 2025 and admitted the SSPL move "hurt our relationship with the Redis community".
- **Rules content must not use the Sigma DRL or Elastic Licence.** Neither is OSI-approved; DRL forces author attribution into every match view, and ELv2 forbids hosted use. Falco (Apache-2.0) and nuclei-templates and CrowdSec hub (MIT) are the models.
- **The steward is a CRA manufacturer for anything it monetises** and a steward only for the free version. Article 14 reporting has applied since 11 September 2026; full obligations apply 11 December 2027.
- **Being fully open source has a concrete CRA advantage.** Intrusion detection and prevention systems are Annex III Class II (normally third-party assessment), but Article 32(5) lets FOSS products self-assess if the technical documentation is public.
- **AI-contribution policies converged in 2025-2026 on three rules:** a human is accountable, AI use is disclosed, and agents never sign the DCO. They diverge on mechanism (LLVM and OpenTelemetry want an `Assisted-by:` trailer; Kubernetes forbids it).
- **Open PR queues and cash bug bounties no longer work.** curl ended its bounty on 31 January 2026 (confirmed rate fell from above 15% to below 5%); Ghostty gates PRs behind a vouch list; tldraw turned PRs off.
- **Revenue without withheld features exists but is narrow:** hosting, managed intelligence (CrowdSec), support and OEM services. Donations are negligible (Plausible: about $300 per month from self-hosters).

## Findings

### 1. What happened to the projects that changed licence

| Project | What they did | Outcome (verified 2026-11-09 unless marked) |
|---|---|---|
| HashiCorp Terraform, Vault | BSL 1.1 (Aug 2023 **[memory]**) | Licence file now names IBM as Licensor; the grant bars "hosted or embedded" competitive offerings. Forks: OpenTofu (MPL-2.0, Linux Foundation, two supported minor lines patched the same day) and OpenBao (MPL-2.0, OpenSSF sandbox, SAP funds full-time developers). |
| Redis | SSPL/RSAL (Mar 2024) | Valkey fork (BSD-3-Clause). Redis 8 added AGPLv3 on 2025-05-01; the CEO wrote that "AWS and Google now maintain their own fork". |
| Elastic | SSPL/ELv2 (2021 **[memory]**) | Licence file is now AGPL-3.0-only / SSPL / ELv2 triple licence, with x-pack ELv2-only. OpenSearch remains Apache-2.0 under the LF. |
| MinIO | AGPL, single vendor | Repository archived; README says "THIS REPOSITORY IS NO LONGER MAINTAINED" and points to proprietary AIStor. |
| Teleport | Source AGPL-3.0; from v16 (June 2024) Community Edition binaries under a commercial licence | Free use only below 100 employees and $10M revenue; "may not resell or embed". |
| Sentry | FSL-1.1-Apache-2.0 | Not OSI-approved; converts to Apache-2.0 after two years. Out of scope for us. |
| Plausible | AGPL plus CLA; "Community Edition" (Feb 2024) | Funnels and revenue metrics became cloud-only; CE releases twice a year. |
| Wazuh | GPL-2.0 | New engine (`src/engine/`) is now AGPL-3.0-or-later; shared libraries are `GPL-2.0-only OR AGPL-3.0-or-later`. |
| Grafana | AGPL-3.0 (Apr 2021); plugins, agents and some libraries stay Apache | Stable since, but the CEO stated the company "retains the right to change the license". That is not a commitment. |

Sources: [terraform LICENSE](https://github.com/hashicorp/terraform/blob/main/LICENSE), [Redis AGPL post](https://redis.io/blog/agplv3/), [elasticsearch LICENSE](https://github.com/elastic/elasticsearch/blob/main/LICENSE.txt), [minio README](https://github.com/minio/minio), [Teleport licence post](https://goteleport.com/blog/teleport-community-license/), [Plausible CE](https://plausible.io/blog/community-edition), [wazuh LICENSE](https://github.com/wazuh/wazuh/blob/main/LICENSE), [Grafana CEO Q&A](https://grafana.com/blog/2021/04/20/qa-with-our-ceo-on-relicensing/), [OpenBao](https://openbao.org/).

A side effect worth designing for: GitHub reports the licence as `NOASSERTION` for every mixed-licence repository checked (Fleet, PostHog, Infisical, Sentry, Elastic, Redis, Wazuh, osquery, Sigma). Single-licence repositories detect cleanly, which matters to embedders' compliance scanners.

### 2. Licence per component

SPDX licence list 3.29.0 (2026-09-16) flags as **not** OSI-approved: CC-BY-4.0, CC0-1.0, CDLA-Permissive-2.0, OpenMDW-1.0, DRL-1.0/1.1, Community-Spec-1.0, BUSL-1.1, Elastic-2.0, SSPL-1.0 and FSL. OSI-approved: Apache-2.0, MIT, MPL-2.0, AGPL-3.0, BSD-3-Clause ([SPDX JSON](https://spdx.org/licenses/licenses.json)). "Everything OSI-approved" therefore rules out the usual foundation defaults for documentation and data unless dual-licensed.

Recommended matrix is in the Matrix section. Reasons:

- **Patent grant.** Apache-2.0 gives embedders an explicit patent licence; MIT and BSD do not.
- **Foundation eligibility.** CNCF charter section 11: inbound and outbound code under Apache-2.0, documentation under CC-BY-4.0, DCO sign-off mandatory, trademarks transferred to the LF ([charter](https://github.com/cncf/foundation/blob/main/charter.md)). OpenSSF: Apache-2.0 or MIT for software ([lifecycle](https://github.com/ossf/tac/blob/main/process/project-lifecycle.md)). AAIF: "OSI-approved permissive license" ([lifecycle policy](https://github.com/aaif/technical-committee/blob/main/governance/project-lifecycle-policy.md), updated 2026-10-15).
- **MPL-2.0 was considered** for the engine (file-level copyleft, as OpenTofu and OpenBao inherited). It would need a foundation exception and adds friction for embedders; rejected.
- **Kernel-side code is the one exception.** eBPF programs that call GPL-only helpers must be GPL-compatible. Falco and Tetragon dual-license kernel-side code (GPL-2.0 with MIT or BSD-2-Clause) while user space is Apache-2.0 **[memory]**. Do the same and keep it in a clearly separate directory.
- **Model weights.** OpenMDW 1.1 (Linux Foundation and PyTorch Foundation, 2025) was written for models but is not OSI-approved ([openmdw.ai](https://openmdw.ai/)). Use Apache-2.0 and publish training code and data descriptions alongside.
- **Rules.** Sigma's DRL 1.1 requires the author to be shown "in views that show matches" ([DRL](https://github.com/SigmaHQ/Detection-Rule-License)), a UI obligation no embedder wants. Elastic's detection rules are ELv2. Falco rules are Apache-2.0 ("All rules must be licensed under the Apache 2.0 License").

### 3. Contributor agreement and relicensing

- **DCO** is mandatory in CNCF and the default in OWASP. Copyright stays with each contributor, so relicensing inbound code requires everyone's consent.
- **CLA with a covenant** is the best-case CLA: Element's commits to distribute contributions as "FOSS under an OSI-approved licence" and exists explicitly to sell AGPL exceptions ([Element](https://element.io/blog/synapse-now-lives-at-github-com-element-hq-synapse/)).
- **Copyright assignment** is the worst case for trust: OISF's agreement "irrevocably and perpetually assigns" ownership, and OISF "may amend the agreement at any time", applying to earlier submissions ([OISF](https://suricata.io/contribution-agreement/)).
- **AI interaction.** The Linux kernel states "AI agents MUST NOT add Signed-off-by tags. Only humans can legally certify the Developer Certificate of Origin" ([coding-assistants.rst](https://github.com/torvalds/linux/blob/master/Documentation/process/coding-assistants.rst)). A project built by agents still needs a named human on every commit.

Inference: under Apache-2.0, DCO stops relicensing of the existing corpus only in a weak sense, because anyone may already ship it in proprietary form. The real protection is asset ownership (next section).

### 4. Trademark and the credibility of "never relicense"

- NATS (2025): Synadia tried to withdraw NATS from CNCF and relicense to BSL. It still held the trademark because the 2018 transfer was never completed. CNCF refused to hand over the domain and GitHub organisation, petitioned the USPTO to cancel the registrations, and stated Synadia could fork under a new name only. Settled 2025-05-01 with NATS staying in CNCF ([CNCF](https://www.cncf.io/blog/2025/05/01/protecting-nats-and-the-integrity-of-open-source-cncfs-commitment-to-the-community/)).
- OpenTofu's licence promise rests on Linux Foundation ownership: the licence "won't suddenly change in the future" ([manifesto](https://opentofu.org/manifesto/)).
- AAIF requires that the "existing project host transfer project trademarks and other project assets to the LF" and that a technical charter fixes the IP policy.
- Plausible registered its marks and gave the community edition a different name and logo after resellers misled users.

### 5. Foundations compared

| | CNCF | OpenSSF | AAIF | OWASP |
|---|---|---|---|---|
| Code licence | Apache-2.0 | Apache-2.0 or MIT | OSI-approved permissive | Any OSI-approved |
| Entry | Sandbox issue form; reviewed roughly every two months | Sandbox needs a sponsoring working group and repository under OpenSSF's GitHub | Sandbox: working implementation, one active maintainer, 1-2 page thesis | 2-5 leaders who are OWASP members; request form |
| Next stage | Incubation: 5-7 adopter interviews, due diligence, 2/3 TOC vote; 5 to 15 months | Incubating: 3 maintainers from 2+ organisations, Silver badge. Graduated: 5 from 3+, Gold badge, third-party audit | Growth: production use by 2 unaffiliated organisations, commits from 2+ organisations over six months | Not on the policy page |
| What you get | Marketing, events, audits (NATS: over $90,000 for two audits) | Budget requests for audits at Incubating; maintainer stipends at Graduated | Sandbox: infrastructure only. Impact: CI costs, audits, contractors | Project page, tooling; "All source material must remain within the foundation" |
| Asset transfer | Trademark and logo to LF | LF IP review; marks held by LF | Trademarks and assets to LF | Operates under OWASP |

AAIF hosts MCP, goose, AGENTS.md, A2A and agentgateway; platinum members are AWS, Anthropic, Block, Bloomberg, Cloudflare, Google, Microsoft and OpenAI; it runs working groups on Security and Privacy, Identity and Trust, and Observability and Traceability ([aaif.io/about](https://aaif.io/about), [project-proposals](https://github.com/aaif/project-proposals)). Sandbox projects must apply for Growth within twelve months or face archival.

### 6. AI-generated contribution policies, 2025-2026

| Project | Rule |
|---|---|
| Linux kernel | Disclose tools, prompts and what was tested; agents must not sign off; an AI-found bug needs a reproducer and a tested fix, and the report must "indicate what could not be done". |
| LLVM | Human in the loop; `Assisted-by:` trailer; "extractive" label for contributions costing more review than they are worth; agents acting without human approval banned; no AI on "good first issue". |
| Kubernetes | Disclose in the PR description; `assisted-by` and co-author trailers are **not allowed**; large AI PRs and AI commit messages not allowed. |
| OpenTelemetry | Maintainers may close AI contributions at discretion; `Assisted-by:` recommended. |
| Apache SF | Acceptable if tool terms and third-party material are clean; `Generated-by:` trailer. |
| QEMU | Declines any contribution where AI use "is either known or suspected". |
| Ghostty | Disclose all AI use; unvouched users' PRs auto-closed; public denouncement list shareable across projects ([vouch](https://github.com/mitchellh/vouch), 5.2k stars). |
| tldraw | Pull requests turned off; issues only, with an optional linked branch. |
| curl | Bounty ended 2026-01-31 after 87 confirmed vulnerabilities and over $100,000 paid; reports now via GitHub private reporting. |

Sources: [kernel](https://docs.kernel.org/process/generated-content.html), [LLVM](https://llvm.org/docs/AIToolPolicy.html), [Kubernetes](https://github.com/kubernetes/community/blob/master/contributors/guide/pull-requests.md), [OTel](https://github.com/open-telemetry/community/blob/main/policies/genai.md), [ASF](https://www.apache.org/legal/generative-tooling.html), [QEMU](https://www.qemu.org/docs/master/devel/code-provenance.html), [Ghostty](https://github.com/ghostty-org/ghostty/blob/main/AI_POLICY.md), [tldraw](https://github.com/tldraw/tldraw/blob/main/CONTRIBUTING.md), [curl](https://daniel.haxx.se/blog/2026/01/26/the-end-of-the-curl-bug-bounty/).

### 7. Content repositories that non-programmers contribute to

- **nuclei-templates** (MIT, 3.7k forks): directories by protocol, a creation guide and a review guide, and CI workflows for tests, template signing, checksums, statistics and KEV/EPSS enrichment.
- **Sigma**: separate trees for `rules`, `rules-emerging-threats`, `rules-threat-hunting`, `rules-placeholder`, `deprecated`, `unsupported`, plus `regression_data`; CI runs good-log tests, regression tests, a `known-FPs.csv`, validation and an automatic rule promoter.
- **CrowdSec hub** (MIT): `.tests/` holds one directory per scenario or CVE, with a generated `.index.json` and a taxonomy.
- **Falco rules** (Apache-2.0): maturity tags `sandbox`, `incubating`, `stable`, `deprecated`; only `stable` ships in the package; new rules cannot start as stable.

### 8. Business models that do not withhold features

| Model | Evidence |
|---|---|
| Hosting | Plausible depends on cloud subscribers and later reserved features. Grafana, Supabase (Apache-2.0) and Sentry all centre on hosting. |
| Managed intelligence | CrowdSec: software MIT; free non-contributors get a 3,000-IP list, contributors about 15,000, paying users up to 60,000. Only unmodified hub scenarios count, verified by content hash. Platinum blocklists from $1,900/month; reputation API from $49/month for 5,000 queries; OEM pricing offered ([docs](https://docs.crowdsec.net/docs/next/central_api/community_blocklist/), [pricing](https://www.crowdsec.net/pricing)). |
| Consortium and support | OISF: "Consortium members fund OISF international operations and the development team" (Proofpoint, AWS, ANSSI, Corelight and others). |
| Open core (`ee/` directory) | Fleet, PostHog, Infisical, GitLab. Commercially proven, but it is feature withholding and excluded by our brief. |
| Client open, server closed | Tailscale (BSD-3). The community rebuilt the server: headscale has 45.5k stars against Tailscale's 38.9k. |

### 9. Security disclosure, CVEs and bounties

GitHub is a CNA; a maintainer requests a CVE from a repository advisory and GitHub "usually reviews the request within 72 hours", but "cannot assign CVEs to your project if it is covered by another CNA" ([GitHub docs](https://docs.github.com/en/code-security/security-advisories/working-with-repository-security-advisories/about-repository-security-advisories)). Sovereign Tech Resilience offers a bug-and-fix bounty platform and audits ([programs](https://www.sovereign.tech/programs)).

### 10. EU Cyber Resilience Act

- Timeline: in force 2024-12-11; Article 14 reporting from **2026-09-11**; everything else from **2027-12-11** ([ORC WG](https://cra.orcwg.org/faq/cra-itself/timeline/)).
- A company publishing a free community version and selling a monetised one "is deemed a steward to the free (or community) version, and a manufacturer to the monetised version" (Commission guidance point 76, via [ORC WG](https://cra.orcwg.org/faq/manufacturers/both-manufacturer-and-steward/)). "Using the software to monetise other services" makes you a manufacturer regardless of earnings ([monetising FAQ](https://cra.orcwg.org/faq/projects/monetizing/)).
- Steward duties (Article 24): a documented cybersecurity policy, cooperation with market surveillance authorities, and Article 14(1) reporting to the extent involved in development. Stewards are exempt from fines (Article 64(10)(b)) and may not affix the CE mark (Recital 19).
- Annex III Class I includes identity and privileged access management, anti-malware software and SIEM; Class II includes "firewalls and intrusion detection and prevention systems". Article 32(5) lets FOSS manufacturers in those categories use self-assessment "provided that the technical documentation referred to in Article 31 is made available to the public" ([Regulation 2024/2847](https://eur-lex.europa.eu/legal-content/EN/TXT/HTML/?uri=OJ:L_202402847)).

### 11. Export controls

Linux Foundation guidance: published open source is "not subject to" the EAR, including binaries; since the 2021 change only **non-standard** cryptography requires notifying BIS and NSA; keep source for distributed binaries public and keep technical discussion public ([LF](https://www.linuxfoundation.org/resources/publications/understanding-us-export-controls-with-open-source-projects)). The hosted service and paid support remain subject to sanctions law **[memory]**.

### 12. Funding and adjacent vendors

- Alpha-Omega: annual budget over $7M; backers include Anthropic, AWS, Citi, GitHub, Google, Microsoft and OpenAI ([site](https://alpha-omega.dev/)).
- GitHub Secure Open Source Fund: $10,000 per project, three-week programme, rolling applications ([page](https://github.com/open-source/github-secure-open-source-fund)).
- Sovereign Tech Agency: Fund, Resilience, Fellowship, and a Standards pilot running June 2026 to June 2027.
- Incumbents keep the engine closed. BeyondTrust AI Agent Security is Windows and macOS only, with no public SDK ([docs](https://docs.beyondtrust.com/bt-docs/docs/ai-agent-security)). Microsoft Agent 365 went GA on 2026-05-01, licensed per user; only its SDKs and samples are open (MIT) ([overview](https://learn.microsoft.com/en-us/microsoft-agent-365/overview), [Agent365-python](https://github.com/microsoft/Agent365-python)).

## Matrix

Recommended licence per component.

| Component | Licence | Reason |
|---|---|---|
| Endpoint sensor (user space) | Apache-2.0 | Patent grant; embeddable; foundation-eligible |
| Kernel-side programs (eBPF, drivers) | `GPL-2.0-only OR BSD-2-Clause`, isolated directory | Kernel helper compatibility; the permissive alternative keeps embedders safe |
| Embeddable engine and SDKs | Apache-2.0 | The explicit embedding goal; matches Falco, OpenTelemetry, Tetragon |
| Schemas, event and policy specifications | Apache-2.0 | CNCF permits Apache-2.0 for API specifications; Community Spec licence is not OSI-approved |
| Server and console | Apache-2.0 | MSPs must host it; AGPL blocks CNCF, OpenSSF and AAIF |
| Rules, fingerprints, policy packs, integrations | Apache-2.0 | Falco precedent; no attribution-in-UI burden; author credit kept as rule metadata |
| ML model weights and training code | Apache-2.0 | OpenMDW and CDLA are not OSI-approved |
| Documentation | `Apache-2.0 OR CC-BY-4.0` | Satisfies the OSI constraint and the foundation documentation norm |
| Name and logo | Not licensed; trademark policy | The only asset that makes the commitments enforceable |

## Weak points, gaps and risks

- **Apache-2.0 gives no legal defence against a hyperscaler or EDR vendor hosting or embedding without paying.** The defence is operational: freshness of content and intelligence, the trademark, and being upstream.
- **The steward will be a CRA manufacturer** for the hosted product and any paid distribution, in a category that may be Class II. Article 14 reporting is already live.
- **Foundation entry is slow and conditional.** AAIF Sandbox gives infrastructure only and a twelve-month clock; CNCF incubation takes 5 to 15 months.
- **Agent-built code and the DCO.** QEMU-style projects would reject it outright; we need a defensible human-accountability chain or downstream embedders' lawyers will object.
- **Trailer conventions conflict.** Whatever we pick will be wrong for some upstream we contribute to.
- **A reciprocity-tiered intelligence feed is close to feature withholding.** It needs a clear public rule to stay on the right side of the brief.

## Implications for our design

**Day-one public commitments**

1. One licence, Apache-2.0, in every repository, with clean SPDX detection. No `ee/` directory, ever.
2. DCO only. No CLA, no copyright assignment.
3. A written covenant that all project code stays under an OSI-approved licence, plus a dated commitment to transfer trademark, domain and GitHub organisation to a neutral foundation when a stated trigger is met (two unaffiliated production adopters and commits from two organisations, which is AAIF's Growth bar).
4. Binaries built from the public source under the same licence as the source, with no usage thresholds.
5. A trademark policy that allows "embeds X" and "compatible with X" for unmodified builds and reserves the name for conformant ones.
6. `GOVERNANCE.md`, a maintainer ladder, a public roadmap, `ADOPTERS.md` and a steering group with seats reserved for non-steward members, modelled on OpenTelemetry's community repository.

**Governance path**

- Join the AAIF Security and Privacy, Identity and Trust, and Observability working groups immediately.
- Apply to AAIF Sandbox once the thesis and a working implementation exist. Keep CNCF Sandbox as the alternative for the Kubernetes and server side, and OpenSSF if the security community pull is stronger.
- Earn the OpenSSF Best Practices badge early; it is optional at AAIF and mandatory at OpenSSF.

**Contribution model**

- Two lanes. Content (rules, fingerprints, policy packs, integrations) is open to anyone as declarative files with fixtures, verified by CI. Code requires an accepted issue or specification first, plus a vouch-list entry.
- Every commit carries a human `Signed-off-by` and an `Assisted-by: <tool>:<model>` trailer. Agents never sign.
- The PR template demands evidence: tests run, a reproducer for bugs, and an explicit "what was not verified" line (the kernel's rule).
- Adopt LLVM's "extractive" label and Ghostty's vouch tooling instead of inventing our own.

**Content repository**

- Separate repository, separately versioned and signed, consumed through a generated index.
- Layout: `fingerprints/`, `detections/{sandbox,incubating,stable,deprecated}/`, `policy-packs/`, `integrations/`, `taxonomy/`, `tests/` with benign and regression corpora and a known-false-positives file.
- CI gates: schema validation, unique identifiers, required metadata, the positive fixture must fire, the benign corpus must not, a performance budget, and automatic promotion after a quiet period.

**Business model**

- Hosted multi-tenant service as the main revenue line.
- Intelligence network on CrowdSec's reciprocity rule: every rule is open; the live crowd-sourced feed is tiered by contribution and payment, with the rule published.
- OEM programme for embedders: signed long-term-support builds, embargoed security notices, a CRA documentation pack, integration engineering and a conformance mark.
- Support and training for self-hosters.

**Security and releases**

- GitHub private vulnerability reporting and GitHub as CNA at first; no cash bounty.
- Quarterly minors with the current and previous line supported (the OpenTofu, OpenBao and Valkey pattern), one long-term line a year, and continuous signed content releases.
- Publish the CRA technical documentation and cybersecurity policy in the repository so that both we and FOSS redistributors can use Article 32(5).

## Ideas worth stealing and whitespace

- **CRA documentation as a product.** Nobody ships a ready technical-documentation pack that embedders can reuse.
- **Federated vouch and denounce lists** across security projects; Ghostty's list is explicitly designed to be shared.
- **Hash-verified contribution** (CrowdSec) as the fair-exchange rule for an intelligence feed.
- **Maturity-tagged content with automatic promotion** (Falco plus Sigma's promoter), extended to agent fingerprints, which go stale monthly.
- **A machine-readable AI provenance standard.** Conventions conflict today; ASF notes a trailer would enable a "Tooling-Provenance file". An AIDR project is well placed to propose one through AAIF.
- **Linux coverage and an embeddable engine under Apache-2.0.** BeyondTrust and Microsoft offer neither.
- **Pre-foundation asset escrow.** No single-vendor project studied bound itself on trademarks before joining a foundation; NATS shows why it matters.

## Could not verify / open questions

- No web search today, so news after mid-2026 may be missing (new relicensing events, CRA guidance updates, AAIF membership changes).
- Fedora's AI policy (blocked by bot protection); CVE CNA rules (JavaScript-only page); GitLab stewardship promises (page too long to extract); Alpha-Omega grant sizes; OISF consortium pricing; AAIF charter PDF and founding date.
- OpenTofu and OpenBao production adoption numbers; only repository metrics were verified.
- Whether an AIDR sensor is Annex III Class I, Class II or neither. Needs counsel and the Commission's implementing act on category descriptions.
- CRA minimum support period for manufacturers (five years **[memory]**) and its effect on the long-term-support promise.
- Licence of the Rune UI framework and of the kernel-side dependencies.
- Whether AAIF would accept a project whose kernel-side code is dual GPL/BSD.
- Wassenaar "intrusion software" controls for any red-team or attack-simulation content.

## Sources

All accessed 2026-11-09.

- https://github.com/cncf/foundation/blob/main/charter.md — CNCF Charter, section 11
- https://github.com/cncf/toc/blob/main/process/README.md — CNCF project lifecycle
- https://github.com/ossf/tac/blob/main/process/project-lifecycle.md — OpenSSF project lifecycle
- https://github.com/aaif/technical-committee/blob/main/governance/project-lifecycle-policy.md — AAIF lifecycle policy (2026-10-15)
- https://github.com/aaif/project-proposals — AAIF project proposals
- https://aaif.io/about — AAIF members, board, projects
- https://owasp.org/www-policy/operational/projects — OWASP projects policy
- https://www.cncf.io/blog/2025/05/01/protecting-nats-and-the-integrity-of-open-source-cncfs-commitment-to-the-community/ — NATS dispute (2025-05-01)
- https://opentofu.org/manifesto/ and https://opentofu.org/blog/ — OpenTofu
- https://openbao.org/ — OpenBao
- https://redis.io/blog/agplv3/ — Redis AGPL (2025-05-01)
- https://goteleport.com/blog/teleport-community-license/ — Teleport (2024-03-08)
- https://plausible.io/blog/community-edition — Plausible CE (2024-02-23)
- https://grafana.com/blog/2021/04/20/qa-with-our-ceo-on-relicensing/ — Grafana (2021-04-21)
- https://element.io/blog/synapse-now-lives-at-github-com-element-hq-synapse/ — Element CLA
- https://suricata.io/contribution-agreement/ and https://suricata.io/consortium/ — OISF
- https://github.com/SigmaHQ/Detection-Rule-License — DRL 1.1
- https://github.com/falcosecurity/rules/blob/main/CONTRIBUTING.md — Falco rules maturity framework
- https://github.com/projectdiscovery/nuclei-templates, https://github.com/SigmaHQ/sigma, https://github.com/crowdsecurity/hub — content repository layouts
- https://docs.crowdsec.net/docs/next/central_api/community_blocklist/ and https://www.crowdsec.net/pricing — CrowdSec
- https://spdx.org/licenses/licenses.json — SPDX licence list 3.29.0 (2026-09-16)
- https://openmdw.ai/ — OpenMDW 1.1
- https://docs.kernel.org/process/generated-content.html and https://github.com/torvalds/linux/blob/master/Documentation/process/coding-assistants.rst — Linux kernel
- https://llvm.org/docs/AIToolPolicy.html — LLVM
- https://github.com/kubernetes/community/blob/master/contributors/guide/pull-requests.md — Kubernetes AI guidance
- https://github.com/open-telemetry/community/blob/main/policies/genai.md — OpenTelemetry
- https://www.apache.org/legal/generative-tooling.html — ASF
- https://www.qemu.org/docs/master/devel/code-provenance.html — QEMU
- https://github.com/ghostty-org/ghostty/blob/main/AI_POLICY.md and https://github.com/mitchellh/vouch — Ghostty, Vouch
- https://github.com/tldraw/tldraw/blob/main/CONTRIBUTING.md — tldraw
- https://daniel.haxx.se/blog/2026/01/26/the-end-of-the-curl-bug-bounty/ — curl (2026-01-26)
- https://eur-lex.europa.eu/legal-content/EN/TXT/HTML/?uri=OJ:L_202402847 — Regulation (EU) 2024/2847
- https://digital-strategy.ec.europa.eu/en/policies/cra-open-source — Commission CRA open-source page (2026-10-15)
- https://cra.orcwg.org/faq/ — ORC WG CRA FAQ (timeline, stewards, monetising)
- https://www.linuxfoundation.org/resources/publications/understanding-us-export-controls-with-open-source-projects — export controls
- https://docs.github.com/en/code-security/security-advisories/working-with-repository-security-advisories/about-repository-security-advisories — GitHub CNA
- https://www.sovereign.tech/programs, https://alpha-omega.dev/, https://github.com/open-source/github-secure-open-source-fund — funding
- https://docs.beyondtrust.com/bt-docs/docs/ai-agent-security — BeyondTrust AI Agent Security
- https://learn.microsoft.com/en-us/microsoft-agent-365/overview — Microsoft Agent 365 (updated 2026-10-23)
- GitHub API repository metadata for all projects named above

## Independent verification

_Checked 2026-11-09 by a separate fact-checker. Web search was unavailable (shared budget exhausted), so every check below was made against primary documents fetched directly (EUR-Lex, Commission guidance C(2026) 5252, foundation repositories through the GitHub API, SPDX JSON, project blogs and docs). News-level changes after these documents were last updated could not be searched for._

| # | Claim | Verdict | Note | Source |
|---|---|---|---|---|
| 1 | CNCF, OpenSSF and AAIF all require permissive licensing (CNCF: Apache-2.0 in and out, DCO, trademark transfer; OpenSSF: Apache-2.0 or MIT; AAIF: OSI-approved permissive) | Confirmed | CNCF charter section 11(a)(i) trademark transfer, 11(b)(ii) DCO plus Apache-2.0 inbound, 11(b)(iii) Apache-2.0 outbound. Both CNCF (11(c)) and OpenSSF ("unless otherwise approved by the Governing Board") have a board exception path, and CNCF lets a project add a CLA on top of DCO. AAIF wording is exact. | [CNCF charter](https://github.com/cncf/foundation/blob/main/charter.md), [OpenSSF lifecycle](https://github.com/ossf/tac/blob/main/process/project-lifecycle.md), [AAIF lifecycle](https://github.com/aaif/technical-committee/blob/main/governance/project-lifecycle-policy.md) |
| 2 | AAIF requires trademark and asset transfer to the LF and an LF technical charter; Growth needs production use by two unaffiliated organisations and commits from two organisations over six months | Confirmed | Text matches the policy as of the 2026-10-15 commit. The transfer applies at Sandbox entry, not only at Growth. Admission at every stage also needs a Technical Committee majority and Governing Board approval. | [AAIF lifecycle](https://github.com/aaif/technical-committee/blob/main/governance/project-lifecycle-policy.md) |
| 3 | CRA: steward for the free version, manufacturer for the monetised one; monetising other services through the software makes you a manufacturer; Article 14 from 2026-09-11, the rest from 2027-12-11 | Confirmed, with two cautions | Wording is point 76 of Commission guidance C(2026) 5252 (27 July 2026, non-binding); dates are Article 71. Caution 1: point 54 and its Example 15 (a free open-source VPN client with paid servers is "placed on the market") mean a free sensor that connects to a paid hosted service or a paid intelligence tier is likely itself a manufacturer product, so the steward-only status of the free version does not hold for the business model proposed here. Caution 2: reporting for stewards (Article 24(3)) starts 2027-12-11; the 2026-09-11 date is for manufacturers. | [Commission guidance annex](https://ec.europa.eu/newsroom/dae/redirection/document/131456), [Commission CRA reporting page](https://digital-strategy.ec.europa.eu/en/policies/cra-reporting), [Regulation 2024/2847](https://eur-lex.europa.eu/legal-content/EN/TXT/HTML/?uri=OJ:L_202402847) |
| 4 | Annex III Class II includes firewalls and intrusion detection and prevention systems; Class I includes SIEM, anti-malware, identity/PAM; Article 32(5) allows FOSS self-assessment with public technical documentation | Confirmed | Annex III Class I items 1, 4, 7 and Class II item 2 read as stated. Article 32(5) requires the documentation to be public "at the time of the placing on the market". It covers Annex III only, not Annex IV, and does not relax the Annex I requirements themselves. | [Regulation 2024/2847](https://eur-lex.europa.eu/legal-content/EN/TXT/HTML/?uri=OJ:L_202402847) |
| 5 | SPDX 3.29.0 marks the listed licences as not OSI-approved | Confirmed | Downloaded list is 3.29.0 dated 2026-09-16; all ten are `isOsiApproved: false`. FSL appears as `FSL-1.1-ALv2` and `FSL-1.1-MIT`. SPDX lists only `OpenMDW-1.0`; version 1.1 (the current one on openmdw.ai) has no SPDX identifier yet, so scanners will not recognise it. | [SPDX JSON](https://spdx.org/licenses/licenses.json) |
| 6 | NATS: CNCF refused to hand over the domain and GitHub organisation and petitioned to cancel the trademark registrations; NATS stayed in CNCF | Confirmed | CNCF post and the joint announcement of 2025-05-01 both agree; Synadia assigned its two registrations to the LF and may fork only under a new name. Synadia's own post (2025-04-25) says it was "exploring a BSL license model for future versions" and denies planning a blanket relicence; CNCF quotes Synadia's exit proposal as adopting BUSL for the server. | [Joint announcement](https://www.cncf.io/announcements/2025/05/01/cncf-and-synadia-align-on-securing-the-future-of-the-nats-io-project/), [Synadia response](https://www.synadia.com/blog/synadia-response-to-cncf) |
| 7 | Kernel: agents must not add Signed-off-by; Kubernetes forbids assisted-by trailers; LLVM and OpenTelemetry recommend them | Confirmed | Kernel text is verbatim in `coding-assistants.rst` on master. Kubernetes: "`assisted-by`, `co-developed` or similar commit trailer is not allowed". LLVM offers the trailer as one acceptable way to label; OpenTelemetry calls it "the recommended method". | [kernel](https://github.com/torvalds/linux/blob/master/Documentation/process/coding-assistants.rst), [Kubernetes](https://github.com/kubernetes/community/blob/master/contributors/guide/pull-requests.md), [LLVM source](https://github.com/llvm/llvm-project/blob/main/llvm/docs/AIToolPolicy.md), [OTel](https://github.com/open-telemetry/community/blob/main/policies/genai.md) |
| 8 | MinIO AGPL repository archived and marked unmaintained, pointing to AIStor; OpenTofu, OpenBao and Valkey each show 350+ contributors and dual release lines | Corrected (second half) | MinIO: confirmed (`archived: true`, README as quoted). Release cadence: confirmed (OpenTofu 1.13/1.12 and OpenBao 2.7/2.6 patched together; Valkey maintains five lines, 7.2 to 9.1). Contributor counts of 351, 373 and 382 are GitHub API figures for the whole inherited history; the top contributors are pre-fork upstream authors (mitchellh, jefferai, antirez). They do not measure the forks' own contributor base and should not be cited as fork health. | GitHub API: `repos/minio/minio`, `repos/{opentofu/opentofu,openbao/openbao,valkey-io/valkey}/contributors` and `/releases` |
| 9 | curl ended its bounty on 2026-01-31 after the confirmed rate fell from above 15% to below 5%; 87 vulnerabilities, over $100,000 | Confirmed | Figures match the post; `docs/BUG-BOUNTY.md` in the repository now reads "No curl bug bounty". See extra check A for what happened next. | [curl BUG-BOUNTY.md](https://github.com/curl/curl/blob/master/docs/BUG-BOUNTY.md) |
| 10 | CrowdSec tiers: 3,000 IPs non-contributing, about 15,000 contributing with hash-verified unmodified hub scenarios, up to 60,000 paying | Confirmed | Live docs give Lite 3,000, Community 15,000, Premium up to 60,000; scenario hash is compared to the hub hash, custom or tainted scenarios do not count, and paying users need not contribute. The pricing page confirms $1,900/month Platinum and $49/month for 5,000 CTI queries but gives no list sizes. | [CrowdSec docs](https://docs.crowdsec.net/docs/next/central_api/community_blocklist/), [pricing](https://www.crowdsec.net/pricing) |

Further statements checked in the brief:

| | Statement | Verdict | Note | Source |
|---|---|---|---|---|
| A | curl: "reports now via GitHub private reporting" (section 6) | Outdated | curl reversed that move. Since 2026-03-01 reports go to HackerOne again, still with no bounty; the maintainer called the GitHub move "a mistake" because private reporting lacked features the team needed. This weakens the "GitHub private vulnerability reporting at first" recommendation; evaluate its limits before committing. | [curl security moves again](https://daniel.haxx.se/blog/2026/02/25/curl-security-moves-again/), [VULN-DISCLOSURE-POLICY.md](https://github.com/curl/curl/blob/master/docs/VULN-DISCLOSURE-POLICY.md) |
| B | "Every licence rug-pull studied (HashiCorp, Redis, Elastic) was enabled by a CLA or copyright assignment. DCO disperses copyright so nobody can relicense inbound code." (TL;DR) | Overstated | Redis had no CLA before 2024: `CONTRIBUTING.md` at 7.2.4 only asks contributors to release under BSD. Redis closed future versions because BSD permits it. The same is true of Apache-2.0, so DCO does not stop a steward relicensing future releases. Only asset ownership does, as the brief's own section 3 inference says. | [redis CONTRIBUTING at 7.2.4](https://github.com/redis/redis/blob/7.2.4/CONTRIBUTING.md) |
| C | BeyondTrust AI Agent Security is Windows and macOS only; Microsoft Agent 365 GA 2026-05-01, per user (section 12) | Confirmed | BeyondTrust docs: "supports Windows and macOS endpoints only" (Windows 11 / Server 2022+ x64, macOS 14 to 26), delivered through its Pathfinder agent, no SDK mentioned. Microsoft Learn: generally available "as of May 1, 2026 ... on a per user basis", E5 recommended as prerequisite. | [BeyondTrust](https://docs.beyondtrust.com/bt-docs/docs/ai-agent-security), [Microsoft](https://learn.microsoft.com/en-us/microsoft-agent-365/overview) |
