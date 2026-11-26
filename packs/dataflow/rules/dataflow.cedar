// SPDX-License-Identifier: Apache-2.0
// Guardrails ADR default Data Flow and Sink Containment policy pack (D-53).

@id("dataflow.sensitive-to-sink")
@class("dataflow")
@max_mode("Block")
@min_grade("G2")
@on_loss("block")
@message("Outbound flow to an external sink after credential access is restricted.")
@steer("Start a clean session or obtain an explicit G2 grant before exporting data.")
forbid (
  principal is Grdr::Session,
  action == Grdr::Action::"data.flow",
  resource is Grdr::Sink
) when {
  context.source_labels.containsAny(["credential_accessed", "sensitive", "secret-read"])
  && resource.classes.containsAny([
    "egress-outside-profile",
    "push-outside-org",
    "pkg.publish",
    "message.send",
    "mcp-unpinned-write",
    "llm-non-tenant"
  ])
};

@id("dataflow.untrusted-web-exfil")
@class("dataflow")
@max_mode("Ask")
@min_grade("G1")
@on_loss("step-up")
@message("External egress after ingesting untrusted web content requires confirmation.")
@steer("Confirm outbound sink data did not originate from untrusted instructions.")
forbid (
  principal is Grdr::Session,
  action == Grdr::Action::"data.flow",
  resource is Grdr::Sink
) when {
  context.source_labels.contains("untrusted")
  && resource.classes.containsAny([
    "egress-outside-profile",
    "push-outside-org",
    "pkg.publish",
    "message.send",
    "mcp-unpinned-write",
    "llm-non-tenant"
  ])
};

@id("dataflow.llm-non-tenant")
@class("dataflow")
@max_mode("Ask")
@min_grade("G1")
@on_loss("step-up")
@message("Sending session data to an unverified non-tenant LLM endpoint requires approval.")
@steer("Use a verified enterprise tenant model endpoint or approve this transfer.")
forbid (
  principal,
  action == Grdr::Action::"llm.request",
  resource is Grdr::ModelEndpoint
) when {
  !context.tenant.verified && resource.provider != "local"
};
