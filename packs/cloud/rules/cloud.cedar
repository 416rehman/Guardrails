// SPDX-License-Identifier: Apache-2.0
// Guardrails ADR default Cloud IAM and Production Infrastructure pack (D-53).

@id("cloud.unverified-admin-request")
@class("cloud")
@max_mode("Ask")
@min_grade("G2")
@on_loss("step-up")
@message("Privileged cloud API calls against unverified tenants require approval.")
@steer("Target verified sandbox tenants or request sponsor approval.")
forbid (
  principal is Grdr::Session,
  action == Grdr::Action::"net.request",
  resource is Grdr::Endpoint
) when {
  !context.cloud.verified && context.cloud.account_classes.contains("privileged-role")
};

@id("cloud.destructive-cli")
@class("cloud")
@max_mode("Ask")
@min_grade("G2")
@on_loss("step-up")
@message("Cloud IAM mutations or cluster destroy CLI operations require approval.")
@steer("Review proposed infrastructure diff and request G2 operator confirmation.")
forbid (
  principal is Grdr::Session,
  action == Grdr::Action::"exec",
  resource is Grdr::Executable
) when {
  resource.classes.contains("cloud-admin") || context.command.classes.contains("cloud-admin")
};
