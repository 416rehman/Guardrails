// SPDX-License-Identifier: Apache-2.0
// Guardrails ADR default Network Egress policy pack (D-53).

@id("egress.metadata-ssrf")
@class("egress")
@max_mode("Block")
@min_grade("G3")
@on_loss("block")
@final("true")
@message("Cloud instance metadata SSRF endpoints are blocked.")
@steer("Do not query local or cloud instance metadata IP endpoints.")
forbid (
  principal is Grdr::Session,
  action == Grdr::Action::"net.request",
  resource is Grdr::Endpoint
) when {
  resource.classes.contains("metadata-endpoint") || context.http.classes.contains("metadata-ssrf")
};

@id("egress.metadata-ssrf-connect")
@class("egress")
@max_mode("Block")
@min_grade("G3")
@on_loss("block")
@final("true")
@message("Raw socket connection to cloud instance metadata SSRF endpoints is blocked.")
@steer("Do not connect to local or cloud instance metadata IP endpoints.")
forbid (
  principal is Grdr::Session,
  action in [Grdr::Action::"net.connect", Grdr::Action::"net.request"],
  resource is Grdr::Endpoint
) when {
  resource.classes.contains("metadata-endpoint")
};

@id("egress.metadata-ssrf-exec")
@class("egress")
@max_mode("Block")
@min_grade("G3")
@on_loss("block")
@final("true")
@message("Shell command targeting cloud instance metadata SSRF endpoints is blocked.")
@steer("Do not query local or cloud instance metadata IP endpoints from shell tools.")
forbid (
  principal is Grdr::Session,
  action == Grdr::Action::"exec",
  resource is Grdr::Executable
) when {
  resource.classes.contains("metadata-endpoint") || context.command.classes.contains("metadata-ssrf")
};

@id("egress.external-upload")
@class("egress")
@max_mode("Ask")
@min_grade("G1")
@on_loss("step-up")
@message("Outbound HTTP uploads and paste sites require approval.")
@steer("Confirm destination domain and payload classification with the operator.")
forbid (
  principal is Grdr::Session,
  action == Grdr::Action::"net.request",
  resource is Grdr::Endpoint
) when {
  context.http.classes.contains("external-upload")
};

@id("egress.nonstandard-port")
@class("egress")
@max_mode("Ask")
@min_grade("G1")
@on_loss("step-up")
@message("Outbound connections to non-HTTP ports require approval.")
@steer("Use standard HTTPS port 443 endpoints or request an approval grant.")
forbid (
  principal is Grdr::Session,
  action in [Grdr::Action::"net.connect", Grdr::Action::"net.request"],
  resource is Grdr::Endpoint
) when {
  resource.port > 0 && resource.port != 443 && resource.port != 80
};
