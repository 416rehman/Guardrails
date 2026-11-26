// SPDX-License-Identifier: Apache-2.0
// Guardrails ADR default Privilege Elevation policy pack (D-53).

@id("elevate.route")
@class("elevate")
@max_mode("Ask")
@min_grade("G2")
@on_loss("step-up")
@message("Direct privilege elevation routes require sponsor-grade approval.")
@steer("Request G2 elevation approval with task justification.")
forbid (
  principal is Grdr::Session,
  action == Grdr::Action::"elevate",
  resource is Grdr::ElevationRoute
);

@id("elevate.sudo-exec")
@class("elevate")
@max_mode("Ask")
@min_grade("G2")
@on_loss("step-up")
@message("Running sudo, doas, or runas from an agent requires approval.")
@steer("Run unprivileged commands or ask the operator to elevate manually.")
forbid (
  principal is Grdr::Session,
  action == Grdr::Action::"exec",
  resource is Grdr::Executable
) when {
  resource.classes.contains("privilege-elevate") || context.command.classes.contains("privilege-elevate")
};
