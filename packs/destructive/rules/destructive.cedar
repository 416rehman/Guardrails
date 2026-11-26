// SPDX-License-Identifier: Apache-2.0
// Guardrails ADR default Destructive Actions policy pack (D-53).

@id("destructive.delete-outside-workspace")
@class("irreversible")
@max_mode("Ask")
@min_grade("G1")
@on_loss("step-up")
@obligation("snapshot")
@message("Recursive deletion outside the workspace requires explicit approval.")
@steer("Keep deletions inside the workspace or request an approval grant.")
forbid (
  principal is Grdr::Session,
  action == Grdr::Action::"file.delete",
  resource is Grdr::Path
) when {
  context.recursive && !resource.in_workspace
} unless {
  resource.classes.contains("session-tmp")
};

@id("destructive.shell-wipe")
@class("irreversible")
@max_mode("Ask")
@min_grade("G1")
@on_loss("step-up")
@message("Destructive recursive force delete or disk command requires approval.")
@steer("Avoid force-recursive deletion or destructive resets without user confirmation.")
forbid (
  principal is Grdr::Session,
  action == Grdr::Action::"exec",
  resource is Grdr::Executable
) when {
  context.command.classes.contains("destructive-delete")
};

@id("destructive.opaque-wipe")
@class("irreversible")
@max_mode("Block")
@min_grade("G2")
@on_loss("block")
@final("true")
@message("Opaque destructive command execution is blocked.")
@steer("Use explicit, non-obfuscated workspace cleanup commands.")
forbid (
  principal is Grdr::Session,
  action == Grdr::Action::"exec",
  resource is Grdr::Executable
) when {
  resource.classes.contains("destructive-delete") && context.facts.contains("exec.opaque")
};
