// SPDX-License-Identifier: Apache-2.0
// Guardrails ADR default Agent Controls and Sub-Agent Delegation pack (D-53).

@id("agents.control-files-write")
@class("config-tamper")
@max_mode("Block")
@min_grade("G2")
@on_loss("block")
@final("true")
@message("Modifying agent hook settings or monitoring files is blocked.")
@steer("Ask the user to edit agent or Guardrails configuration files directly.")
forbid (
  principal is Grdr::Session,
  action in [Grdr::Action::"file.write", Grdr::Action::"file.delete"],
  resource is Grdr::Path
) when {
  resource.classes.containsAny(["agent-control", "grdr-control", "monitoring-config"])
};

@id("agents.control-config-change")
@class("config-tamper")
@max_mode("Block")
@min_grade("G2")
@on_loss("block")
@final("true")
@message("Mutating Guardrails configuration targets is blocked.")
@steer("Do not alter configuration enforcement targets programmatically.")
forbid (
  principal is Grdr::Session,
  action == Grdr::Action::"config.change",
  resource is Grdr::ConfigTarget
) when {
  context.change_classes.containsAny(["agent-control", "grdr-control", "monitoring-config"])
};

@id("agents.uncontained-deep-spawn")
@class("containment")
@max_mode("Ask")
@min_grade("G1")
@on_loss("step-up")
@message("Spawning uncontained nested sub-agents beyond depth 2 requires approval.")
@steer("Enable sandbox containment or request approval to spawn deeper sub-agents.")
forbid (
  principal is Grdr::Session,
  action == Grdr::Action::"agent.spawn",
  resource is Grdr::Agent
) when {
  (context.child.depth > 2 || principal.contained) && !context.child.contained
};

@id("agents.undetermined.control-files")
@class("config-tamper")
@max_mode("Ask")
@min_grade("G1")
@on_loss("step-up")
@message("Modifying agent control files from an unattributed process requires approval.")
@steer("Verify user identity and request approval before altering control files.")
forbid (
  principal is Grdr::Process,
  action in [Grdr::Action::"file.write", Grdr::Action::"file.delete"],
  resource is Grdr::Path
) when {
  principal.agent_capable_host
  && principal.actor_kind == "undetermined"
  && resource.classes.containsAny(["agent-control", "grdr-control", "monitoring-config"])
};

@id("agents.undetermined.control-config")
@class("config-tamper")
@max_mode("Ask")
@min_grade("G1")
@on_loss("step-up")
@message("Mutating Guardrails configuration from an unattributed process requires approval.")
@steer("Verify user identity and request approval before modifying configuration targets.")
forbid (
  principal is Grdr::Process,
  action == Grdr::Action::"config.change",
  resource is Grdr::ConfigTarget
) when {
  principal.agent_capable_host
  && principal.actor_kind == "undetermined"
  && context.change_classes.containsAny(["agent-control", "grdr-control", "monitoring-config"])
};
