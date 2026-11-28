@id("essentials.control-files.write")
@class("config-tamper")
@max_mode("Block")
@min_grade("G2")
@on_loss("block")
@final("true")
@message("Agents cannot modify agent hook settings or Guardrails control files.")
@steer("Ask the user before changing hook, MCP, or Guardrails configuration.")
forbid (
  principal is Grdr::Session,
  action in [Grdr::Action::"file.write", Grdr::Action::"file.delete"],
  resource
) when {
  resource.classes.containsAny(["agent-control", "grdr-control", "monitoring-config"])
};

@id("essentials.control-files.config-change")
@class("config-tamper")
@max_mode("Block")
@min_grade("G2")
@on_loss("block")
@final("true")
@message("Agents cannot change Guardrails or agent monitoring configuration.")
@steer("Ask the user to adjust configuration settings.")
forbid (
  principal is Grdr::Session,
  action == Grdr::Action::"config.change",
  resource
) when {
  resource.classes.containsAny(["agent-control", "grdr-control", "monitoring-config"])
};

@id("essentials.bypass-flags")
@class("config-tamper")
@max_mode("Block")
@min_grade("G2")
@on_loss("block")
@final("true")
@message("Bypassing security hooks or permission boundaries is blocked by Essentials.")
@steer("Run commands without bypass or hook-disabling flags.")
forbid (
  principal is Grdr::Session,
  action in [Grdr::Action::"exec", Grdr::Action::"agent.spawn", Grdr::Action::"config.change"],
  resource
) when {
  context.facts.containsAny(["flag.bypass-permissions", "flag.hooks-disabled", "flag.no-sandbox", "grdr.disable"])
  || (action == Grdr::Action::"exec" && context.command.classes.containsAny(["flag.bypass-permissions", "flag.no-sandbox"]))
};

@id("essentials.honeytoken.file")
@class("secret")
@max_mode("Block")
@min_grade("G2")
@on_loss("block")
@final("true")
@message("Access to decoy honeytoken material is blocked by Essentials.")
@steer("Stop accessing decoy credential files.")
forbid (
  principal,
  action == Grdr::Action::"file.read",
  resource is Grdr::Path
) when {
  resource.classes.contains("honeytoken")
};

@id("essentials.honeytoken.cred")
@class("secret")
@max_mode("Block")
@min_grade("G2")
@on_loss("block")
@final("true")
@message("Use of decoy honeytoken credentials is blocked by Essentials.")
@steer("Use approved non-honeytoken credentials only.")
forbid (
  principal,
  action == Grdr::Action::"cred.use",
  resource is Grdr::Credential
) when {
  resource.classes.contains("honeytoken")
};

@id("essentials.undetermined.control-files")
@class("config-tamper")
@max_mode("Ask")
@min_grade("G1")
@on_loss("step-up")
@message("Modifying agent or Guardrails control files from an unattributed process requires approval.")
@steer("Confirm this configuration edit interactively.")
forbid (
  principal is Grdr::Process,
  action in [Grdr::Action::"file.write", Grdr::Action::"file.delete"],
  resource is Grdr::Path
) when {
  principal.agent_capable_host
  && principal.actor_kind == "undetermined"
  && resource.classes.containsAny(["agent-control", "grdr-control", "monitoring-config"])
};

@id("essentials.cred-store.read")
@class("secret")
@max_mode("Ask")
@min_grade("G1")
@on_loss("step-up")
@message("Reading credential stores and private keys requires your approval.")
@steer("Request scoped approval or use a configured credential helper.")
forbid (
  principal is Grdr::Session,
  action in [Grdr::Action::"file.read", Grdr::Action::"cred.use", Grdr::Action::"exec"],
  resource
) when {
  resource.classes.containsAny(["cred-store", "private-key", "credential-store"])
};

@id("essentials.delete-outside-workspace")
@class("irreversible")
@max_mode("Ask")
@min_grade("G1")
@on_loss("step-up")
@message("Recursive deletion outside the workspace requires approval.")
@steer("Limit deletion to workspace-local files or request approval.")
forbid (
  principal is Grdr::Session,
  action in [Grdr::Action::"exec", Grdr::Action::"file.delete"],
  resource
) when {
  resource.classes.contains("destructive-delete")
  || (action == Grdr::Action::"file.delete" && context.recursive && !resource.in_workspace)
} unless {
  resource.classes.contains("session-tmp")
};

@id("essentials.elevate")
@class("elevate")
@max_mode("Ask")
@min_grade("G1")
@on_loss("step-up")
@message("Privilege elevation from an agent session requires approval.")
@steer("Explain why privilege elevation is needed and request approval.")
forbid (
  principal is Grdr::Session,
  action in [Grdr::Action::"elevate", Grdr::Action::"exec"],
  resource
) when {
  action == Grdr::Action::"elevate" || resource.classes.contains("privilege-elevate")
};
