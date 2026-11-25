// SPDX-License-Identifier: Apache-2.0
// Guardrails ADR default Essentials policy pack (D-53).
// Forbid-only policies; zero Grdr::User references (works-council compatible).

@id("essentials.control-files.write")
@class("config-tamper")
@final("true")
forbid (
  principal is Grdr::Session,
  action in [Grdr::Action::"file.write", Grdr::Action::"file.delete"],
  resource is Grdr::Path
) when {
  resource.classes.containsAny(["agent-control", "grdr-control", "monitoring-config"])
};

@id("essentials.control-files.config-change")
@class("config-tamper")
@final("true")
forbid (
  principal is Grdr::Session,
  action == Grdr::Action::"config.change",
  resource is Grdr::ConfigTarget
) when {
  resource.classes.containsAny(["agent-control", "grdr-control", "monitoring-config"])
};

@id("essentials.bypass-flags")
@class("config-tamper")
@final("true")
forbid (
  principal is Grdr::Session,
  action == Grdr::Action::"exec",
  resource is Grdr::Executable
) when {
  context.facts.containsAny(["flag.bypass-permissions", "flag.hooks-disabled", "grdr.disable"])
  || context.command.classes.containsAny(["flag.bypass-permissions", "flag.no-sandbox"])
};

@id("essentials.honeytoken.file")
@class("secret")
@on_loss("block")
@final("true")
forbid (
  principal is Grdr::Session,
  action == Grdr::Action::"file.read",
  resource is Grdr::Path
) when {
  resource.classes.contains("honeytoken")
};

@id("essentials.honeytoken.cred")
@class("secret")
@on_loss("block")
@final("true")
forbid (
  principal is Grdr::Session,
  action == Grdr::Action::"cred.use",
  resource is Grdr::Credential
) when {
  resource.classes.contains("honeytoken")
};

@id("essentials.cred-store.read")
@class("secret")
@max_mode("Ask")
@approver("self")
@min_grade("G1")
forbid (
  principal is Grdr::Session,
  action == Grdr::Action::"file.read",
  resource is Grdr::Path
) when {
  resource.classes.containsAny(["cred-store", "private-key", "credential-store"])
};

@id("essentials.delete-outside-workspace")
@class("irreversible")
@max_mode("Ask")
@approver("self")
@min_grade("G1")
forbid (
  principal is Grdr::Session,
  action == Grdr::Action::"file.delete",
  resource is Grdr::Path
) when {
  context.recursive && !resource.in_workspace
} unless {
  resource.classes.contains("session-tmp")
};

@id("essentials.elevate")
@class("elevate")
@max_mode("Ask")
@approver("sponsor")
@min_grade("G2")
forbid (
  principal is Grdr::Session,
  action == Grdr::Action::"elevate",
  resource is Grdr::ElevationRoute
) when {
  !context.grants.contains("elevate")
};
