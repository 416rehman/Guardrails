// SPDX-License-Identifier: Apache-2.0
// Guardrails ADR credential locator hygiene policy (D-53, D-54).

@id("cred-locator.honeytoken-trap.file")
@class("secret")
@max_mode("Block")
@min_grade("G2")
@on_loss("block")
@final("true")
@message("Access to decoy honeytoken credential files is blocked.")
@steer("Do not open or use honeytoken decoy credential paths.")
forbid (
  principal is Grdr::Session,
  action == Grdr::Action::"file.read",
  resource is Grdr::Path
) when {
  resource.classes.contains("honeytoken")
};

@id("cred-locator.honeytoken-trap.cred")
@class("secret")
@max_mode("Block")
@min_grade("G2")
@on_loss("block")
@final("true")
@message("Use of decoy honeytoken credentials is blocked.")
@steer("Do not use honeytoken decoy credentials.")
forbid (
  principal is Grdr::Session,
  action == Grdr::Action::"cred.use",
  resource is Grdr::Credential
) when {
  resource.classes.contains("honeytoken")
};

@id("cred-locator.store-read.file")
@class("secret")
@max_mode("Ask")
@approver("self")
@min_grade("G1")
@on_loss("step-up")
@message("Direct access to discovered credential store files requires approval.")
@steer("Use brokered credential helpers (`grdr cred adopt`) instead of raw store files.")
forbid (
  principal is Grdr::Session,
  action == Grdr::Action::"file.read",
  resource is Grdr::Path
) when {
  resource.classes.containsAny(["cred-store", "private-key", "agent-store"])
};

@id("cred-locator.store-read.cred")
@class("secret")
@max_mode("Ask")
@approver("self")
@min_grade("G1")
@on_loss("step-up")
@message("Direct access to discovered credential bindings requires approval.")
@steer("Use brokered credential helpers (`grdr cred adopt`) instead of raw credentials.")
forbid (
  principal is Grdr::Session,
  action == Grdr::Action::"cred.use",
  resource is Grdr::Credential
) when {
  resource.classes.containsAny(["cred-store", "private-key", "agent-store"])
};
