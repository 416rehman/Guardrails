// SPDX-License-Identifier: Apache-2.0
// Guardrails ADR default Secrets policy pack (D-53).

@id("secrets.cred-store-read")
@class("secret")
@max_mode("Ask")
@min_grade("G1")
@on_loss("step-up")
@message("Reading credential stores or private key material requires approval.")
@steer("Use a configured secret broker or request explicit operator approval.")
forbid (
  principal is Grdr::Session,
  action in [Grdr::Action::"file.read", Grdr::Action::"cred.use", Grdr::Action::"exec"],
  resource
) when {
  resource.classes.containsAny(["cred-store", "private-key"])
};

@id("secrets.credential-redact")
@class("secret")
@max_mode("Ask")
@min_grade("G1")
@on_loss("step-up")
@remedy("modify")
@message("Inline secret material must be redacted or swapped with broker credentials.")
@steer("Remove raw tokens from tool arguments or use broker references.")
forbid (
  principal is Grdr::Session,
  action in [Grdr::Action::"exec", Grdr::Action::"net.request", Grdr::Action::"net.connect", Grdr::Action::"llm.request", Grdr::Action::"mcp.call"],
  resource
) when {
  resource.classes.contains("secret-material")
};

@id("secrets.honeytoken-trap")
@class("secret")
@max_mode("Block")
@min_grade("G2")
@on_loss("block")
@final("true")
@message("Access to decoy honeytoken credentials is blocked.")
@steer("Do not touch honeytoken trap credentials.")
forbid (
  principal,
  action in [Grdr::Action::"cred.use", Grdr::Action::"file.read", Grdr::Action::"exec"],
  resource
) when {
  resource.classes.contains("honeytoken")
};

@id("secrets.undetermined-cred-store")
@class("secret")
@max_mode("Ask")
@min_grade("G1")
@on_loss("step-up")
@message("Accessing credential stores from an undetermined process on an agent host requires approval.")
@steer("Verify attribution and request approval before accessing private keys.")
forbid (
  principal is Grdr::Process,
  action in [Grdr::Action::"file.read", Grdr::Action::"cred.use"],
  resource
) when {
  principal.agent_capable_host
  && principal.actor_kind == "undetermined"
  && resource.classes.containsAny(["cred-store", "private-key"])
};
