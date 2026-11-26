// SPDX-License-Identifier: Apache-2.0
// Guardrails ADR default Base policy pack (D-53).

@id("base.permit-session")
@class("baseline")
@max_mode("Block")
@min_grade("G0")
@on_loss("allow")
@message("Baseline permit for attributed agent sessions subject to pack forbids.")
@steer("Proceed within configured policy boundaries.")
permit (
  principal is Grdr::Session,
  action in Grdr::Action::"any",
  resource
);

@id("base.permit-process")
@class("baseline")
@max_mode("Block")
@min_grade("G0")
@on_loss("allow")
@message("Baseline permit for attributed device processes subject to pack forbids.")
@steer("Proceed within configured policy boundaries.")
permit (
  principal is Grdr::Process,
  action in [
    Grdr::Action::"exec",
    Grdr::Action::"file.read",
    Grdr::Action::"file.write",
    Grdr::Action::"file.delete",
    Grdr::Action::"net.connect",
    Grdr::Action::"net.request",
    Grdr::Action::"llm.request",
    Grdr::Action::"mcp.connect",
    Grdr::Action::"mcp.call",
    Grdr::Action::"cred.use",
    Grdr::Action::"config.change",
    Grdr::Action::"elevate",
    Grdr::Action::"ui.act"
  ],
  resource
);

@id("base.frozen-session")
@class("containment")
@max_mode("Block")
@min_grade("G3")
@on_loss("block")
@final("true")
@message("Frozen sessions cannot execute further actions until released.")
@steer("Stop acting and ask a human operator to review the session freeze.")
forbid (
  principal is Grdr::Session,
  action in Grdr::Action::"any",
  resource
) when {
  context.session.labels.contains("session:frozen")
};
