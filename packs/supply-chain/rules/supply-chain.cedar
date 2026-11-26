// SPDX-License-Identifier: Apache-2.0
// Guardrails ADR default Supply Chain policy pack (D-53).

@id("supply-chain.pipe-to-shell")
@class("supply-chain")
@max_mode("Block")
@min_grade("G2")
@on_loss("block")
@final("true")
@message("Piping remote scripts straight into a shell interpreter is blocked.")
@steer("Download, inspect, and verify script digests before running them.")
forbid (
  principal is Grdr::Session,
  action == Grdr::Action::"exec",
  resource is Grdr::Executable
) when {
  resource.classes.contains("supply-chain-risk") || context.command.classes.contains("supply-chain-risk")
};

@id("supply-chain.package-publish")
@class("supply-chain")
@max_mode("Ask")
@min_grade("G2")
@on_loss("step-up")
@message("Publishing artifacts to package registries requires sponsor approval.")
@steer("Verify package contents and request G2 publish approval.")
forbid (
  principal is Grdr::Session,
  action == Grdr::Action::"data.flow",
  resource is Grdr::Sink
) when {
  resource.classes.contains("pkg.publish")
};
