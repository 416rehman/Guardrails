# macOS Native Container App, Network Extension & Endpoint Security (`platform/macos/`)

This directory scaffolds the macOS System Extensions and Container App wrapping the `grdr-sensor-macos` Rust static library (`libgrdr_sensor_macos.a`) over its `catch_unwind`-guarded C ABI (`Bridge/GrdrSensorMacOS.h`).

## Layout

- `Bridge/`: `GrdrSensorMacOS.h` + `module.modulemap` exposing `grdr_macos_*` C symbols from `crates/grdr-sensor-macos`.
- `ContainerApp/`: `com.guardrailshq.grdr.app` menu-bar / activation host invoking `OSSystemExtensionRequest` to activate the Network Extension and Endpoint Security system extensions.
- `NetworkExtension/`: `com.guardrailshq.grdr.network-extension` (`NEFilterDataProvider` Inspector grade + QUIC UDP/443 drop, opt-in `NEDNSProxyProvider`, opt-in `NETransparentProxyProvider`).
- `EndpointSecurityExtension/`: `com.guardrailshq.grdr.endpoint-security` (`es_new_client` tree coordinator, `es_new_descendants_client` supervisor, and Team-ID verified XPC daemon bridge).

## External Blockers (`[EXT]`)

- `[EXT]` **Apple Developer Program Membership & Team ID (`DEVELOPMENT_TEAM`):** Activating a System Extension (`OSSystemExtensionRequest`), code-signing `.app`/`.appex`/`.systemextension` bundles, notarizing `.pkg` installers, and using `NetworkExtension` entitlements (`com.apple.developer.networking.networkextension`) require an enrolled paid Apple Developer Program account and organization Team ID (referenced in `com.guardrailshq.grdr.*` plists and XPC Team-ID predicates).
- `[EXT]` **Endpoint Security Entitlement Approval (`com.apple.developer.endpoint-security.client`):** Deploying `EndpointSecurityExtension` and `es_new_descendants_client` on SIP-enabled customer Macs requires Apple's manual per-bundle-ID entitlement approval (`com.apple.developer.endpoint-security.client` in provisioning profile). Until granted, builds targeting SIP-off lab guests use `GRDR_MACOS_ES=1`.
- `[EXT]` **macOS Xcode/Swift Toolchain Build:** Building and signing the Xcode/SwiftPM `.app` and `.systemextension` bundles requires macOS (`Xcode 16+` / Swift 6 SDK) with `cargo build --release -p grdr-sensor-macos` built first to produce `target/release/libgrdr_sensor_macos.a`.

## Build Steps on macOS

```bash
cargo build --release -p grdr-sensor-macos
swift build --package-path platform/macos -Xlinker -L../../target/release
```
