# macOS Native Container App, Network Extension & Endpoint Security (`platform/macos/`)

This directory scaffolds the macOS System Extensions and Container App wrapping the `grdr-sensor-macos` Rust static library (`libgrdr_sensor_macos.a`) over its `catch_unwind`-guarded fixed `#[repr(C)]` ABI (`Bridge/GrdrSensorMacOS.h`).

## Layout

- `Bridge/`: `GrdrSensorMacOS.h` + `module.modulemap` exposing `grdr_macos_*` fixed C-ABI structs and entry points from `crates/grdr-sensor-macos`.
- `ContainerApp/`: `com.guardrailshq.grdr` menu-bar / activation host invoking `OSSystemExtensionRequest` to activate the Network Extension and Endpoint Security system extensions.
- `NetworkExtension/`: `com.guardrailshq.grdr.netext` (`NEFilterDataProvider` Inspector grade + TLS SNI peek + QUIC UDP/443 drop, opt-in `NEDNSProxyProvider` UDP/TCP resolver, opt-in `NETransparentProxyProvider` audit-token routed relay).
- `EndpointSecurityExtension/`: `com.guardrailshq.grdr.esext` (4 isolated `es_new_client` concerns with `ES_DEADLINE_MISS_MODE_FAIL_OPEN` and inverted muting, `es_new_descendants_client` supervisor for macOS 27+, and audit-token/Team-ID verified XPC daemon bridge).

## External Blockers (`[EXT]`)

- `[EXT]` **Apple Developer Program Membership & Team ID (`DEVELOPMENT_TEAM`):** Activating a System Extension (`OSSystemExtensionRequest`), code-signing `.app`/`.appex`/`.systemextension` bundles, notarizing `.pkg` installers, and using `NetworkExtension` entitlements (`com.apple.developer.networking.networkextension`) require an enrolled paid Apple Developer Program account and organization Team ID (aligned with `contracts/interface/brand/brand.toml` `com.guardrailshq.grdr.*`).
- `[EXT]` **Endpoint Security Entitlement Approval (`com.apple.developer.endpoint-security.client`):** Deploying `EndpointSecurityExtension` and `es_new_descendants_client` on SIP-enabled customer Macs requires Apple's manual per-bundle-ID entitlement approval (`com.apple.developer.endpoint-security.client` in provisioning profile). Until granted, builds targeting SIP-off lab guests use `GRDR_MACOS_ES=1`.
- `[EXT]` **macOS Xcode/Swift Toolchain Build:** Building and signing the Xcode/SwiftPM `.app` and `.systemextension` bundles requires macOS (`Xcode 16+` / Swift 6 SDK) with `cargo build --release -p grdr-sensor-macos` built first to produce `target/release/libgrdr_sensor_macos.a`.

## Build Steps on macOS

```bash
cargo build --release -p grdr-sensor-macos
swift build --package-path platform/macos -Xlinker -L../../target/release
```
