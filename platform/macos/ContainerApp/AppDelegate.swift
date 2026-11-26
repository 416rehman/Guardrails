// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors

#if os(macOS)
import AppKit
import Foundation
import NetworkExtension
import SystemExtensions
import GrdrSensorMacOSBridge

@MainActor
public final class GrdrContainerAppDelegate: NSObject, NSApplicationDelegate, OSSystemExtensionRequestDelegate {
    private static let networkExtensionId = "com.guardrailshq.grdr.network-extension"
    private static let endpointSecurityExtensionId = "com.guardrailshq.grdr.endpoint-security"

    public func applicationDidFinishLaunching(_ notification: Notification) {
        let abiVersion = grdr_macos_abi_version()
        if abiVersion == 0 {
            return
        }
        activateSystemExtension(identifier: Self.networkExtensionId)
        activateSystemExtension(identifier: Self.endpointSecurityExtensionId)
    }

    public func activateSystemExtension(identifier: String) {
        let request = OSSystemExtensionRequest.activationRequest(
            forExtensionWithIdentifier: identifier,
            queue: .main
        )
        request.delegate = self
        OSSystemExtensionManager.shared.submitRequest(request)
    }

    public func configureContentFilter(
        providerBundleId: String = GrdrContainerAppDelegate.networkExtensionId,
        completion: @escaping (Error?) -> Void
    ) {
        NEFilterManager.shared().loadFromPreferences { loadError in
            if let loadError = loadError {
                completion(loadError)
                return
            }
            let cfg = NEFilterProviderConfiguration()
            cfg.filterSockets = true
            cfg.filterPackets = false
            cfg.filterDataProviderBundleIdentifier = providerBundleId
            cfg.organization = "Guardrails ADR"
            NEFilterManager.shared().providerConfiguration = cfg
            NEFilterManager.shared().grade = .inspector
            NEFilterManager.shared().isEnabled = true
            NEFilterManager.shared().saveToPreferences(completionHandler: completion)
        }
    }

    public func probeCapabilitiesJson() -> String {
        guard let rawPtr = grdr_macos_probe_capabilities() else {
            return "{}"
        }
        defer { grdr_macos_free_string(rawPtr) }
        return String(cString: rawPtr)
    }

    public func request(
        _ request: OSSystemExtensionRequest,
        actionForReplacingExtension existing: OSSystemExtensionProperties,
        withExtension ext: OSSystemExtensionProperties
    ) -> OSSystemExtensionRequest.ReplacementAction {
        return .replace
    }

    public func requestNeedsUserApproval(_ request: OSSystemExtensionRequest) {
    }

    public func request(
        _ request: OSSystemExtensionRequest,
        didFinishWithResult result: OSSystemExtensionRequest.Result
    ) {
    }

    public func request(
        _ request: OSSystemExtensionRequest,
        didFailWithError error: Error
    ) {
    }
}
#endif
