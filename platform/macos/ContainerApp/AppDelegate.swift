// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors

#if os(macOS)
import AppKit
import Foundation
import NetworkExtension
import SystemExtensions
import GrdrSensorMacOSBridge

public enum GrdrExtensionActivationState: Equatable, Sendable {
    case idle
    case submitting
    case needsUserApproval
    case replacing
    case active
    case requiresReboot
    case failed(String)
}

public struct GrdrBrandRuntimeInfo: Sendable {
    public let bundleId: String
    public let ownPrefix: String
    public let networkExtensionId: String
    public let endpointSecurityExtensionId: String
    public let productName: String
    public let daemonLabel: String
    public let appGroupId: String

    public static func load() -> GrdrBrandRuntimeInfo? {
        var raw = GrdrMacBrandInfoC()
        guard grdr_macos_get_brand_info(&raw) == GRDR_MAC_FFI_OK.rawValue else {
            return nil
        }
        return GrdrBrandRuntimeInfo(
            bundleId: decodeFixedUtf8(raw.bundle_id, len: raw.bundle_id_len),
            ownPrefix: decodeFixedUtf8(raw.own_prefix, len: raw.own_prefix_len),
            networkExtensionId: decodeFixedUtf8(raw.netext_bundle_id, len: raw.netext_bundle_id_len),
            endpointSecurityExtensionId: decodeFixedUtf8(raw.esext_bundle_id, len: raw.esext_bundle_id_len),
            productName: decodeFixedUtf8(raw.product_name, len: raw.product_name_len),
            daemonLabel: decodeFixedUtf8(raw.daemon_label, len: raw.daemon_label_len),
            appGroupId: decodeFixedUtf8(raw.app_group_id, len: raw.app_group_id_len)
        )
    }

    private static func decodeFixedUtf8<T>(_ tuple: T, len: UInt16) -> String {
        return withUnsafeBytes(of: tuple) { buf in
            let count = min(Int(len), buf.count)
            return String(decoding: buf.prefix(count), as: UTF8.self)
        }
    }
}

@MainActor
public final class GrdrContainerAppDelegate: NSObject, NSApplicationDelegate, OSSystemExtensionRequestDelegate {
    private let brand: GrdrBrandRuntimeInfo? = GrdrBrandRuntimeInfo.load()
    private var activationStates: [String: GrdrExtensionActivationState] = [:]
    public var onActivationStateChanged: ((String, GrdrExtensionActivationState) -> Void)?
    public var onUserApprovalRequired: ((String, URL?) -> Void)?

    public func applicationDidFinishLaunching(_ notification: Notification) {
        guard grdr_macos_abi_version() != 0, let brand = brand else {
            return
        }
        let caps = probeCapabilities()
        guard caps.developer_program_held != 0 else {
            if !brand.networkExtensionId.isEmpty {
                updateState(
                    identifier: brand.networkExtensionId,
                    state: .failed("Apple Developer Program signing required for Network Extension")
                )
            }
            if !brand.endpointSecurityExtensionId.isEmpty {
                updateState(
                    identifier: brand.endpointSecurityExtensionId,
                    state: .failed("Apple Developer Program signing required for Endpoint Security")
                )
            }
            return
        }

        if !brand.networkExtensionId.isEmpty {
            activateSystemExtension(identifier: brand.networkExtensionId)
        }
        if !brand.endpointSecurityExtensionId.isEmpty,
           (caps.es_status_code != 1 || caps.own_extension_count > 0) {
            activateSystemExtension(identifier: brand.endpointSecurityExtensionId)
        } else if !brand.endpointSecurityExtensionId.isEmpty {
            updateState(
                identifier: brand.endpointSecurityExtensionId,
                state: .failed("Endpoint Security entitlement not provisioned")
            )
        }
    }

    public func currentActivationState(for identifier: String) -> GrdrExtensionActivationState {
        return activationStates[identifier] ?? .idle
    }

    public func activateSystemExtension(identifier: String) {
        guard !identifier.isEmpty else {
            return
        }
        updateState(identifier: identifier, state: .submitting)
        let request = OSSystemExtensionRequest.activationRequest(
            forExtensionWithIdentifier: identifier,
            queue: .main
        )
        request.delegate = self
        OSSystemExtensionManager.shared.submitRequest(request)
    }

    public func deactivateSystemExtension(identifier: String) {
        guard !identifier.isEmpty else {
            return
        }
        let request = OSSystemExtensionRequest.deactivationRequest(
            forExtensionWithIdentifier: identifier,
            queue: .main
        )
        request.delegate = self
        OSSystemExtensionManager.shared.submitRequest(request)
    }

    public func configureContentFilter(
        providerBundleId: String? = nil,
        completion: @escaping @Sendable (Error?) -> Void
    ) {
        guard let brand = brand else {
            completion(NSError(domain: Bundle.main.bundleIdentifier ?? "grdr", code: -1))
            return
        }
        let targetBundleId = providerBundleId ?? brand.networkExtensionId
        guard !targetBundleId.isEmpty else {
            completion(NSError(domain: brand.ownPrefix, code: -2))
            return
        }
        NEFilterManager.shared().loadFromPreferences { loadError in
            if let loadError = loadError {
                completion(loadError)
                return
            }
            let cfg = NEFilterProviderConfiguration()
            cfg.filterSockets = true
            cfg.filterPackets = false
            cfg.filterDataProviderBundleIdentifier = targetBundleId
            cfg.organization = brand.productName
            NEFilterManager.shared().providerConfiguration = cfg
            NEFilterManager.shared().grade = .inspector
            NEFilterManager.shared().isEnabled = true
            NEFilterManager.shared().saveToPreferences(completionHandler: completion)
        }
    }

    public func probeCapabilities() -> GrdrMacCapabilitiesC {
        var caps = GrdrMacCapabilitiesC()
        _ = grdr_macos_probe_capabilities_c(&caps)
        return caps
    }

    public func request(
        _ request: OSSystemExtensionRequest,
        actionForReplacingExtension existing: OSSystemExtensionProperties,
        withExtension ext: OSSystemExtensionProperties
    ) -> OSSystemExtensionRequest.ReplacementAction {
        if existing.bundleShortVersion == ext.bundleShortVersion,
           existing.bundleVersion == ext.bundleVersion {
            updateState(identifier: request.identifier, state: .active)
            return .cancel
        }
        updateState(identifier: request.identifier, state: .replacing)
        return .replace
    }

    public func requestNeedsUserApproval(_ request: OSSystemExtensionRequest) {
        updateState(identifier: request.identifier, state: .needsUserApproval)
        let settingsUrl = URL(string: "x-apple.systempreferences:com.apple.LoginItems-Settings.extension")
        onUserApprovalRequired?(request.identifier, settingsUrl)
        if let url = settingsUrl {
            NSWorkspace.shared.open(url)
        }
    }

    public func request(
        _ request: OSSystemExtensionRequest,
        didFinishWithResult result: OSSystemExtensionRequest.Result
    ) {
        switch result {
        case .completed:
            updateState(identifier: request.identifier, state: .active)
            if request.identifier == brand?.networkExtensionId {
                configureContentFilter(providerBundleId: request.identifier) { _ in }
            }
        case .willCompleteAfterReboot:
            updateState(identifier: request.identifier, state: .requiresReboot)
        @unknown default:
            updateState(identifier: request.identifier, state: .active)
        }
    }

    public func request(
        _ request: OSSystemExtensionRequest,
        didFailWithError error: Error
    ) {
        let message = error.localizedDescription
        updateState(identifier: request.identifier, state: .failed(message))
    }

    private func updateState(identifier: String, state: GrdrExtensionActivationState) {
        activationStates[identifier] = state
        onActivationStateChanged?(identifier, state)
    }
}
#endif
