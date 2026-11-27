// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors

#if os(macOS)
import Dispatch
import EndpointSecurity
import Foundation
import GrdrSensorMacOSBridge

public enum GrdrEsExtensionBootstrap {
    private static let lock = NSLock()
    private nonisolated(unsafe) static var activeCoordinator: GrdrEsTreeCoordinator?
    private nonisolated(unsafe) static var activeXpcListener: GrdrSensorXpcListener?
    private nonisolated(unsafe) static var activeNeForwarder: GrdrEsToNeForwarder?

    public static func start(mutedTeamIds: [String], expectedTeamId: String = "") -> Int32 {
        let selfInfo = resolveSelfSigningInfo()
        let teamToPin = expectedTeamId.isEmpty ? selfInfo.teamId : expectedTeamId
        guard GrdrSensorXpcListener.isValidAppleTeamId(teamToPin) else {
            return -1
        }
        let machService = defaultMachServiceName()
        guard !machService.isEmpty else {
            return -1
        }

        lock.lock()
        defer { lock.unlock() }
        activeCoordinator?.stop()

        let coordinator = GrdrEsTreeCoordinator()
        let forwarder = GrdrEsToNeForwarder(expectedTeamId: teamToPin)
        coordinator.onPolicyUpdated = { floorBin, epoch, defaultDeny, port, suffixes, token in
            forwarder.pushPolicySnapshot(
                floorBin: floorBin,
                epoch: epoch,
                defaultDeny: defaultDeny,
                loopbackPort: port,
                modelHostSuffixes: suffixes,
                proxyToken: token
            )
        }
        coordinator.onTreeDeltaEmitted = { delta in
            forwarder.pushTreeDelta(delta)
        }

        let result = coordinator.startClients(mutedTeamIds: mutedTeamIds)
        if result == ES_NEW_CLIENT_RESULT_SUCCESS {
            let listener = GrdrSensorXpcListener(
                machServiceName: machService,
                expectedTeamId: teamToPin,
                coordinator: coordinator
            )
            listener.resume()
            activeCoordinator = coordinator
            activeXpcListener = listener
            activeNeForwarder = forwarder
            return 0
        }

        coordinator.stop()
        activeCoordinator = nil
        activeXpcListener = nil
        activeNeForwarder = nil
        return -1
    }

    public static func runMain(mutedTeamIds: [String] = [], expectedTeamId: String = "") -> Never {
        let rc = start(mutedTeamIds: mutedTeamIds, expectedTeamId: expectedTeamId)
        if rc != 0 {
            exit(EXIT_FAILURE)
        }
        dispatchMain()
    }

    public static func stop() {
        lock.lock()
        defer { lock.unlock() }
        activeCoordinator?.stop()
        activeCoordinator = nil
        activeXpcListener = nil
        activeNeForwarder = nil
    }

    public static func resolveSelfSigningInfo() -> (teamId: String, esEntitled: Bool) {
        var teamBuf = [UInt8](repeating: 0, count: 64)
        var teamLen: Int = 0
        var esEntitled: UInt8 = 0
        let rc = teamBuf.withUnsafeMutableBufferPointer { ptr in
            grdr_macos_self_signing_info_c(ptr.baseAddress, ptr.count, &teamLen, &esEntitled)
        }
        guard rc == GRDR_MAC_FFI_OK.rawValue else {
            return ("", false)
        }
        let team = String(decoding: teamBuf.prefix(min(teamLen, teamBuf.count)), as: UTF8.self)
        return (team, esEntitled != 0)
    }

    private static func defaultMachServiceName() -> String {
        var brand = GrdrMacBrandInfoC()
        guard grdr_macos_get_brand_info(&brand) == GRDR_MAC_FFI_OK.rawValue else {
            return ""
        }
        return withUnsafeBytes(of: brand.esext_bundle_id) { raw in
            String(decoding: raw.prefix(Int(brand.esext_bundle_id_len)), as: UTF8.self)
        }
    }
}

#if GRDR_ES_EXECUTABLE
@main
enum GrdrEsSystemExtensionEntry {
    static func main() {
        GrdrEsExtensionBootstrap.runMain()
    }
}
#endif
#endif
