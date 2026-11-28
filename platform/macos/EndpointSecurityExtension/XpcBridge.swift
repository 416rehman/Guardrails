// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors

#if os(macOS)
import Darwin.bsm
import Foundation
import GrdrSensorMacOSBridge

@objc public protocol GrdrSensorXpcProtocol {
    func ping(reply: @escaping @Sendable (Bool) -> Void)
    func fetchAbiVersion(reply: @escaping @Sendable (UInt32) -> Void)
    func fetchEsClientStatuses(reply: @escaping @Sendable ([String: String]) -> Void)
    func fetchPolicySnapshot(reply: @escaping @Sendable (Data, UInt64, Bool, UInt16, [String], String, [Data]) -> Void)
    func lookupAuditToken(pid: UInt32, pidversion: UInt32, reply: @escaping @Sendable (Bool, String, String) -> Void)
    func pushBinaryFloorTable(floorBin: Data, epoch: UInt64, defaultDeny: Bool, reply: @escaping @Sendable (Bool, UInt64) -> Void)
    func pushProxyConfig(loopbackPort: UInt16, modelHostSuffixes: [String], proxyToken: String, reply: @escaping @Sendable (Bool) -> Void)
    func registerAgentRoot(pid: UInt32, pidversion: UInt32, uid: UInt32, sessionId: String, agentName: String, reply: @escaping @Sendable (Bool) -> Void)
    func registerSelfPid(pid: UInt32, reply: @escaping @Sendable (Bool) -> Void)
    func addProtectedPath(path: String, reply: @escaping @Sendable (Bool) -> Void)
    func addSelfPath(path: String, reply: @escaping @Sendable (Bool) -> Void)
    func muteIncumbentTeam(teamId: String, reply: @escaping @Sendable (Bool) -> Void)
    func drainTelemetry(maxEvents: UInt32, reply: @escaping @Sendable ([Data]) -> Void)
}

@objc public protocol GrdrNeXpcSyncProtocol {
    func pushPolicySnapshot(floorBin: Data, epoch: UInt64, defaultDeny: Bool, loopbackPort: UInt16, modelHostSuffixes: [String], proxyToken: String, reply: @escaping @Sendable (Bool) -> Void)
    func applyTreeDeltas(recordsBin: [Data], reply: @escaping @Sendable (Bool) -> Void)
}

public final class GrdrSensorXpcListener: NSObject, NSXPCListenerDelegate, GrdrSensorXpcProtocol, @unchecked Sendable {
    private let listener: NSXPCListener
    private let expectedTeamId: String
    private let allowedSigningIds: [String]
    private weak var coordinator: GrdrEsTreeCoordinator?

    public init(machServiceName: String, expectedTeamId: String, coordinator: GrdrEsTreeCoordinator? = nil) {
        self.listener = NSXPCListener(machServiceName: machServiceName)
        self.expectedTeamId = expectedTeamId
        self.allowedSigningIds = Self.loadAllowedSigningIdentifiers()
        self.coordinator = coordinator
        super.init()
        self.listener.delegate = self
    }

    public func attachCoordinator(_ coordinator: GrdrEsTreeCoordinator) {
        self.coordinator = coordinator
    }

    public func resume() {
        listener.resume()
    }

    public func listener(
        _ listener: NSXPCListener,
        shouldAcceptNewConnection newConnection: NSXPCConnection
    ) -> Bool {
        guard let requirement = Self.buildExactPeerRequirement(
            teamId: expectedTeamId,
            allowedIdentifiers: allowedSigningIds
        ) else {
            return false
        }
        let peerPid = audit_token_to_pid(newConnection.auditToken)
        guard peerPid > 0 && peerPid == newConnection.processIdentifier else {
            return false
        }
        newConnection.setCodeSigningRequirement(requirement)
        newConnection.exportedInterface = NSXPCInterface(with: GrdrSensorXpcProtocol.self)
        newConnection.exportedObject = self
        newConnection.resume()
        return true
    }

    public func ping(reply: @escaping @Sendable (Bool) -> Void) {
        reply(true)
    }

    public func fetchAbiVersion(reply: @escaping @Sendable (UInt32) -> Void) {
        reply(grdr_macos_abi_version())
    }

    public func fetchEsClientStatuses(reply: @escaping @Sendable ([String: String]) -> Void) {
        reply(coordinator?.currentStatuses() ?? [:])
    }

    public func fetchPolicySnapshot(reply: @escaping @Sendable (Data, UInt64, Bool, UInt16, [String], String, [Data]) -> Void) {
        guard let snap = coordinator?.currentPolicySnapshot() else {
            reply(Data(), 0, true, 0, [], "", [])
            return
        }
        reply(
            snap.floorBin,
            snap.epoch,
            snap.defaultDeny,
            snap.proxyPort,
            snap.modelHostSuffixes,
            snap.proxyToken,
            snap.treeDeltas
        )
    }

    public func lookupAuditToken(
        pid: UInt32,
        pidversion: UInt32,
        reply: @escaping @Sendable (Bool, String, String) -> Void
    ) {
        guard let hit = coordinator?.lookupAuditToken(pid: pid, pidversion: pidversion) else {
            reply(false, "", "")
            return
        }
        reply(hit.governed, hit.sessionId, hit.agentName)
    }

    public func pushBinaryFloorTable(
        floorBin: Data,
        epoch: UInt64,
        defaultDeny: Bool,
        reply: @escaping @Sendable (Bool, UInt64) -> Void
    ) {
        guard let coord = coordinator else {
            reply(false, 0)
            return
        }
        let appliedEpoch = coord.swapBinaryFloorTable(data: floorBin, epoch: epoch, defaultDeny: defaultDeny)
        reply(true, appliedEpoch)
    }

    public func pushProxyConfig(
        loopbackPort: UInt16,
        modelHostSuffixes: [String],
        proxyToken: String,
        reply: @escaping @Sendable (Bool) -> Void
    ) {
        guard let coord = coordinator else {
            reply(false)
            return
        }
        coord.configureProxy(
            loopbackPort: loopbackPort,
            modelHostSuffixes: modelHostSuffixes,
            proxyToken: proxyToken
        )
        reply(true)
    }

    public func registerAgentRoot(
        pid: UInt32,
        pidversion: UInt32,
        uid: UInt32,
        sessionId: String,
        agentName: String,
        reply: @escaping @Sendable (Bool) -> Void
    ) {
        let ok = coordinator?.registerAgentRoot(
            pid: pid,
            pidversion: pidversion,
            uid: uid,
            sessionId: sessionId,
            agentName: agentName
        ) ?? false
        reply(ok)
    }

    public func registerSelfPid(pid: UInt32, reply: @escaping @Sendable (Bool) -> Void) {
        reply(coordinator?.registerSelfPid(pid) ?? false)
    }

    public func addProtectedPath(path: String, reply: @escaping @Sendable (Bool) -> Void) {
        reply(coordinator?.addProtectedPath(path) ?? false)
    }

    public func addSelfPath(path: String, reply: @escaping @Sendable (Bool) -> Void) {
        reply(coordinator?.addSelfPath(path) ?? false)
    }

    public func muteIncumbentTeam(teamId: String, reply: @escaping @Sendable (Bool) -> Void) {
        reply(coordinator?.muteIncumbentTeam(teamId) ?? false)
    }

    public func drainTelemetry(maxEvents: UInt32, reply: @escaping @Sendable ([Data]) -> Void) {
        reply(coordinator?.drainTelemetry(maxEvents: Int(maxEvents)) ?? [])
    }

    public static func buildExactPeerRequirement(
        teamId: String,
        allowedIdentifiers: [String]
    ) -> String? {
        guard isValidAppleTeamId(teamId) else {
            return nil
        }
        let cleanIds = allowedIdentifiers.filter { isSafeSigningIdentifier($0) }
        guard !cleanIds.isEmpty else {
            return nil
        }
        let idClauses = cleanIds.map { "identifier = \"\($0)\"" }.joined(separator: " or ")
        return "anchor apple generic and (\(idClauses)) and certificate leaf[subject.OU] = \"\(teamId)\""
    }

    public static func isValidAppleTeamId(_ teamId: String) -> Bool {
        return teamId.range(of: "^[A-Z0-9]{10}$", options: .regularExpression) != nil
    }

    public static func isSafeSigningIdentifier(_ identifier: String) -> Bool {
        return !identifier.isEmpty
            && identifier.range(of: "^[A-Za-z0-9.-]+$", options: .regularExpression) != nil
    }

    public static func loadAllowedSigningIdentifiers() -> [String] {
        var brand = GrdrMacBrandInfoC()
        guard grdr_macos_get_brand_info(&brand) == GRDR_MAC_FFI_OK.rawValue else {
            return []
        }
        let ids = [
            decodeFixedUtf8(brand.bundle_id, len: brand.bundle_id_len),
            decodeFixedUtf8(brand.netext_bundle_id, len: brand.netext_bundle_id_len),
            decodeFixedUtf8(brand.esext_bundle_id, len: brand.esext_bundle_id_len),
            decodeFixedUtf8(brand.daemon_label, len: brand.daemon_label_len)
        ].filter { isSafeSigningIdentifier($0) }
        return Array(Set(ids)).sorted()
    }

    private static func decodeFixedUtf8<T>(_ tuple: T, len: UInt16) -> String {
        return withUnsafeBytes(of: tuple) { raw in
            let count = min(Int(len), raw.count)
            return String(decoding: raw.prefix(count), as: UTF8.self)
        }
    }
}

public final class GrdrEsToNeForwarder: @unchecked Sendable {
    private let netextMachService: String
    private let expectedTeamId: String
    private let allowedIds: [String]
    private let lock = NSLock()
    private var connection: NSXPCConnection?

    public init(expectedTeamId: String) {
        self.expectedTeamId = expectedTeamId
        self.allowedIds = GrdrSensorXpcListener.loadAllowedSigningIdentifiers()
        var brand = GrdrMacBrandInfoC()
        if grdr_macos_get_brand_info(&brand) == GRDR_MAC_FFI_OK.rawValue {
            self.netextMachService = withUnsafeBytes(of: brand.netext_bundle_id) { raw in
                String(decoding: raw.prefix(Int(brand.netext_bundle_id_len)), as: UTF8.self)
            }
        } else {
            self.netextMachService = ""
        }
    }

    public func pushPolicySnapshot(
        floorBin: Data,
        epoch: UInt64,
        defaultDeny: Bool,
        loopbackPort: UInt16,
        modelHostSuffixes: [String],
        proxyToken: String
    ) {
        guard let proxy = remoteProxy() else {
            return
        }
        proxy.pushPolicySnapshot(
            floorBin: floorBin,
            epoch: epoch,
            defaultDeny: defaultDeny,
            loopbackPort: loopbackPort,
            modelHostSuffixes: modelHostSuffixes,
            proxyToken: proxyToken
        ) { _ in }
    }

    public func pushTreeDelta(_ record: Data) {
        guard !record.isEmpty, let proxy = remoteProxy() else {
            return
        }
        proxy.applyTreeDeltas(recordsBin: [record]) { _ in }
    }

    private func remoteProxy() -> GrdrNeXpcSyncProtocol? {
        guard !netextMachService.isEmpty,
              let requirement = GrdrSensorXpcListener.buildExactPeerRequirement(
                  teamId: expectedTeamId,
                  allowedIdentifiers: allowedIds
              )
        else {
            return nil
        }
        lock.lock()
        defer { lock.unlock() }
        if connection == nil {
            let conn = NSXPCConnection(machServiceName: netextMachService, options: .privileged)
            conn.remoteObjectInterface = NSXPCInterface(with: GrdrNeXpcSyncProtocol.self)
            conn.setCodeSigningRequirement(requirement)
            conn.invalidationHandler = { [weak self] in
                self?.lock.lock()
                self?.connection = nil
                self?.lock.unlock()
            }
            conn.resume()
            connection = conn
        }
        return connection?.remoteObjectProxyWithErrorHandler { _ in } as? GrdrNeXpcSyncProtocol
    }
}
#endif
