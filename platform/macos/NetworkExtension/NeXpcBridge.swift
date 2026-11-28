// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors

#if os(macOS)
import Darwin.bsm
import Foundation
import GrdrSensorMacOSBridge

@objc public protocol GrdrNeXpcSyncProtocol {
    func pushPolicySnapshot(floorBin: Data, epoch: UInt64, defaultDeny: Bool, loopbackPort: UInt16, modelHostSuffixes: [String], proxyToken: String, reply: @escaping @Sendable (Bool) -> Void)
    func applyTreeDeltas(recordsBin: [Data], reply: @escaping @Sendable (Bool) -> Void)
}

@objc public protocol GrdrEsPolicyClientProtocol {
    func fetchPolicySnapshot(reply: @escaping @Sendable (Data, UInt64, Bool, UInt16, [String], String, [Data]) -> Void)
}

public struct GrdrNePolicySnapshot: Sendable {
    public let floorTableBin: Data
    public let epoch: UInt64
    public let defaultDeny: UInt8
    public let loopbackProxyPort: UInt16
    public let modelHostSuffixes: [String]
    public let proxyAuthToken: String
}

public final class GrdrNeProviderHub: NSObject, NSXPCListenerDelegate, GrdrNeXpcSyncProtocol, @unchecked Sendable {
    public static let shared = GrdrNeProviderHub()
    private static let maxDomainCacheEntries: Int = 4_096

    private let lock = NSLock()
    private var sharedFollower: OpaquePointer?
    private var ownsFollower: Bool = false
    private var floorTableBin: Data = Data()
    private var floorEpoch: UInt64 = 0
    private var defaultDeny: UInt8 = 1
    private var loopbackProxyPort: UInt16 = 0
    private var modelHostSuffixes: [String] = []
    private var proxyAuthToken: String = ""
    private var upstreamDnsHost: String = "127.0.0.1"
    private var upstreamDnsPort: UInt16 = 53
    private var domainIpCache: [String: (domain: String, expiresAt: Date)] = [:]
    private var cacheOrder: [String] = []
    private var listener: NSXPCListener?
    private var esConnection: NSXPCConnection?

    public override init() {
        super.init()
        sharedFollower = grdr_macos_follower_new()
        ownsFollower = true
    }

    deinit {
        lock.lock()
        let owned = ownsFollower ? sharedFollower : nil
        sharedFollower = nil
        ownsFollower = false
        lock.unlock()
        if let f = owned {
            grdr_macos_follower_free(f)
        }
    }

    public func ensureSyncStarted(expectedTeamId: String = "") {
        let resolvedTeam = expectedTeamId.isEmpty ? Self.loadSelfTeamId() : expectedTeamId
        let allowed = Self.loadBrandIdentifiers()
        guard let requirement = Self.buildExactPeerRequirement(teamId: resolvedTeam, allowedIdentifiers: allowed) else {
            return
        }
        let brand = Self.loadBrandInfo()

        lock.lock()
        if listener == nil && !brand.netextId.isEmpty {
            let xpcListener = NSXPCListener(machServiceName: brand.netextId)
            xpcListener.delegate = self
            xpcListener.resume()
            listener = xpcListener
        }
        let shouldBootstrapEs = (esConnection == nil && !brand.esextId.isEmpty)
        lock.unlock()

        if shouldBootstrapEs {
            bootstrapFromEs(machServiceName: brand.esextId, requirement: requirement)
        }
    }

    public func attachFollower(_ follower: OpaquePointer?) {
        lock.lock()
        let oldOwned = ownsFollower ? sharedFollower : nil
        sharedFollower = follower
        ownsFollower = false
        lock.unlock()
        if let f = oldOwned {
            grdr_macos_follower_free(f)
        }
    }

    public func followerHandle() -> OpaquePointer? {
        lock.lock()
        defer { lock.unlock() }
        return sharedFollower
    }

    public func configureBinaryFloorPolicy(tableBin: Data, defaultDeny: Bool, epoch: UInt64 = 0) {
        lock.lock()
        floorTableBin = tableBin
        self.defaultDeny = defaultDeny ? 1 : 0
        if epoch > 0 {
            floorEpoch = epoch
        }
        lock.unlock()
    }

    public func configureProxy(loopbackPort: UInt16, modelHostSuffixes: [String], proxyToken: String? = nil) {
        let normalized = modelHostSuffixes
            .map { $0.lowercased().trimmingCharacters(in: CharacterSet(charactersIn: ".")) }
            .filter { !$0.isEmpty }
        lock.lock()
        loopbackProxyPort = loopbackPort
        self.modelHostSuffixes = normalized
        if let token = proxyToken {
            proxyAuthToken = token
        }
        lock.unlock()
    }

    public func configureUpstreamResolver(host: String, port: UInt16) {
        guard !host.isEmpty, port > 0 else {
            return
        }
        lock.lock()
        upstreamDnsHost = host
        upstreamDnsPort = port
        lock.unlock()
    }

    public func upstreamResolver() -> (host: String, port: UInt16) {
        lock.lock()
        defer { lock.unlock() }
        return (upstreamDnsHost, upstreamDnsPort)
    }

    public func policySnapshot() -> GrdrNePolicySnapshot {
        lock.lock()
        defer { lock.unlock() }
        return GrdrNePolicySnapshot(
            floorTableBin: floorTableBin,
            epoch: floorEpoch,
            defaultDeny: defaultDeny,
            loopbackProxyPort: loopbackProxyPort,
            modelHostSuffixes: modelHostSuffixes,
            proxyAuthToken: proxyAuthToken
        )
    }

    public func lookupLineage(auditTokenData: Data?) -> (governed: Bool, pid: UInt32, pidversion: UInt32, agentName: String) {
        guard let tokenData = auditTokenData,
              tokenData.count >= MemoryLayout<audit_token_t>.size
        else {
            return (false, 0, 0, "")
        }
        let token = tokenData.withUnsafeBytes { buf in
            buf.load(as: audit_token_t.self)
        }
        let pid = UInt32(max(0, audit_token_to_pid(token)))
        let pidver = UInt32(max(0, audit_token_to_pidversion(token)))
        lock.lock()
        let f = sharedFollower
        lock.unlock()
        guard let follower = f else {
            return (false, pid, pidver, "")
        }
        var out = GrdrMacTokenLookupOutC()
        let rc = grdr_macos_follower_lookup_token(follower, pid, pidver, &out)
        if rc != GRDR_MAC_FFI_OK.rawValue || out.governed == 0 {
            return (false, pid, pidver, "")
        }
        let agent = withUnsafeBytes(of: out.agent_name) { raw in
            String(decoding: raw.prefix(Int(out.agent_name_len)), as: UTF8.self)
        }
        return (true, pid, pidver, agent)
    }

    public func recordResolvedIps(_ ips: [String], domain: String, ttl: UInt32) {
        guard !domain.isEmpty, !ips.isEmpty else {
            return
        }
        let now = Date()
        let expiresAt = now.addingTimeInterval(TimeInterval(max(1, min(86_400, ttl))))
        lock.lock()
        pruneExpiredLocked(now: now)
        for ip in ips where !ip.isEmpty {
            if domainIpCache[ip] == nil {
                while domainIpCache.count >= Self.maxDomainCacheEntries, let oldest = cacheOrder.first {
                    cacheOrder.removeFirst()
                    domainIpCache.removeValue(forKey: oldest)
                }
                cacheOrder.append(ip)
            }
            domainIpCache[ip] = (domain: domain, expiresAt: expiresAt)
        }
        lock.unlock()
    }

    public func lookupCachedDomain(ipAddress: String) -> String? {
        guard !ipAddress.isEmpty else {
            return nil
        }
        let now = Date()
        lock.lock()
        defer { lock.unlock() }
        guard let entry = domainIpCache[ipAddress] else {
            return nil
        }
        if entry.expiresAt <= now {
            domainIpCache.removeValue(forKey: ipAddress)
            cacheOrder.removeAll { $0 == ipAddress }
            return nil
        }
        return entry.domain
    }

    public func clearDomainCache() {
        lock.lock()
        domainIpCache.removeAll()
        cacheOrder.removeAll()
        lock.unlock()
    }

    public func listener(_ listener: NSXPCListener, shouldAcceptNewConnection newConnection: NSXPCConnection) -> Bool {
        let team = Self.loadSelfTeamId()
        let allowed = Self.loadBrandIdentifiers()
        guard let requirement = Self.buildExactPeerRequirement(teamId: team, allowedIdentifiers: allowed) else {
            return false
        }
        let peerPid = audit_token_to_pid(newConnection.auditToken)
        guard peerPid > 0 && peerPid == newConnection.processIdentifier else {
            return false
        }
        newConnection.setCodeSigningRequirement(requirement)
        newConnection.exportedInterface = NSXPCInterface(with: GrdrNeXpcSyncProtocol.self)
        newConnection.exportedObject = self
        newConnection.resume()
        return true
    }

    public func pushPolicySnapshot(
        floorBin: Data,
        epoch: UInt64,
        defaultDeny: Bool,
        loopbackPort: UInt16,
        modelHostSuffixes: [String],
        proxyToken: String,
        reply: @escaping @Sendable (Bool) -> Void
    ) {
        configureBinaryFloorPolicy(tableBin: floorBin, defaultDeny: defaultDeny, epoch: epoch)
        configureProxy(
            loopbackPort: loopbackPort,
            modelHostSuffixes: modelHostSuffixes,
            proxyToken: proxyToken.isEmpty ? nil : proxyToken
        )
        reply(true)
    }

    public func applyTreeDeltas(recordsBin: [Data], reply: @escaping @Sendable (Bool) -> Void) {
        lock.lock()
        let follower = sharedFollower
        lock.unlock()
        guard let f = follower else {
            reply(false)
            return
        }
        for rec in recordsBin {
            applySingleTreeDelta(rec, follower: f)
        }
        reply(true)
    }

    private func bootstrapFromEs(machServiceName: String, requirement: String) {
        let conn = NSXPCConnection(machServiceName: machServiceName, options: .privileged)
        conn.remoteObjectInterface = NSXPCInterface(with: GrdrEsPolicyClientProtocol.self)
        conn.setCodeSigningRequirement(requirement)
        conn.invalidationHandler = { [weak self] in
            self?.lock.lock()
            self?.esConnection = nil
            self?.lock.unlock()
        }
        lock.lock()
        esConnection = conn
        lock.unlock()
        conn.resume()
        if let proxy = conn.remoteObjectProxyWithErrorHandler({ _ in }) as? GrdrEsPolicyClientProtocol {
            proxy.fetchPolicySnapshot { [weak self] bin, epoch, deny, port, suffixes, token, treeDeltas in
                guard let self = self else {
                    return
                }
                self.configureBinaryFloorPolicy(tableBin: bin, defaultDeny: deny, epoch: epoch)
                self.configureProxy(
                    loopbackPort: port,
                    modelHostSuffixes: suffixes,
                    proxyToken: token.isEmpty ? nil : token
                )
                if !treeDeltas.isEmpty {
                    self.applyTreeDeltas(recordsBin: treeDeltas) { _ in }
                }
            }
        }
    }

    private func pruneExpiredLocked(now: Date) {
        var expiredKeys: [String] = []
        for (ip, entry) in domainIpCache where entry.expiresAt <= now {
            expiredKeys.append(ip)
        }
        guard !expiredKeys.isEmpty else {
            return
        }
        let expiredSet = Set(expiredKeys)
        for key in expiredKeys {
            domainIpCache.removeValue(forKey: key)
        }
        cacheOrder.removeAll { expiredSet.contains($0) }
    }

    private func applySingleTreeDelta(_ rawData: Data, follower: OpaquePointer) {
        let data = Data(rawData)
        // Header: ['T', version(1), kind(1), 0] + 6x UInt32 + 3x UInt16 = 34 bytes
        guard data.count >= 34, data[0] == 0x54, data[1] == 1 else {
            return
        }
        let kindCode = data[2]
        let validKinds: Set<UInt8> = [
            UInt8(GRDR_MAC_ES_REGISTER_ROOT.rawValue),
            UInt8(GRDR_MAC_ES_NOTIFY_FORK.rawValue),
            UInt8(GRDR_MAC_ES_AUTH_EXEC.rawValue),
            UInt8(GRDR_MAC_ES_NOTIFY_EXEC.rawValue),
            UInt8(GRDR_MAC_ES_NOTIFY_EXIT.rawValue)
        ]
        guard validKinds.contains(kindCode) else {
            return
        }
        let actorPid = readU32(data, offset: 4)
        let actorPidver = readU32(data, offset: 8)
        let actorUid = readU32(data, offset: 12)
        let targetPid = readU32(data, offset: 16)
        let targetPidver = readU32(data, offset: 20)
        let targetUid = readU32(data, offset: 24)
        let sidLen = Int(readU16(data, offset: 28))
        let agentLen = Int(readU16(data, offset: 30))
        let pathLen = Int(readU16(data, offset: 32))
        guard 34 + sidLen + agentLen + pathLen <= data.count else {
            return
        }
        let sidData = data.subdata(in: 34..<(34 + sidLen))
        let agentData = data.subdata(in: (34 + sidLen)..<(34 + sidLen + agentLen))
        let pathData = data.subdata(in: (34 + sidLen + agentLen)..<(34 + sidLen + agentLen + pathLen))

        var out = GrdrMacEsVerdictC()
        _ = sidData.withUnsafeBytes { sidBuf in
            agentData.withUnsafeBytes { agentBuf in
                pathData.withUnsafeBytes { pathBuf in
                    var ev = GrdrMacEsEventC(
                        kind_code: kindCode,
                        concern_code: UInt8(GRDR_MAC_ES_CONCERN_EXEC_AUTHORIZER.rawValue),
                        default_deny: 0,
                        reserved0: 0,
                        access_flags: 0,
                        event_flags: 0,
                        reserved1: 0,
                        seq_num: 1,
                        timestamp_ns: 0,
                        elapsed_ms: 0,
                        kernel_deadline_ms: 10_000,
                        actor: GrdrMacAuditTokenC(
                            key: GrdrMacProcessKeyC(pid: actorPid, pidversion: actorPidver),
                            uid: actorUid,
                            reserved: 0,
                            team_id_ptr: nil,
                            team_id_len: 0
                        ),
                        target: GrdrMacAuditTokenC(
                            key: GrdrMacProcessKeyC(pid: targetPid, pidversion: targetPidver),
                            uid: targetUid,
                            reserved: 0,
                            team_id_ptr: nil,
                            team_id_len: 0
                        ),
                        path_ptr: pathBuf.bindMemory(to: UInt8.self).baseAddress,
                        path_len: pathBuf.count,
                        secondary_path_ptr: nil,
                        secondary_path_len: 0,
                        session_id_ptr: sidBuf.bindMemory(to: UInt8.self).baseAddress,
                        session_id_len: sidBuf.count,
                        agent_name_ptr: agentBuf.bindMemory(to: UInt8.self).baseAddress,
                        agent_name_len: agentBuf.count
                    )
                    return grdr_macos_eval_es_event_c(follower, &ev, nil, 0, &out)
                }
            }
        }
    }

    private func readU32(_ data: Data, offset: Int) -> UInt32 {
        var val: UInt32 = 0
        _ = withUnsafeMutableBytes(of: &val) { dst in
            data.copyBytes(to: dst, from: offset..<(offset + 4))
        }
        return UInt32(littleEndian: val)
    }

    private func readU16(_ data: Data, offset: Int) -> UInt16 {
        var val: UInt16 = 0
        _ = withUnsafeMutableBytes(of: &val) { dst in
            data.copyBytes(to: dst, from: offset..<(offset + 2))
        }
        return UInt16(littleEndian: val)
    }

    private static func loadSelfTeamId() -> String {
        var teamBuf = [UInt8](repeating: 0, count: 64)
        var teamLen: Int = 0
        var esEnt: UInt8 = 0
        let rc = teamBuf.withUnsafeMutableBufferPointer { ptr in
            grdr_macos_self_signing_info_c(ptr.baseAddress, ptr.count, &teamLen, &esEnt)
        }
        guard rc == GRDR_MAC_FFI_OK.rawValue else {
            return ""
        }
        return String(decoding: teamBuf.prefix(min(teamLen, teamBuf.count)), as: UTF8.self)
    }

    private static func loadBrandInfo() -> (bundleId: String, netextId: String, esextId: String, daemonLabel: String) {
        var brand = GrdrMacBrandInfoC()
        guard grdr_macos_get_brand_info(&brand) == GRDR_MAC_FFI_OK.rawValue else {
            return ("", "", "", "")
        }
        return (
            decodeFixedUtf8(brand.bundle_id, len: brand.bundle_id_len),
            decodeFixedUtf8(brand.netext_bundle_id, len: brand.netext_bundle_id_len),
            decodeFixedUtf8(brand.esext_bundle_id, len: brand.esext_bundle_id_len),
            decodeFixedUtf8(brand.daemon_label, len: brand.daemon_label_len)
        )
    }

    private static func loadBrandIdentifiers() -> [String] {
        let b = loadBrandInfo()
        return Array(Set([b.bundleId, b.netextId, b.esextId, b.daemonLabel].filter { isSafeId($0) })).sorted()
    }

    private static func buildExactPeerRequirement(teamId: String, allowedIdentifiers: [String]) -> String? {
        guard teamId.range(of: "^[A-Z0-9]{10}$", options: .regularExpression) != nil else {
            return nil
        }
        let clean = allowedIdentifiers.filter { isSafeId($0) }
        guard !clean.isEmpty else {
            return nil
        }
        let clauses = clean.map { "identifier = \"\($0)\"" }.joined(separator: " or ")
        return "anchor apple generic and (\(clauses)) and certificate leaf[subject.OU] = \"\(teamId)\""
    }

    private static func isSafeId(_ id: String) -> Bool {
        return !id.isEmpty && id.range(of: "^[A-Za-z0-9.-]+$", options: .regularExpression) != nil
    }

    private static func decodeFixedUtf8<T>(_ tuple: T, len: UInt16) -> String {
        return withUnsafeBytes(of: tuple) { raw in
            let count = min(Int(len), raw.count)
            return String(decoding: raw.prefix(count), as: UTF8.self)
        }
    }
}
#endif
