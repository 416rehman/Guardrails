// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors

#if os(macOS)
import Darwin.Mach
import Darwin.bsm
import EndpointSecurity
import Foundation
import GrdrSensorMacOSBridge

public final class GrdrEsTreeCoordinator: @unchecked Sendable {
    private static let maxTelemetryQueue: Int = 4_096
    private static let maxLiveMembers: Int = 4_096

    private var follower: OpaquePointer?
    private var clients: [GrdrEsConcern: OpaquePointer] = [:]
    private var clientStatuses: [GrdrEsConcern: GrdrEsClientState] = [:]
    private let dispatchQueues: [GrdrEsConcern: DispatchQueue]
    private let stateLock = NSLock()
    private let policyLock = NSLock()
    private var floorTableBin: Data = Data()
    private var floorEpoch: UInt64 = 0
    private var defaultDeny: UInt8 = 1
    private var proxyPort: UInt16 = 0
    private var proxyToken: String = ""
    private var modelHostSuffixes: [String] = []
    private var seqCounter: UInt64 = 1
    private var cacheClearCount: UInt64 = 0
    private var mutedTeams: Set<String> = []
    private var protectedPaths: [String] = []
    private var selfPaths: [String] = []
    private var liveMembers: [UInt64: GrdrEsLiveMemberEntry] = [:]
    private var telemetryQueue: [GrdrEsTelemetryEvent] = []
    private var timebaseInfo = mach_timebase_info_data_t(numer: 1, denom: 1)

    public var onPolicyUpdated: ((Data, UInt64, Bool, UInt16, [String], String) -> Void)?
    public var onTreeDeltaEmitted: ((Data) -> Void)?

    public init() {
        mach_timebase_info(&timebaseInfo)
        follower = grdr_macos_follower_new()
        let prefix = GrdrEsEventAdapter.loadBrandMetadata().prefix
        var queues: [GrdrEsConcern: DispatchQueue] = [:]
        for concern in GrdrEsConcern.allCases {
            let label = prefix.isEmpty ? "es.\(concern.rawValue)" : "\(prefix)es.\(concern.rawValue)"
            let qos: DispatchQoS = (concern == .recorder) ? .utility : .userInteractive
            queues[concern] = DispatchQueue(label: label, qos: qos)
            clientStatuses[concern] = .stopped
        }
        self.dispatchQueues = queues
        if let f = follower {
            _ = grdr_macos_follower_register_self_pid(f, UInt32(max(1, getpid())))
        }
        for path in GrdrEsEventAdapter.defaultSelfPaths() {
            _ = addSelfPath(path)
        }
    }

    deinit {
        stop()
        stateLock.lock()
        let f = follower
        follower = nil
        stateLock.unlock()
        if let ptr = f {
            grdr_macos_follower_free(ptr)
        }
    }

    public func sharedFollower() -> OpaquePointer? {
        stateLock.lock()
        defer { stateLock.unlock() }
        return follower
    }

    public func currentStatuses() -> [String: String] {
        stateLock.lock()
        defer { stateLock.unlock() }
        var out: [String: String] = [:]
        for concern in GrdrEsConcern.allCases {
            out[concern.rawValue] = (clientStatuses[concern] ?? .stopped).rawValue
        }
        return out
    }

    public func currentPolicySnapshot() -> (
        floorBin: Data,
        epoch: UInt64,
        defaultDeny: Bool,
        proxyPort: UInt16,
        modelHostSuffixes: [String],
        proxyToken: String,
        treeDeltas: [Data]
    ) {
        policyLock.lock()
        let bin = floorTableBin
        let epoch = floorEpoch
        let deny = defaultDeny != 0
        let port = proxyPort
        let suffixes = modelHostSuffixes
        let token = proxyToken
        policyLock.unlock()

        let deltas = snapshotTreeDeltas()
        return (bin, epoch, deny, port, suffixes, token, deltas)
    }

    public func snapshotTreeDeltas() -> [Data] {
        stateLock.lock()
        let entries = Array(liveMembers.values)
        stateLock.unlock()
        return GrdrEsClientConfigurator.encodeLiveMemberDeltas(entries)
    }

    public func lookupAuditToken(pid: UInt32, pidversion: UInt32) -> (governed: Bool, sessionId: String, agentName: String) {
        stateLock.lock()
        let f = follower
        stateLock.unlock()
        guard let f = f else {
            return (false, "", "")
        }
        return GrdrEsClientConfigurator.lookupAuditToken(follower: f, pid: pid, pidversion: pidversion)
    }

    public func swapBinaryFloorTable(data: Data, epoch: UInt64, defaultDeny: Bool) -> UInt64 {
        policyLock.lock()
        let changed = (floorTableBin != data) || (self.defaultDeny != (defaultDeny ? 1 : 0))
        floorTableBin = data
        floorEpoch = epoch
        self.defaultDeny = defaultDeny ? 1 : 0
        let port = proxyPort
        let suffixes = modelHostSuffixes
        let token = proxyToken
        policyLock.unlock()

        if changed {
            clearAuthorizerCaches()
        }
        onPolicyUpdated?(data, epoch, defaultDeny, port, suffixes, token)
        return epoch
    }

    public func configureProxy(loopbackPort: UInt16, modelHostSuffixes: [String], proxyToken: String = "") {
        policyLock.lock()
        self.proxyPort = loopbackPort
        self.modelHostSuffixes = modelHostSuffixes
        if !proxyToken.isEmpty {
            self.proxyToken = proxyToken
        }
        let bin = floorTableBin
        let epoch = floorEpoch
        let deny = defaultDeny != 0
        let activeToken = self.proxyToken
        policyLock.unlock()
        onPolicyUpdated?(bin, epoch, deny, loopbackPort, modelHostSuffixes, activeToken)
    }

    public func registerAgentRoot(
        pid: UInt32,
        pidversion: UInt32,
        uid: UInt32,
        sessionId: String,
        agentName: String
    ) -> Bool {
        stateLock.lock()
        let f = follower
        let recorderClient = clients[.recorder]
        let execClient = clients[.execAuthorizer]
        stateLock.unlock()
        guard let f = f, !sessionId.isEmpty else {
            return false
        }

        var auditTok = GrdrEsClientConfigurator.synthesizeAuditToken(pid: pid, pidversion: pidversion, uid: uid)
        if let c = recorderClient {
            _ = es_unmute_process(c, &auditTok)
        }
        if let c = execClient {
            _ = es_unmute_process(c, &auditTok)
        }

        let ok = GrdrEsClientConfigurator.registerRoot(
            follower: f,
            pid: pid,
            pidversion: pidversion,
            uid: uid,
            sessionId: sessionId,
            agentName: agentName
        )
        if ok {
            stateLock.lock()
            let delta = GrdrEsClientConfigurator.insertRootMember(
                &liveMembers,
                maxMembers: Self.maxLiveMembers,
                pid: pid,
                pidversion: pidversion,
                uid: uid,
                sessionId: sessionId,
                agentName: agentName
            )
            stateLock.unlock()
            onTreeDeltaEmitted?(delta)
        }
        return ok
    }

    public func registerSelfPid(_ pid: UInt32) -> Bool {
        stateLock.lock()
        let f = follower
        stateLock.unlock()
        guard let f = f, pid > 0 else {
            return false
        }
        return grdr_macos_follower_register_self_pid(f, pid) == GRDR_MAC_FFI_OK.rawValue
    }

    public func addProtectedPath(_ rawPath: String) -> Bool {
        registerGuardPath(rawPath, isSelfPath: false)
    }

    public func addSelfPath(_ rawPath: String) -> Bool {
        registerGuardPath(rawPath, isSelfPath: true)
    }

    private func registerGuardPath(_ rawPath: String, isSelfPath: Bool) -> Bool {
        let canon = GrdrEsEventAdapter.canonicalizeTargetPath(rawPath)
        guard !canon.isEmpty else {
            return false
        }
        stateLock.lock()
        let f = follower
        let pathClient = isSelfPath ? nil : clients[.protectedPathGuard]
        let selfClient = clients[.selfProtection]
        if isSelfPath {
            if !selfPaths.contains(canon) { selfPaths.append(canon) }
        } else if !protectedPaths.contains(canon) {
            protectedPaths.append(canon)
        }
        stateLock.unlock()
        if let c = pathClient {
            _ = canon.withCString { es_unmute_path(c, $0, ES_MUTE_PATH_TYPE_TARGET_PREFIX) }
        }
        if let c = selfClient {
            _ = canon.withCString { es_unmute_path(c, $0, ES_MUTE_PATH_TYPE_TARGET_PREFIX) }
        }
        guard let f = f else {
            return false
        }
        return GrdrEsClientConfigurator.registerGuardPath(follower: f, path: canon, isSelfPath: isSelfPath)
    }

    public func muteIncumbentTeam(_ teamId: String) -> Bool {
        stateLock.lock()
        let f = follower
        if !teamId.isEmpty {
            mutedTeams.insert(teamId)
        }
        stateLock.unlock()
        guard let f = f, !teamId.isEmpty else {
            return false
        }
        let data = Data(teamId.utf8)
        return data.withUnsafeBytes { buf in
            grdr_macos_follower_mute_team(f, buf.bindMemory(to: UInt8.self).baseAddress, buf.count) == GRDR_MAC_FFI_OK.rawValue
        }
    }

    public func drainTelemetry(maxEvents: Int) -> [Data] {
        guard maxEvents > 0 else {
            return []
        }
        stateLock.lock()
        let count = min(maxEvents, telemetryQueue.count)
        let batch = Array(telemetryQueue.prefix(count))
        telemetryQueue.removeFirst(count)
        stateLock.unlock()
        return batch.map { GrdrEsTelemetryCodec.encodeBinary($0) }
    }

    public func stop() {
        stateLock.lock()
        let active = clients
        clients.removeAll()
        liveMembers.removeAll()
        for concern in GrdrEsConcern.allCases {
            clientStatuses[concern] = .stopped
        }
        stateLock.unlock()
        for (_, client) in active {
            _ = es_unsubscribe_all(client)
            es_delete_client(client)
        }
    }

    public func startClients(mutedTeamIds: [String]) -> es_new_client_result_t {
        stop()
        for team in mutedTeamIds where !team.isEmpty {
            _ = muteIncumbentTeam(team)
        }

        stateLock.lock()
        let protSnapshot = protectedPaths
        let selfSnapshot = selfPaths
        stateLock.unlock()

        var firstFailure: es_new_client_result_t?
        for concern in GrdrEsConcern.allCases {
            let outcome = GrdrEsClientConfigurator.startClient(
                concern: concern,
                protectedPaths: protSnapshot,
                selfPaths: selfSnapshot
            ) { [weak self] clientRef, message in
                self?.handleEsMessage(concern: concern, client: clientRef, message: message)
            }
            stateLock.lock()
            if let activeClient = outcome.client {
                clients[concern] = activeClient
            }
            clientStatuses[concern] = outcome.state
            stateLock.unlock()
            if outcome.result != ES_NEW_CLIENT_RESULT_SUCCESS && firstFailure == nil {
                firstFailure = outcome.result
            }
        }
        return firstFailure ?? ES_NEW_CLIENT_RESULT_SUCCESS
    }

    private func clearAuthorizerCaches() {
        stateLock.lock()
        let targets = [clients[.execAuthorizer], clients[.protectedPathGuard], clients[.selfProtection]]
        cacheClearCount = cacheClearCount &+ 1
        stateLock.unlock()
        for case let client? in targets {
            _ = es_clear_cache(client)
            break
        }
    }

    private func handleEsMessage(
        concern: GrdrEsConcern,
        client: OpaquePointer,
        message: UnsafePointer<es_message_t>
    ) {
        let startMach = mach_absolute_time()
        es_retain_message(message)
        guard let queue = dispatchQueues[concern] else {
            if message.pointee.action_type == ES_ACTION_TYPE_AUTH {
                _ = es_respond_auth_result(client, message, ES_AUTH_RESULT_ALLOW, false)
            }
            es_release_message(message)
            return
        }

        queue.async { [weak self] in
            defer { es_release_message(message) }
            guard let self = self else {
                return
            }
            self.stateLock.lock()
            let activeClient = self.clients[concern]
            let f = self.follower
            self.stateLock.unlock()

            guard activeClient == client, let f = f else {
                if message.pointee.action_type == ES_ACTION_TYPE_AUTH {
                    _ = es_respond_auth_result(client, message, ES_AUTH_RESULT_ALLOW, false)
                }
                return
            }

            self.policyLock.lock()
            let binSnapshot = self.floorTableBin
            let denyFlag = self.defaultDeny
            self.policyLock.unlock()

            let elapsedMs = GrdrEsClientConfigurator.elapsedMilliseconds(since: startMach, timebase: self.timebaseInfo)
            let kernelDeadlineMs = GrdrEsEventAdapter.remainingKernelDeadlineMs(
                deadline: message.pointee.deadline,
                now: mach_absolute_time(),
                timebase: self.timebaseInfo
            )
            let eval = GrdrEsEventAdapter.evaluateMessage(
                concern: concern,
                follower: f,
                message: message,
                floorTableBin: binSnapshot,
                defaultDeny: denyFlag,
                seqNum: self.nextSequenceNumber(),
                elapsedMs: elapsedMs,
                kernelDeadlineMs: kernelDeadlineMs
            )

            self.stateLock.lock()
            GrdrEsClientConfigurator.updateLiveMembers(
                &self.liveMembers,
                maxMembers: Self.maxLiveMembers,
                message: message,
                eval: eval
            )
            self.stateLock.unlock()

            if (message.pointee.event_type == ES_EVENT_TYPE_NOTIFY_FORK || message.pointee.event_type == ES_EVENT_TYPE_AUTH_EXEC),
               eval.verdict.unmuted_pid != 0 {
                self.stateLock.lock()
                let execC = self.clients[.execAuthorizer]
                let recC = self.clients[.recorder]
                self.stateLock.unlock()
                GrdrEsClientConfigurator.unmutePidInTreeClients(
                    message: message,
                    execClient: execC,
                    recorderClient: recC
                )
            }

            if concern == .recorder && eval.verdict.governed_member != 0 {
                let teamStr = GrdrEsEventAdapter.stringFromEsToken(message.pointee.process.pointee.team_id)
                self.stateLock.lock()
                let isMutedTeam = !teamStr.isEmpty && self.mutedTeams.contains(teamStr)
                self.stateLock.unlock()
                if isMutedTeam {
                    var tok = message.pointee.process.pointee.audit_token
                    _ = es_mute_process(client, &tok)
                }
            }

            if message.pointee.action_type == ES_ACTION_TYPE_AUTH {
                let authRes: es_auth_result_t = (eval.verdict.verdict_code == UInt8(GRDR_MAC_VERDICT_ALLOW.rawValue))
                    ? ES_AUTH_RESULT_ALLOW
                    : ES_AUTH_RESULT_DENY
                let cacheFlag = (authRes == ES_AUTH_RESULT_ALLOW) && (eval.verdict.should_cache != 0)
                _ = es_respond_auth_result(client, message, authRes, cacheFlag)
            }

            if let delta = eval.treeDeltaRecord {
                self.onTreeDeltaEmitted?(delta)
            }

            if eval.verdict.governed_member != 0
                || eval.verdict.tamper_alert != 0
                || eval.verdict.synthesized_denied_exec != 0
                || eval.alwaysEmitTelemetry {
                self.enqueueTelemetry(
                    concern: concern,
                    kindCode: eval.kindCode,
                    message: message,
                    targetPath: eval.targetPath,
                    verdict: eval.verdict
                )
            }
        }
    }

    private func enqueueTelemetry(
        concern: GrdrEsConcern,
        kindCode: UInt8,
        message: UnsafePointer<es_message_t>,
        targetPath: String,
        verdict: GrdrMacEsVerdictC
    ) {
        let rec = GrdrEsClientConfigurator.buildTelemetryEvent(
            seqNum: nextSequenceNumber(),
            concern: concern,
            kindCode: kindCode,
            message: message,
            targetPath: targetPath,
            verdict: verdict
        )
        stateLock.lock()
        if telemetryQueue.count >= Self.maxTelemetryQueue {
            telemetryQueue.removeFirst()
        }
        telemetryQueue.append(rec)
        stateLock.unlock()
    }

    private func nextSequenceNumber() -> UInt64 {
        stateLock.lock()
        let s = seqCounter
        seqCounter = seqCounter &+ 1
        stateLock.unlock()
        return s
    }
}
#endif
