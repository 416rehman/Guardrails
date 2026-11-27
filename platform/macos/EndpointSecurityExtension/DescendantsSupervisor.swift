// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors

#if os(macOS)
import Darwin.Mach
import Darwin.bsm
import EndpointSecurity
import Foundation
import GrdrSensorMacOSBridge

public enum GrdrDescendantsActivationResult: Sendable {
    case active
    case fallbackSeatbeltRequired(reason: String)
    case error(es_new_client_result_t)
}

public final class GrdrDescendantsSupervisor: @unchecked Sendable {
    private static let guardTailMs: UInt32 = 10_000
    private static let holdCapPct: UInt64 = 80
    private var client: OpaquePointer?
    private let lock = NSLock()
    private let callbackQueue: DispatchQueue
    private var floorTableBin: Data = Data()
    private var defaultDeny: UInt8 = 1
    private var sharedFollower: OpaquePointer?
    private var ownsFollower: Bool = false
    private var activeSessionId: String = ""
    private var activeAgentName: String = ""
    private var trackedMembers: [UInt32: UInt32] = [:]
    private var timebaseInfo = mach_timebase_info_data_t(numer: 1, denom: 1)
    public var onTelemetryEvent: ((GrdrEsTelemetryEvent) -> Void)?

    public init() {
        var prefix = ""
        var brand = GrdrMacBrandInfoC()
        if grdr_macos_get_brand_info(&brand) == GRDR_MAC_FFI_OK.rawValue {
            prefix = withUnsafeBytes(of: brand.own_prefix) { raw in
                String(decoding: raw.prefix(Int(brand.own_prefix_len)), as: UTF8.self)
            }
        }
        let label = prefix.isEmpty ? "es.descendants" : "\(prefix)descendants"
        self.callbackQueue = DispatchQueue(label: label, qos: .userInteractive)
        mach_timebase_info(&timebaseInfo)
    }

    deinit {
        stop()
        lock.lock()
        let owned = ownsFollower ? sharedFollower : nil
        sharedFollower = nil
        ownsFollower = false
        lock.unlock()
        if let f = owned {
            grdr_macos_follower_free(f)
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

    public func configureBinaryFloorPolicy(tableBin: Data, defaultDeny: Bool) {
        lock.lock()
        floorTableBin = tableBin
        self.defaultDeny = defaultDeny ? 1 : 0
        lock.unlock()
    }

    public func currentMembersSnapshot() -> [UInt32: UInt32] {
        lock.lock()
        defer { lock.unlock() }
        return trackedMembers
    }

    public func stop() {
        lock.lock()
        let c = client
        client = nil
        trackedMembers.removeAll()
        lock.unlock()
        if let active = c {
            _ = es_unsubscribe_all(active)
            es_delete_client(active)
        }
    }

    public func superviseSubtree(
        sessionId: String,
        agentName: String = "",
        rootPid: UInt32 = UInt32(max(1, getpid())),
        rootPidVersion: UInt32 = 1,
        rootUid: UInt32 = geteuid(),
        deadlineFloorMs: UInt32,
        failClosed: Bool
    ) -> GrdrDescendantsActivationResult {
        guard !sessionId.isEmpty, deadlineFloorMs > 0, deadlineFloorMs < (UInt32.max - Self.guardTailMs) else {
            return .error(ES_NEW_CLIENT_RESULT_ERR_INVALID_ARGUMENT)
        }
        guard #available(macOS 27.0, *) else {
            return .fallbackSeatbeltRequired(reason: "macOS < 27 uses Seatbelt containment fallback")
        }
        stop()

        lock.lock()
        if sharedFollower == nil {
            sharedFollower = grdr_macos_follower_new()
            ownsFollower = true
        }
        let followerRef = sharedFollower
        activeSessionId = sessionId
        activeAgentName = agentName
        trackedMembers[rootPid] = rootPidVersion
        lock.unlock()

        if let f = followerRef {
            _ = registerRootMember(
                follower: f,
                pid: rootPid,
                pidversion: rootPidVersion,
                uid: rootUid,
                sessionId: sessionId,
                agentName: agentName
            )
        }

        let holdCapMs = max(1, (UInt64(deadlineFloorMs) * Self.holdCapPct) / 100)
        var newClient: OpaquePointer?
        let status = es_new_descendants_client(&newClient) { [weak self] clientRef, message in
            guard let self = self else {
                if message.pointee.action_type == ES_ACTION_TYPE_AUTH {
                    _ = es_respond_auth_result(clientRef, message, ES_AUTH_RESULT_ALLOW, false)
                }
                return
            }
            es_retain_message(message)
            self.callbackQueue.async {
                defer { es_release_message(message) }
                self.handleDescendantMessage(
                    client: clientRef,
                    message: message,
                    holdCapMs: holdCapMs,
                    deadlineFloorMs: UInt64(deadlineFloorMs),
                    failClosed: failClosed
                )
            }
        }
        guard status == ES_NEW_CLIENT_RESULT_SUCCESS, let active = newClient else {
            return .error(status)
        }
        guard es_set_deadline_min_milliseconds(active, deadlineFloorMs) == ES_RETURN_SUCCESS else {
            es_delete_client(active)
            return .error(ES_NEW_CLIENT_RESULT_ERR_INTERNAL)
        }
        let missMode = failClosed
            ? ES_DEADLINE_MISS_MODE_FAIL_CLOSED
            : ES_DEADLINE_MISS_MODE_FAIL_OPEN
        guard es_set_deadline_miss_mode(active, missMode) == ES_RETURN_SUCCESS else {
            es_delete_client(active)
            return .error(ES_NEW_CLIENT_RESULT_ERR_INTERNAL)
        }

        let subs: [es_event_type_t] = [
            ES_EVENT_TYPE_AUTH_EXEC,
            ES_EVENT_TYPE_NOTIFY_FORK,
            ES_EVENT_TYPE_NOTIFY_EXEC,
            ES_EVENT_TYPE_NOTIFY_EXIT,
            ES_EVENT_TYPE_AUTH_OPEN
        ]
        guard es_subscribe(active, subs, UInt32(subs.count)) == ES_RETURN_SUCCESS else {
            es_delete_client(active)
            return .error(ES_NEW_CLIENT_RESULT_ERR_INTERNAL)
        }

        lock.lock()
        client = active
        lock.unlock()
        return .active
    }

    private func registerRootMember(
        follower: OpaquePointer,
        pid: UInt32,
        pidversion: UInt32,
        uid: UInt32,
        sessionId: String,
        agentName: String
    ) -> Bool {
        let sidData = Data(sessionId.utf8)
        let agentData = Data(agentName.utf8)
        return sidData.withUnsafeBytes { sidBuf in
            agentData.withUnsafeBytes { agentBuf in
                var ev = emptyEvent(
                    kindCode: UInt8(GRDR_MAC_ES_REGISTER_ROOT.rawValue),
                    concernCode: UInt8(GRDR_MAC_ES_CONCERN_EXEC_AUTHORIZER.rawValue)
                )
                ev.actor.key = GrdrMacProcessKeyC(pid: pid, pidversion: pidversion)
                ev.actor.uid = uid
                ev.session_id_ptr = sidBuf.bindMemory(to: UInt8.self).baseAddress
                ev.session_id_len = sidBuf.count
                ev.agent_name_ptr = agentBuf.bindMemory(to: UInt8.self).baseAddress
                ev.agent_name_len = agentBuf.count
                var out = GrdrMacEsVerdictC()
                return grdr_macos_eval_es_event_c(follower, &ev, nil, 0, &out) == GRDR_MAC_FFI_OK.rawValue
            }
        }
    }

    private func handleDescendantMessage(
        client: OpaquePointer,
        message: UnsafePointer<es_message_t>,
        holdCapMs: UInt64,
        deadlineFloorMs: UInt64,
        failClosed: Bool
    ) {
        let startMach = mach_absolute_time()
        let msg = message.pointee
        let actorProc = msg.process.pointee
        let actorTok = actorProc.audit_token
        let pid = UInt32(max(0, audit_token_to_pid(actorTok)))
        let pidver = UInt32(max(0, audit_token_to_pidversion(actorTok)))

        lock.lock()
        let f = sharedFollower
        let bin = floorTableBin
        let denyFlag = defaultDeny
        let sid = activeSessionId
        if msg.event_type == ES_EVENT_TYPE_NOTIFY_EXIT {
            trackedMembers.removeValue(forKey: pid)
        } else {
            trackedMembers[pid] = pidver
        }
        lock.unlock()

        guard let f = f else {
            if msg.action_type == ES_ACTION_TYPE_AUTH {
                let fallback = failClosed ? ES_AUTH_RESULT_DENY : ES_AUTH_RESULT_ALLOW
                _ = es_respond_auth_result(client, message, fallback, false)
            }
            return
        }

        let elapsedMs = elapsedMilliseconds(since: startMach)
        if msg.action_type == ES_ACTION_TYPE_AUTH && elapsedMs > holdCapMs {
            let fallback = failClosed ? ES_AUTH_RESULT_DENY : ES_AUTH_RESULT_ALLOW
            _ = es_respond_auth_result(client, message, fallback, false)
            emitSynthesizedTelemetry(
                concernCode: UInt8(GRDR_MAC_ES_CONCERN_EXEC_AUTHORIZER.rawValue),
                kindCode: UInt8(GRDR_MAC_ES_AUTH_EXEC.rawValue),
                pid: pid,
                pidver: pidver,
                sessionId: sid,
                verdictCode: failClosed ? UInt8(GRDR_MAC_VERDICT_DENY.rawValue) : UInt8(GRDR_MAC_VERDICT_ALLOW.rawValue),
                synthesizedDeniedExec: failClosed,
                targetPath: "hold-cap-exceeded"
            )
            return
        }

        var kindCode: UInt8 = 0
        var concernCode = UInt8(GRDR_MAC_ES_CONCERN_EXEC_AUTHORIZER.rawValue)
        var targetProc = actorProc
        var path = ""
        var accessFlags: UInt32 = 0

        switch msg.event_type {
        case ES_EVENT_TYPE_AUTH_EXEC:
            kindCode = UInt8(GRDR_MAC_ES_AUTH_EXEC.rawValue)
            targetProc = msg.event.exec.target.pointee
            path = stringFromEsToken(targetProc.executable.pointee.path)
        case ES_EVENT_TYPE_NOTIFY_FORK:
            kindCode = UInt8(GRDR_MAC_ES_NOTIFY_FORK.rawValue)
            targetProc = msg.event.fork.child.pointee
        case ES_EVENT_TYPE_NOTIFY_EXEC:
            kindCode = UInt8(GRDR_MAC_ES_NOTIFY_EXEC.rawValue)
            targetProc = msg.event.exec.target.pointee
            path = stringFromEsToken(targetProc.executable.pointee.path)
        case ES_EVENT_TYPE_NOTIFY_EXIT:
            kindCode = UInt8(GRDR_MAC_ES_NOTIFY_EXIT.rawValue)
        case ES_EVENT_TYPE_AUTH_OPEN:
            kindCode = UInt8(GRDR_MAC_ES_AUTH_OPEN.rawValue)
            concernCode = UInt8(GRDR_MAC_ES_CONCERN_PROTECTED_PATH_GUARD.rawValue)
            path = stringFromEsToken(msg.event.open.file.pointee.path)
            let writeMask = Int32(FWRITE) | O_APPEND | O_TRUNC | O_CREAT
            accessFlags = (msg.event.open.fflag & writeMask) != 0 ? 0x2 : 0x1
        default:
            if msg.action_type == ES_ACTION_TYPE_AUTH {
                _ = es_respond_auth_result(client, message, ES_AUTH_RESULT_ALLOW, false)
            }
            return
        }

        let targetTok = targetProc.audit_token
        let targetPid = UInt32(max(0, audit_token_to_pid(targetTok)))
        let targetPidver = UInt32(max(0, audit_token_to_pidversion(targetTok)))
        let actorTokC = GrdrMacAuditTokenC(
            key: GrdrMacProcessKeyC(pid: pid, pidversion: pidver),
            uid: audit_token_to_euid(actorTok),
            reserved: 0,
            team_id_ptr: nil,
            team_id_len: 0
        )
        let targetTokC = GrdrMacAuditTokenC(
            key: GrdrMacProcessKeyC(pid: targetPid, pidversion: targetPidver),
            uid: audit_token_to_euid(targetTok),
            reserved: 0,
            team_id_ptr: nil,
            team_id_len: 0
        )

        let pathData = Data(path.utf8)
        let remainingDeadline = remainingKernelDeadlineMs(deadline: msg.deadline, now: mach_absolute_time(), floorMs: deadlineFloorMs)
        var verdictOut = GrdrMacEsVerdictC()
        verdictOut.verdict_code = failClosed ? UInt8(GRDR_MAC_VERDICT_DENY.rawValue) : UInt8(GRDR_MAC_VERDICT_ALLOW.rawValue)

        _ = pathData.withUnsafeBytes { pathBuf in
            bin.withUnsafeBytes { binBuf in
                var ev = emptyEvent(kindCode: kindCode, concernCode: concernCode)
                ev.default_deny = denyFlag
                ev.access_flags = accessFlags
                ev.elapsed_ms = elapsedMs
                ev.kernel_deadline_ms = remainingDeadline
                ev.actor = actorTokC
                ev.target = targetTokC
                ev.path_ptr = pathBuf.bindMemory(to: UInt8.self).baseAddress
                ev.path_len = pathBuf.count
                return grdr_macos_eval_es_event_bin_c(
                    f,
                    &ev,
                    binBuf.bindMemory(to: UInt8.self).baseAddress,
                    binBuf.count,
                    &verdictOut
                )
            }
        }

        if msg.action_type == ES_ACTION_TYPE_AUTH {
            let authRes: es_auth_result_t = (verdictOut.verdict_code == UInt8(GRDR_MAC_VERDICT_ALLOW.rawValue))
                ? ES_AUTH_RESULT_ALLOW
                : ES_AUTH_RESULT_DENY
            let cacheFlag = (authRes == ES_AUTH_RESULT_ALLOW) && (verdictOut.should_cache != 0)
            _ = es_respond_auth_result(client, message, authRes, cacheFlag)
        }

        emitSynthesizedTelemetry(
            concernCode: concernCode,
            kindCode: kindCode,
            pid: pid,
            pidver: pidver,
            sessionId: sid,
            verdictCode: verdictOut.verdict_code,
            synthesizedDeniedExec: verdictOut.synthesized_denied_exec != 0,
            targetPath: path
        )
    }

    private func emitSynthesizedTelemetry(
        concernCode: UInt8,
        kindCode: UInt8,
        pid: UInt32,
        pidver: UInt32,
        sessionId: String,
        verdictCode: UInt8,
        synthesizedDeniedExec: Bool,
        targetPath: String
    ) {
        onTelemetryEvent?(GrdrEsTelemetryEvent(
            seqNum: 0,
            concernCode: concernCode,
            concern: "descendants_supervisor",
            kindCode: kindCode,
            pid: pid,
            pidversion: pidver,
            sessionId: sessionId,
            actionClassCode: 0,
            verdictCode: verdictCode,
            tamperAlert: false,
            synthesizedDeniedExec: synthesizedDeniedExec,
            targetPath: targetPath
        ))
    }

    private func emptyEvent(kindCode: UInt8, concernCode: UInt8) -> GrdrMacEsEventC {
        let zeroKey = GrdrMacProcessKeyC(pid: 0, pidversion: 0)
        let zeroTok = GrdrMacAuditTokenC(key: zeroKey, uid: 0, reserved: 0, team_id_ptr: nil, team_id_len: 0)
        return GrdrMacEsEventC(
            kind_code: kindCode,
            concern_code: concernCode,
            default_deny: 1,
            reserved0: 0,
            access_flags: 0,
            event_flags: 0,
            reserved1: 0,
            seq_num: 0,
            timestamp_ns: 0,
            elapsed_ms: 0,
            kernel_deadline_ms: 0,
            actor: zeroTok,
            target: zeroTok,
            path_ptr: nil,
            path_len: 0,
            secondary_path_ptr: nil,
            secondary_path_len: 0,
            session_id_ptr: nil,
            session_id_len: 0,
            agent_name_ptr: nil,
            agent_name_len: 0
        )
    }

    private func elapsedMilliseconds(since startMach: UInt64) -> UInt64 {
        let now = mach_absolute_time()
        let delta = now > startMach ? (now - startMach) : 0
        let ns = (delta &* UInt64(timebaseInfo.numer)) / UInt64(max(1, timebaseInfo.denom))
        return ns / 1_000_000
    }

    private func remainingKernelDeadlineMs(deadline: UInt64, now: UInt64, floorMs: UInt64) -> UInt64 {
        guard deadline > now else {
            return 0
        }
        let delta = deadline - now
        let ns = (delta &* UInt64(timebaseInfo.numer)) / UInt64(max(1, timebaseInfo.denom))
        let rem = ns / 1_000_000
        return floorMs > 0 ? min(rem, floorMs) : rem
    }

    private func stringFromEsToken(_ token: es_string_token_t) -> String {
        guard let ptr = token.data, token.length > 0 else {
            return ""
        }
        let raw = UnsafeRawPointer(ptr).assumingMemoryBound(to: UInt8.self)
        return String(bytes: UnsafeBufferPointer(start: raw, count: token.length), encoding: .utf8) ?? ""
    }
}
#endif
