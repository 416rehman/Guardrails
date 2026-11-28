// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors

#if os(macOS)
import Darwin.Mach
import Darwin.bsm
import EndpointSecurity
import Foundation
import GrdrSensorMacOSBridge

internal struct GrdrEsLiveMemberEntry {
    let pid: UInt32
    let pidversion: UInt32
    let uid: UInt32
    let sessionId: String
    let agentName: String
}

internal struct GrdrEsClientStartOutcome {
    let client: OpaquePointer?
    let state: GrdrEsClientState
    let result: es_new_client_result_t
}

internal enum GrdrEsClientConfigurator {
    static func startClient(
        concern: GrdrEsConcern,
        protectedPaths: [String],
        selfPaths: [String],
        handler: @escaping (OpaquePointer, UnsafePointer<es_message_t>) -> Void
    ) -> GrdrEsClientStartOutcome {
        var newClient: OpaquePointer?
        let status = es_new_client(&newClient) { clientRef, message in
            handler(clientRef, message)
        }
        guard status == ES_NEW_CLIENT_RESULT_SUCCESS, let activeClient = newClient else {
            return GrdrEsClientStartOutcome(
                client: nil,
                state: mapClientError(status),
                result: status
            )
        }

        let missRc = es_set_deadline_miss_mode(activeClient, ES_DEADLINE_MISS_MODE_FAIL_OPEN)
        guard missRc == ES_RETURN_SUCCESS else {
            es_delete_client(activeClient)
            return GrdrEsClientStartOutcome(
                client: nil,
                state: .internalError,
                result: ES_NEW_CLIENT_RESULT_ERR_INTERNAL
            )
        }

        configureClientMuting(
            concern: concern,
            client: activeClient,
            protectedPaths: protectedPaths,
            selfPaths: selfPaths
        )

        let subs = subscriptionsForConcern(concern)
        let subRc = es_subscribe(activeClient, subs, UInt32(subs.count))
        guard subRc == ES_RETURN_SUCCESS else {
            es_delete_client(activeClient)
            return GrdrEsClientStartOutcome(
                client: nil,
                state: .internalError,
                result: ES_NEW_CLIENT_RESULT_ERR_INTERNAL
            )
        }

        return GrdrEsClientStartOutcome(
            client: activeClient,
            state: .active,
            result: ES_NEW_CLIENT_RESULT_SUCCESS
        )
    }

    static func configureClientMuting(
        concern: GrdrEsConcern,
        client: OpaquePointer,
        protectedPaths: [String],
        selfPaths: [String]
    ) {
        switch concern {
        case .recorder, .execAuthorizer:
            _ = es_mute_inversion_set_muting_enabled(client, ES_MUTE_INVERSION_TYPE_PROCESS, true)
        case .protectedPathGuard:
            _ = es_mute_inversion_set_muting_enabled(client, ES_MUTE_INVERSION_TYPE_TARGET_PATH, true)
            for p in protectedPaths.map(GrdrEsEventAdapter.canonicalizeTargetPath) where !p.isEmpty {
                _ = p.withCString { es_unmute_path(client, $0, ES_MUTE_PATH_TYPE_TARGET_PREFIX) }
            }
        case .selfProtection:
            _ = es_mute_inversion_set_muting_enabled(client, ES_MUTE_INVERSION_TYPE_TARGET_PATH, true)
            for p in (selfPaths + protectedPaths).map(GrdrEsEventAdapter.canonicalizeTargetPath) where !p.isEmpty {
                _ = p.withCString { es_unmute_path(client, $0, ES_MUTE_PATH_TYPE_TARGET_PREFIX) }
            }
        }
    }

    static func subscriptionsForConcern(_ concern: GrdrEsConcern) -> [es_event_type_t] {
        switch concern {
        case .recorder:
            var events: [es_event_type_t] = [
                ES_EVENT_TYPE_NOTIFY_EXEC,
                ES_EVENT_TYPE_NOTIFY_FORK,
                ES_EVENT_TYPE_NOTIFY_EXIT,
                ES_EVENT_TYPE_NOTIFY_CREATE,
                ES_EVENT_TYPE_NOTIFY_RENAME,
                ES_EVENT_TYPE_NOTIFY_UNLINK,
                ES_EVENT_TYPE_NOTIFY_UIPC_CONNECT,
                ES_EVENT_TYPE_NOTIFY_XPC_CONNECT,
                ES_EVENT_TYPE_NOTIFY_SUDO,
                ES_EVENT_TYPE_NOTIFY_SU,
                ES_EVENT_TYPE_NOTIFY_AUTHORIZATION_PETITION,
                ES_EVENT_TYPE_NOTIFY_AUTHORIZATION_JUDGEMENT,
                ES_EVENT_TYPE_NOTIFY_TCC_MODIFY,
                ES_EVENT_TYPE_NOTIFY_BTM_LAUNCH_ITEM_ADD
            ]
            if #available(macOS 27.0, *) {
                events.append(ES_EVENT_TYPE_NOTIFY_BOOTSTRAP_LOOKUP)
            }
            return events
        case .execAuthorizer:
            return [ES_EVENT_TYPE_AUTH_EXEC]
        case .protectedPathGuard:
            return [
                ES_EVENT_TYPE_AUTH_OPEN,
                ES_EVENT_TYPE_AUTH_CREATE,
                ES_EVENT_TYPE_AUTH_TRUNCATE,
                ES_EVENT_TYPE_AUTH_LINK,
                ES_EVENT_TYPE_AUTH_CLONE,
                ES_EVENT_TYPE_AUTH_UNLINK,
                ES_EVENT_TYPE_AUTH_RENAME,
                ES_EVENT_TYPE_AUTH_UIPC_CONNECT
            ]
        case .selfProtection:
            return [
                ES_EVENT_TYPE_AUTH_SIGNAL,
                ES_EVENT_TYPE_AUTH_GET_TASK,
                ES_EVENT_TYPE_AUTH_PROC_SUSPEND_RESUME,
                ES_EVENT_TYPE_AUTH_OPEN,
                ES_EVENT_TYPE_AUTH_UNLINK,
                ES_EVENT_TYPE_AUTH_RENAME
            ]
        }
    }

    static func mapClientError(_ result: es_new_client_result_t) -> GrdrEsClientState {
        switch result {
        case ES_NEW_CLIENT_RESULT_SUCCESS: return .active
        case ES_NEW_CLIENT_RESULT_ERR_NOT_ENTITLED: return .missingEntitlement
        case ES_NEW_CLIENT_RESULT_ERR_TOO_MANY_CLIENTS: return .tooManyClients
        case ES_NEW_CLIENT_RESULT_ERR_NOT_PERMITTED: return .notPermittedFda
        default: return .internalError
        }
    }

    static func synthesizeAuditToken(pid: UInt32, pidversion: UInt32, uid: UInt32) -> audit_token_t {
        var token = audit_token_t()
        withUnsafeMutableBytes(of: &token) { raw in
            let words = raw.bindMemory(to: UInt32.self)
            if words.count >= 8 {
                words[1] = uid
                words[5] = pid
                words[7] = pidversion
            }
        }
        return token
    }

    static func elapsedMilliseconds(since startMach: UInt64, timebase: mach_timebase_info_data_t) -> UInt64 {
        let now = mach_absolute_time()
        let delta = now > startMach ? (now - startMach) : 0
        let ns = (delta &* UInt64(timebase.numer)) / UInt64(max(1, timebase.denom))
        return ns / 1_000_000
    }

    static func unmutePidInTreeClients(
        message: UnsafePointer<es_message_t>,
        execClient: OpaquePointer?,
        recorderClient: OpaquePointer?
    ) {
        let msg = message.pointee
        var targetToken: audit_token_t?
        if msg.event_type == ES_EVENT_TYPE_AUTH_EXEC {
            targetToken = msg.event.exec.target.pointee.audit_token
        } else if msg.event_type == ES_EVENT_TYPE_NOTIFY_FORK {
            targetToken = msg.event.fork.child.pointee.audit_token
        }
        guard var tok = targetToken else {
            return
        }
        if let c = execClient {
            _ = es_unmute_process(c, &tok)
        }
        if let c = recorderClient {
            _ = es_unmute_process(c, &tok)
        }
    }

    static func encodeLiveMemberDeltas(_ entries: [GrdrEsLiveMemberEntry]) -> [Data] {
        entries.map { entry in
            GrdrEsTelemetryCodec.encodeTreeDeltaRecord(
                kindCode: UInt8(GRDR_MAC_ES_REGISTER_ROOT.rawValue),
                actorPid: entry.pid,
                actorPidver: entry.pidversion,
                actorUid: entry.uid,
                targetPid: entry.pid,
                targetPidver: entry.pidversion,
                targetUid: entry.uid,
                sessionId: entry.sessionId,
                agentName: entry.agentName,
                path: ""
            )
        }
    }

    static func lookupAuditToken(
        follower: OpaquePointer,
        pid: UInt32,
        pidversion: UInt32
    ) -> (governed: Bool, sessionId: String, agentName: String) {
        var out = GrdrMacTokenLookupOutC()
        let rc = grdr_macos_follower_lookup_token(follower, pid, pidversion, &out)
        guard rc == GRDR_MAC_FFI_OK.rawValue, out.governed != 0 else {
            return (false, "", "")
        }
        let sid = withUnsafeBytes(of: out.session_id) { String(decoding: $0.prefix(Int(out.session_id_len)), as: UTF8.self) }
        let agent = withUnsafeBytes(of: out.agent_name) { String(decoding: $0.prefix(Int(out.agent_name_len)), as: UTF8.self) }
        return (true, sid, agent)
    }

    static func registerRoot(
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
                var ev = GrdrEsEventAdapter.emptyEsEvent(
                    kindCode: UInt8(GRDR_MAC_ES_REGISTER_ROOT.rawValue),
                    concernCode: GrdrEsConcern.execAuthorizer.concernCode
                )
                ev.actor.key = GrdrMacProcessKeyC(pid: pid, pidversion: pidversion)
                ev.actor.uid = uid
                ev.session_id_ptr = sidBuf.bindMemory(to: UInt8.self).baseAddress
                ev.session_id_len = sidBuf.count
                ev.agent_name_ptr = agentBuf.bindMemory(to: UInt8.self).baseAddress
                ev.agent_name_len = agentBuf.count
                var verdict = GrdrMacEsVerdictC()
                return grdr_macos_eval_es_event_c(follower, &ev, nil, 0, &verdict) == GRDR_MAC_FFI_OK.rawValue
            }
        }
    }

    static func buildTelemetryEvent(
        seqNum: UInt64,
        concern: GrdrEsConcern,
        kindCode: UInt8,
        message: UnsafePointer<es_message_t>,
        targetPath: String,
        verdict: GrdrMacEsVerdictC
    ) -> GrdrEsTelemetryEvent {
        let tok = message.pointee.process.pointee.audit_token
        let sid = withUnsafeBytes(of: verdict.session_id) { raw in
            String(decoding: raw.prefix(Int(verdict.session_id_len)), as: UTF8.self)
        }
        let ruleId = withUnsafeBytes(of: verdict.matched_rule_id) { raw in
            String(decoding: raw.prefix(Int(verdict.matched_rule_id_len)), as: UTF8.self)
        }
        return GrdrEsTelemetryEvent(
            seqNum: seqNum,
            concernCode: concern.concernCode,
            concern: concern.rawValue,
            kindCode: kindCode,
            pid: UInt32(max(0, audit_token_to_pid(tok))),
            pidversion: UInt32(max(0, audit_token_to_pidversion(tok))),
            sessionId: sid,
            actionClassCode: verdict.action_class_code,
            verdictCode: verdict.verdict_code,
            tamperAlert: verdict.tamper_alert != 0,
            synthesizedDeniedExec: verdict.synthesized_denied_exec != 0,
            targetPath: targetPath,
            matchedRuleId: ruleId
        )
    }

    static func registerGuardPath(follower: OpaquePointer, path: String, isSelfPath: Bool) -> Bool {
        let data = Data(path.utf8)
        return data.withUnsafeBytes { buf in
            let ptr = buf.bindMemory(to: UInt8.self).baseAddress
            let rc = isSelfPath
                ? grdr_macos_follower_add_self_path(follower, ptr, buf.count)
                : grdr_macos_follower_add_protected_path(follower, ptr, buf.count)
            return rc == GRDR_MAC_FFI_OK.rawValue
        }
    }

    static func insertRootMember(
        _ members: inout [UInt64: GrdrEsLiveMemberEntry],
        maxMembers: Int,
        pid: UInt32,
        pidversion: UInt32,
        uid: UInt32,
        sessionId: String,
        agentName: String
    ) -> Data {
        let key = GrdrEsEventAdapter.processKey(pid: pid, pidversion: pidversion)
        if members[key] == nil && members.count >= maxMembers, let firstKey = members.keys.first {
            members.removeValue(forKey: firstKey)
        }
        members[key] = GrdrEsLiveMemberEntry(
            pid: pid,
            pidversion: pidversion,
            uid: uid,
            sessionId: sessionId,
            agentName: agentName
        )
        return GrdrEsTelemetryCodec.encodeTreeDeltaRecord(
            kindCode: UInt8(GRDR_MAC_ES_REGISTER_ROOT.rawValue),
            actorPid: pid,
            actorPidver: pidversion,
            actorUid: uid,
            targetPid: pid,
            targetPidver: pidversion,
            targetUid: uid,
            sessionId: sessionId,
            agentName: agentName,
            path: ""
        )
    }

    static func updateLiveMembers(
        _ members: inout [UInt64: GrdrEsLiveMemberEntry],
        maxMembers: Int,
        message: UnsafePointer<es_message_t>,
        eval: EsEvaluatedMessage
    ) {
        let evType = message.pointee.event_type
        if evType == ES_EVENT_TYPE_NOTIFY_EXIT {
            members.removeValue(forKey: eval.actorKey)
            return
        }
        guard eval.treeDeltaRecord != nil else {
            return
        }
        let sid = withUnsafeBytes(of: eval.verdict.session_id) { raw in
            String(decoding: raw.prefix(Int(eval.verdict.session_id_len)), as: UTF8.self)
        }
        guard !sid.isEmpty else {
            return
        }
        if evType == ES_EVENT_TYPE_NOTIFY_EXEC && eval.actorKey != eval.targetKey {
            members.removeValue(forKey: eval.actorKey)
        }
        if members[eval.targetKey] == nil && members.count >= maxMembers, let oldest = members.keys.first {
            members.removeValue(forKey: oldest)
        }
        members[eval.targetKey] = GrdrEsLiveMemberEntry(
            pid: eval.targetPid,
            pidversion: eval.targetPidVersion,
            uid: eval.targetUid,
            sessionId: sid,
            agentName: ""
        )
    }
}
#endif
