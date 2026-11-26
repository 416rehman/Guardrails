// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors

#if os(macOS)
import Darwin.bsm
import EndpointSecurity
import Foundation
import GrdrSensorMacOSBridge

public final class GrdrEsTreeCoordinator {
    private var follower: OpaquePointer?
    private var authExecClient: OpaquePointer?
    private let queue = DispatchQueue(label: "com.guardrailshq.grdr.es.coordinator")
    private let policyLock = NSLock()
    private var floorRulesJson: Data = Data("[]".utf8)
    private var defaultDeny: UInt8 = 1

    public init() {
        follower = grdr_macos_follower_new()
    }

    deinit {
        stop()
        let staleFollower: OpaquePointer? = queue.sync {
            let current = follower
            follower = nil
            return current
        }
        if let f = staleFollower {
            grdr_macos_follower_free(f)
        }
    }

    public func configureExecFloorPolicy(rulesJson: Data, defaultDeny: Bool) {
        policyLock.lock()
        floorRulesJson = rulesJson
        self.defaultDeny = defaultDeny ? 1 : 0
        policyLock.unlock()
    }

    public func stop() {
        let clientToDelete: OpaquePointer? = queue.sync {
            let active = authExecClient
            authExecClient = nil
            return active
        }
        if let client = clientToDelete {
            _ = es_unsubscribe_all(client)
            es_delete_client(client)
        }
    }

    public func startClients(mutedTeamIds: [String]) -> es_new_client_result_t {
        stop()
        let followerPtr: OpaquePointer? = queue.sync { follower }
        if let f = followerPtr {
            for team in mutedTeamIds where !team.isEmpty {
                let teamData = Data(team.utf8)
                teamData.withUnsafeBytes { buf in
                    let ptr = buf.bindMemory(to: UInt8.self).baseAddress
                    if let outPtr = grdr_macos_follower_mute_team(f, ptr, buf.count) {
                        grdr_macos_free_string(outPtr)
                    }
                }
            }
        }

        var client: OpaquePointer?
        let status = es_new_client(&client) { [weak self] clientRef, message in
            self?.handleEsMessage(client: clientRef, message: message)
        }
        guard status == ES_NEW_CLIENT_RESULT_SUCCESS, let activeClient = client else {
            return status
        }

        let missRc = es_set_deadline_miss_mode(activeClient, ES_DEADLINE_MISS_MODE_FAIL_CLOSED)
        guard missRc == ES_RETURN_SUCCESS else {
            es_delete_client(activeClient)
            return ES_NEW_CLIENT_RESULT_ERR_INTERNAL
        }

        queue.sync {
            authExecClient = activeClient
        }
        let subscriptions: [es_event_type_t] = [
            ES_EVENT_TYPE_AUTH_EXEC,
            ES_EVENT_TYPE_NOTIFY_EXEC,
            ES_EVENT_TYPE_NOTIFY_FORK,
            ES_EVENT_TYPE_NOTIFY_EXIT
        ]
        let subRc = es_subscribe(activeClient, subscriptions, UInt32(subscriptions.count))
        guard subRc == ES_RETURN_SUCCESS else {
            queue.sync {
                if authExecClient == activeClient {
                    authExecClient = nil
                }
            }
            es_delete_client(activeClient)
            return ES_NEW_CLIENT_RESULT_ERR_INTERNAL
        }

        return ES_NEW_CLIENT_RESULT_SUCCESS
    }

    private func handleEsMessage(client: OpaquePointer, message: UnsafePointer<es_message_t>) {
        let msg = message.pointee
        es_retain_message(message)
        queue.async { [weak self] in
            defer { es_release_message(message) }
            guard let self = self, self.authExecClient == client else {
                return
            }
            guard let f = self.follower else {
                if msg.action_type == ES_ACTION_TYPE_AUTH {
                    _ = es_respond_auth_result(client, message, ES_AUTH_RESULT_DENY, false)
                }
                return
            }

            let authResult = self.dispatchToRust(follower: f, message: message)
            if msg.action_type == ES_ACTION_TYPE_AUTH {
                // Never enable cache on DENY; fail closed on errors or unmatched denials.
                _ = es_respond_auth_result(client, message, authResult, false)
            }
        }
    }

    private func dispatchToRust(
        follower f: OpaquePointer,
        message: UnsafePointer<es_message_t>
    ) -> es_auth_result_t {
        guard let payload = buildPayloadJson(message: message),
              let jsonData = try? JSONSerialization.data(withJSONObject: payload)
        else {
            return ES_AUTH_RESULT_DENY
        }

        let isAuthExec = (message.pointee.event_type == ES_EVENT_TYPE_AUTH_EXEC)
        policyLock.lock()
        let rulesSnapshot = floorRulesJson
        let denyFlag = defaultDeny
        policyLock.unlock()

        let rawResponse: String? = jsonData.withUnsafeBytes { eventBuf in
            let eventPtr = eventBuf.bindMemory(to: UInt8.self).baseAddress
            if isAuthExec {
                return rulesSnapshot.withUnsafeBytes { floorBuf in
                    let floorPtr = floorBuf.bindMemory(to: UInt8.self).baseAddress
                    guard let outPtr = grdr_macos_eval_es_auth_exec(
                        f,
                        eventPtr,
                        eventBuf.count,
                        floorPtr,
                        floorBuf.count,
                        denyFlag
                    ) else {
                        return nil
                    }
                    defer { grdr_macos_free_string(outPtr) }
                    return String(cString: outPtr)
                }
            } else {
                guard let outPtr = grdr_macos_apply_es_event(f, eventPtr, eventBuf.count) else {
                    return nil
                }
                defer { grdr_macos_free_string(outPtr) }
                return String(cString: outPtr)
            }
        }

        guard let responseStr = rawResponse,
              let respObj = try? JSONSerialization.jsonObject(with: Data(responseStr.utf8)) as? [String: Any],
              respObj["error"] == nil,
              let verdict = (respObj["verdict"] as? String)?.lowercased(),
              verdict == "allow"
        else {
            return ES_AUTH_RESULT_DENY
        }
        return ES_AUTH_RESULT_ALLOW
    }

    private func buildPayloadJson(message: UnsafePointer<es_message_t>) -> [String: Any]? {
        let msg = message.pointee
        let procPtr = msg.process
        let actorKey = keyJson(auditToken: procPtr.pointee.audit_token)
        switch msg.event_type {
        case ES_EVENT_TYPE_AUTH_EXEC:
            let targetPtr = msg.event.exec.target
            return [
                "event": "auth_exec",
                "old_key": actorKey,
                "target": auditTokenJson(process: targetPtr),
                "executable_path": stringFromEsToken(targetPtr.pointee.executable.pointee.path)
            ]
        case ES_EVENT_TYPE_NOTIFY_EXEC:
            let targetPtr = msg.event.exec.target
            return [
                "event": "notify_exec",
                "old_key": actorKey,
                "new_token": auditTokenJson(process: targetPtr),
                "executable_path": stringFromEsToken(targetPtr.pointee.executable.pointee.path)
            ]
        case ES_EVENT_TYPE_NOTIFY_FORK:
            let childPtr = msg.event.fork.child
            return [
                "event": "notify_fork",
                "parent": actorKey,
                "child": auditTokenJson(process: childPtr)
            ]
        case ES_EVENT_TYPE_NOTIFY_EXIT:
            return [
                "event": "notify_exit",
                "key": actorKey
            ]
        default:
            return nil
        }
    }

    private func keyJson(auditToken: audit_token_t) -> [String: Any] {
        let pid = UInt32(max(0, audit_token_to_pid(auditToken)))
        let pidver = UInt32(max(0, audit_token_to_pidversion(auditToken)))
        return ["pid": pid, "pidversion": pidver]
    }

    private func auditTokenJson(process: UnsafePointer<es_process_t>) -> [String: Any] {
        let tok = process.pointee.audit_token
        let uid = audit_token_to_euid(tok)
        let team = stringFromEsToken(process.pointee.team_id)
        return [
            "key": keyJson(auditToken: tok),
            "uid": uid,
            "team_id": team.isEmpty ? NSNull() : team
        ]
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
