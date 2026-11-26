// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors

#if os(macOS)
import EndpointSecurity
import Foundation

public final class GrdrDescendantsSupervisor {
    private static let guardTailMs: UInt32 = 10_000
    private var client: OpaquePointer?

    deinit {
        stop()
    }

    public func stop() {
        if let c = client {
            _ = es_unsubscribe_all(c)
            es_delete_client(c)
            client = nil
        }
    }

    public func superviseSubtree(deadlineFloorMs: UInt32, failClosed: Bool) -> es_new_client_result_t {
        guard deadlineFloorMs > 0, deadlineFloorMs < (UInt32.max - Self.guardTailMs) else {
            return ES_NEW_CLIENT_RESULT_ERR_INVALID_ARGUMENT
        }
        stop()

        var newClient: OpaquePointer?
        let status = es_new_descendants_client(&newClient) { clientRef, message in
            if message.pointee.action_type == ES_ACTION_TYPE_AUTH {
                let fallback = failClosed ? ES_AUTH_RESULT_DENY : ES_AUTH_RESULT_ALLOW
                _ = es_respond_auth_result(clientRef, message, fallback, false)
            }
        }
        guard status == ES_NEW_CLIENT_RESULT_SUCCESS, let active = newClient else {
            return status
        }
        guard es_set_deadline_min_milliseconds(active, deadlineFloorMs) == ES_RETURN_SUCCESS else {
            es_delete_client(active)
            return ES_NEW_CLIENT_RESULT_ERR_INTERNAL
        }
        let missMode = failClosed
            ? ES_DEADLINE_MISS_MODE_FAIL_CLOSED
            : ES_DEADLINE_MISS_MODE_FAIL_OPEN
        guard es_set_deadline_miss_mode(active, missMode) == ES_RETURN_SUCCESS else {
            es_delete_client(active)
            return ES_NEW_CLIENT_RESULT_ERR_INTERNAL
        }
        client = active
        return ES_NEW_CLIENT_RESULT_SUCCESS
    }
}
#endif
