// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors

#if os(macOS)
import Foundation
import NetworkExtension

public final class GrdrDNSProxyProvider: NEDNSProxyProvider {
    public override func startProxy(
        options: [String: Any]? = nil,
        completionHandler: @escaping (Error?) -> Void
    ) {
        completionHandler(nil)
    }

    public override func stopProxy(
        with reason: NEProviderStopReason,
        completionHandler: @escaping () -> Void
    ) {
        completionHandler()
    }

    public override func handleNewFlow(_ flow: NEAppProxyFlow) -> Bool {
        // Opt-in pass-through DNS proxy only when slot broker confirms slot is free.
        return false
    }
}
#endif
