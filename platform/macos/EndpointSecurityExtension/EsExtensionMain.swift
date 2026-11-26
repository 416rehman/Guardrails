// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors

#if os(macOS)
import Foundation
import EndpointSecurity

public enum GrdrEsExtensionBootstrap {
    private static let lock = NSLock()
    private static var activeCoordinator: GrdrEsTreeCoordinator?

    public static func start(mutedTeamIds: [String]) -> Int32 {
        lock.lock()
        defer { lock.unlock() }
        activeCoordinator?.stop()
        let coordinator = GrdrEsTreeCoordinator()
        let result = coordinator.startClients(mutedTeamIds: mutedTeamIds)
        if result == ES_NEW_CLIENT_RESULT_SUCCESS {
            activeCoordinator = coordinator
            return 0
        }
        coordinator.stop()
        activeCoordinator = nil
        return -1
    }

    public static func stop() {
        lock.lock()
        defer { lock.unlock() }
        activeCoordinator?.stop()
        activeCoordinator = nil
    }
}
#endif
