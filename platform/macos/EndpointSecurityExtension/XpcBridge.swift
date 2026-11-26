// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors

#if os(macOS)
import Foundation
import GrdrSensorMacOSBridge

@objc public protocol GrdrSensorXpcProtocol {
    func ping(reply: @escaping (Bool) -> Void)
    func fetchAbiVersion(reply: @escaping (UInt32) -> Void)
}

public final class GrdrSensorXpcListener: NSObject, NSXPCListenerDelegate, GrdrSensorXpcProtocol {
    private let listener: NSXPCListener
    private let expectedTeamId: String

    public init(machServiceName: String, expectedTeamId: String) {
        self.listener = NSXPCListener(machServiceName: machServiceName)
        self.expectedTeamId = expectedTeamId
        super.init()
        self.listener.delegate = self
    }

    public func resume() {
        listener.resume()
    }

    public func listener(
        _ listener: NSXPCListener,
        shouldAcceptNewConnection newConnection: NSXPCConnection
    ) -> Bool {
        guard Self.isValidAppleTeamId(expectedTeamId) else {
            return false
        }
        let requirement =
            "anchor apple generic and identifier like \"com.guardrailshq.grdr.*\" and certificate leaf[subject.OU] = \"\(expectedTeamId)\""
        newConnection.setCodeSigningRequirement(requirement)
        newConnection.exportedInterface = NSXPCInterface(with: GrdrSensorXpcProtocol.self)
        newConnection.exportedObject = self
        newConnection.resume()
        return true
    }

    public func ping(reply: @escaping (Bool) -> Void) {
        reply(true)
    }

    public func fetchAbiVersion(reply: @escaping (UInt32) -> Void) {
        reply(grdr_macos_abi_version())
    }

    private static func isValidAppleTeamId(_ teamId: String) -> Bool {
        return teamId.range(of: "^[A-Z0-9]{10}$", options: .regularExpression) != nil
    }
}
#endif
