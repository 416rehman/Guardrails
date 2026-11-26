// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors

#if os(macOS)
import Foundation
import Network
import NetworkExtension

public final class GrdrTransparentProxyProvider: NETransparentProxyProvider {
    private static let loopbackProxyPort: UInt16 = 18080
    private var modelHostSuffixes: [String] = []
    private let relayQueue = DispatchQueue(label: "com.guardrailshq.grdr.ne.proxy-relay")

    public override func startProxy(
        options: [String: Any]? = nil,
        completionHandler: @escaping (Error?) -> Void
    ) {
        if let configured = options?["model_host_suffixes"] as? [String] {
            modelHostSuffixes = configured
                .map { $0.lowercased().trimmingCharacters(in: CharacterSet(charactersIn: ".")) }
                .filter { !$0.isEmpty }
        }
        let rule = NENetworkRule(
            remoteNetwork: nil,
            remotePrefix: 0,
            localNetwork: nil,
            localPrefix: 0,
            protocol: .TCP,
            direction: .outbound
        )
        let settings = NETransparentProxyNetworkSettings(tunnelRemoteAddress: "127.0.0.1")
        settings.includedNetworkRules = [rule]
        setTunnelNetworkSettings(settings, completionHandler: completionHandler)
    }

    public override func stopProxy(
        with reason: NEProviderStopReason,
        completionHandler: @escaping () -> Void
    ) {
        completionHandler()
    }

    public override func handleNewFlow(_ flow: NEAppProxyFlow) -> Bool {
        guard let tcpFlow = flow as? NEAppProxyTCPFlow,
              let endpoint = tcpFlow.remoteEndpoint as? NWHostEndpoint,
              shouldInterceptModelHost(endpoint.hostname),
              let port = NWEndpoint.Port(rawValue: Self.loopbackProxyPort)
        else {
            return false
        }
        let connection = NWConnection(host: "127.0.0.1", port: port, using: .tcp)
        connection.stateUpdateHandler = { [weak self] state in
            switch state {
            case .ready:
                tcpFlow.open(withLocalEndpoint: nil) { error in
                    if let error = error {
                        connection.cancel()
                        tcpFlow.closeReadWithError(error)
                        tcpFlow.closeWriteWithError(error)
                        return
                    }
                    self?.pumpFlowToConnection(tcpFlow: tcpFlow, connection: connection)
                    self?.pumpConnectionToFlow(tcpFlow: tcpFlow, connection: connection)
                }
            case .failed(let error):
                tcpFlow.closeReadWithError(error)
                tcpFlow.closeWriteWithError(error)
            case .cancelled:
                tcpFlow.closeReadWithError(nil)
                tcpFlow.closeWriteWithError(nil)
            default:
                break
            }
        }
        connection.start(queue: relayQueue)
        return true
    }

    private func pumpFlowToConnection(tcpFlow: NEAppProxyTCPFlow, connection: NWConnection) {
        tcpFlow.readData { [weak self] data, error in
            if let error = error {
                connection.cancel()
                tcpFlow.closeWriteWithError(error)
                return
            }
            guard let data = data, !data.isEmpty else {
                connection.send(content: nil, contentContext: .finalMessage, isComplete: true, completion: .contentProcessed { _ in })
                return
            }
            connection.send(content: data, completion: .contentProcessed { sendErr in
                if sendErr != nil {
                    connection.cancel()
                    tcpFlow.closeReadWithError(sendErr)
                    return
                }
                self?.pumpFlowToConnection(tcpFlow: tcpFlow, connection: connection)
            })
        }
    }

    private func pumpConnectionToFlow(tcpFlow: NEAppProxyTCPFlow, connection: NWConnection) {
        connection.receive(minimumIncompleteLength: 1, maximumLength: 65536) { [weak self] data, _, isComplete, error in
            if let error = error {
                tcpFlow.closeWriteWithError(error)
                connection.cancel()
                return
            }
            if let data = data, !data.isEmpty {
                tcpFlow.write(data) { writeErr in
                    if writeErr != nil {
                        connection.cancel()
                        tcpFlow.closeReadWithError(writeErr)
                        return
                    }
                    if isComplete {
                        tcpFlow.closeWriteWithError(nil)
                    } else {
                        self?.pumpConnectionToFlow(tcpFlow: tcpFlow, connection: connection)
                    }
                }
            } else if isComplete {
                tcpFlow.closeWriteWithError(nil)
            }
        }
    }

    private func shouldInterceptModelHost(_ host: String) -> Bool {
        let lower = host.lowercased().trimmingCharacters(in: CharacterSet(charactersIn: "."))
        return modelHostSuffixes.contains { bare in
            lower == bare || lower.hasSuffix(".\(bare)")
        }
    }
}
#endif
