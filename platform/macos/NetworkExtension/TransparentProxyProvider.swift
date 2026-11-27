// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors

#if os(macOS)
import Darwin.bsm
import Foundation
import Network
import NetworkExtension
import GrdrSensorMacOSBridge

public final class GrdrTransparentProxyProvider: NETransparentProxyProvider, @unchecked Sendable {
    private static let maxConnectHeaderBytes: Int = 8_192

    private let hub = GrdrNeProviderHub.shared
    private var relayQueue: DispatchQueue = DispatchQueue(label: "ne-proxy-relay")

    public func attachFollower(_ follower: OpaquePointer?) {
        hub.attachFollower(follower)
    }

    public func configureProxy(loopbackPort: UInt16, modelHostSuffixes: [String], proxyToken: String? = nil) {
        hub.configureProxy(loopbackPort: loopbackPort, modelHostSuffixes: modelHostSuffixes, proxyToken: proxyToken)
    }

    public override func startProxy(
        options: [String: Any]? = nil,
        completionHandler: @escaping (Error?) -> Void
    ) {
        hub.ensureSyncStarted()
        var brand = GrdrMacBrandInfoC()
        if grdr_macos_get_brand_info(&brand) == GRDR_MAC_FFI_OK.rawValue {
            let prefix = withUnsafeBytes(of: brand.own_prefix) { raw in
                String(decoding: raw.prefix(Int(brand.own_prefix_len)), as: UTF8.self)
            }
            if !prefix.isEmpty {
                relayQueue = DispatchQueue(label: "\(prefix)ne.proxy-relay")
            }
        }
        let optPort = (options?["loopback_proxy_port"] as? NSNumber)?.uint16Value ?? 0
        let optSuffixes = options?["model_host_suffixes"] as? [String] ?? []
        let optToken = options?["proxy_auth_token"] as? String
        if optPort > 0 || !optSuffixes.isEmpty || optToken != nil {
            let current = hub.policySnapshot()
            hub.configureProxy(
                loopbackPort: optPort > 0 ? optPort : current.loopbackProxyPort,
                modelHostSuffixes: optSuffixes.isEmpty ? current.modelHostSuffixes : optSuffixes,
                proxyToken: optToken
            )
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
        let snapshot = hub.policySnapshot()
        let lineage = hub.lookupLineage(auditTokenData: flow.metaData.sourceAppAuditToken)
        guard snapshot.loopbackProxyPort > 0,
              lineage.governed,
              let tcpFlow = flow as? NEAppProxyTCPFlow,
              let endpoint = tcpFlow.remoteEndpoint as? NWHostEndpoint,
              let port = NWEndpoint.Port(rawValue: snapshot.loopbackProxyPort)
        else {
            return false
        }

        let rawHost = endpoint.hostname
        guard isValidConnectHost(rawHost) else {
            return false
        }
        let effectiveHost = resolveEffectiveHostName(rawHost: rawHost)
        guard isValidConnectHost(effectiveHost),
              shouldInterceptModelHost(effectiveHost, customSuffixes: snapshot.modelHostSuffixes)
        else {
            return false
        }

        let destPort = UInt16(endpoint.port) ?? 443
        guard let connectRequest = buildConnectRequest(
            destHost: effectiveHost,
            destPort: destPort,
            proxyToken: snapshot.proxyAuthToken
        ) else {
            return false
        }

        let connection = NWConnection(host: "127.0.0.1", port: port, using: .tcp)
        connection.stateUpdateHandler = { [weak self] state in
            switch state {
            case .ready:
                self?.performConnectHandshake(
                    tcpFlow: tcpFlow,
                    connection: connection,
                    connectRequest: connectRequest
                )
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

    private func buildConnectRequest(destHost: String, destPort: UInt16, proxyToken: String) -> Data? {
        guard isValidConnectHost(destHost), destPort > 0 else {
            return nil
        }
        guard proxyToken.unicodeScalars.allSatisfy({ $0.value > 0x20 && $0.value < 0x7f }) else {
            return nil
        }
        let authorityHost = destHost.contains(":") ? "[\(destHost)]" : destHost
        let authority = "\(authorityHost):\(destPort)"
        var req = "CONNECT \(authority) HTTP/1.1\r\nHost: \(authority)\r\n"
        if !proxyToken.isEmpty {
            req += "X-Grdr-Instance-Token: \(proxyToken)\r\n"
        }
        req += "\r\n"
        return Data(req.utf8)
    }

    private func performConnectHandshake(
        tcpFlow: NEAppProxyTCPFlow,
        connection: NWConnection,
        connectRequest: Data
    ) {
        connection.send(content: connectRequest, completion: .contentProcessed { [weak self] sendErr in
            guard let self = self else {
                connection.cancel()
                return
            }
            if let sendErr = sendErr {
                connection.cancel()
                tcpFlow.closeReadWithError(sendErr)
                tcpFlow.closeWriteWithError(sendErr)
                return
            }
            self.readConnectResponse(
                tcpFlow: tcpFlow,
                connection: connection,
                accumulated: Data()
            )
        })
    }

    private func readConnectResponse(
        tcpFlow: NEAppProxyTCPFlow,
        connection: NWConnection,
        accumulated: Data
    ) {
        connection.receive(minimumIncompleteLength: 1, maximumLength: Self.maxConnectHeaderBytes) { [weak self] data, _, isComplete, err in
            guard let self = self else {
                connection.cancel()
                return
            }
            if let err = err {
                connection.cancel()
                tcpFlow.closeReadWithError(err)
                tcpFlow.closeWriteWithError(err)
                return
            }
            var buffer = accumulated
            if let data = data {
                buffer.append(data)
            }
            if buffer.count > Self.maxConnectHeaderBytes {
                connection.cancel()
                let overflowErr = NSError(domain: "grdr.netext", code: 431)
                tcpFlow.closeReadWithError(overflowErr)
                tcpFlow.closeWriteWithError(overflowErr)
                return
            }
            let delimiter = Data([0x0D, 0x0A, 0x0D, 0x0A])
            if let headerRange = buffer.range(of: delimiter) {
                let headerStr = String(decoding: buffer[..<headerRange.lowerBound], as: UTF8.self)
                let firstLine = String(headerStr.split(separator: "\r\n", maxSplits: 1).first ?? "")
                guard Self.isValidHttp200StatusLine(firstLine) else {
                    connection.cancel()
                    let rejectErr = NSError(domain: "grdr.netext", code: 502)
                    tcpFlow.closeReadWithError(rejectErr)
                    tcpFlow.closeWriteWithError(rejectErr)
                    return
                }
                let residual = Data(buffer[headerRange.upperBound...])
                tcpFlow.open(withLocalEndpoint: nil) { openErr in
                    if let openErr = openErr {
                        connection.cancel()
                        tcpFlow.closeReadWithError(openErr)
                        tcpFlow.closeWriteWithError(openErr)
                        return
                    }
                    if !residual.isEmpty {
                        tcpFlow.write(residual) { writeErr in
                            if let writeErr = writeErr {
                                connection.cancel()
                                tcpFlow.closeReadWithError(writeErr)
                                return
                            }
                            self.pumpFlowToConnection(tcpFlow: tcpFlow, connection: connection)
                            self.pumpConnectionToFlow(tcpFlow: tcpFlow, connection: connection)
                        }
                    } else {
                        self.pumpFlowToConnection(tcpFlow: tcpFlow, connection: connection)
                        self.pumpConnectionToFlow(tcpFlow: tcpFlow, connection: connection)
                    }
                }
                return
            }
            if isComplete {
                connection.cancel()
                tcpFlow.closeReadWithError(nil)
                tcpFlow.closeWriteWithError(nil)
                return
            }
            self.readConnectResponse(tcpFlow: tcpFlow, connection: connection, accumulated: buffer)
        }
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
        connection.receive(minimumIncompleteLength: 1, maximumLength: 65_536) { [weak self] data, _, isComplete, error in
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

    private func resolveEffectiveHostName(rawHost: String) -> String {
        if isIpLiteral(rawHost), let cached = hub.lookupCachedDomain(ipAddress: rawHost) {
            return cached
        }
        return rawHost
    }

    private func isIpLiteral(_ host: String) -> Bool {
        var v4 = in_addr()
        var v6 = in6_addr()
        return inet_pton(AF_INET, host, &v4) == 1 || inet_pton(AF_INET6, host, &v6) == 1
    }

    private func isValidConnectHost(_ host: String) -> Bool {
        guard !host.isEmpty, host.count <= 253 else {
            return false
        }
        guard host.unicodeScalars.allSatisfy({ $0.value > 0x20 && $0.value < 0x7f }) else {
            return false
        }
        if isIpLiteral(host) {
            return true
        }
        return host.unicodeScalars.allSatisfy { scalar in
            let v = scalar.value
            return (v >= 0x30 && v <= 0x39)
                || (v >= 0x41 && v <= 0x5A)
                || (v >= 0x61 && v <= 0x7A)
                || v == 0x2D
                || v == 0x2E
                || v == 0x5F
        }
    }

    private static func isValidHttp200StatusLine(_ line: String) -> Bool {
        return line == "HTTP/1.1 200"
            || line.hasPrefix("HTTP/1.1 200 ")
            || line == "HTTP/1.0 200"
            || line.hasPrefix("HTTP/1.0 200 ")
    }

    private func shouldInterceptModelHost(_ host: String, customSuffixes: [String]) -> Bool {
        let lower = host.lowercased().trimmingCharacters(in: CharacterSet(charactersIn: "."))
        guard !lower.isEmpty else {
            return false
        }
        for suffix in customSuffixes where lower == suffix || lower.hasSuffix(".\(suffix)") {
            return true
        }
        var matched: UInt8 = 0
        let data = Data(lower.utf8)
        let rc = data.withUnsafeBytes { buf in
            grdr_macos_match_model_host_c(buf.bindMemory(to: UInt8.self).baseAddress, buf.count, &matched)
        }
        return rc == GRDR_MAC_FFI_OK.rawValue && matched != 0
    }
}
#endif
