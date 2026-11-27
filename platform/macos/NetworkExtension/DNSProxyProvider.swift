// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors

#if os(macOS)
import Darwin.bsm
import Foundation
import Network
import NetworkExtension
import GrdrSensorMacOSBridge

public struct GrdrDnsObservation: Sendable {
    public let domain: String
    public let resolvedIps: [String]
    public let ttlSeconds: UInt32
    public let agentName: String
    public let governed: Bool
}

public final class DnsTcpFrameAccumulator: @unchecked Sendable {
    private static let maxBufferBytes: Int = 131_072
    private var buffer = Data()

    public init() {}

    public func appendAndExtractFrames(_ chunk: Data) -> [Data] {
        guard !chunk.isEmpty else {
            return []
        }
        if buffer.count + chunk.count > Self.maxBufferBytes {
            buffer.removeAll(keepingCapacity: false)
            return []
        }
        buffer.append(chunk)
        var frames: [Data] = []
        while buffer.count >= 2 {
            let base = buffer.startIndex
            let b0 = buffer[base]
            let b1 = buffer[buffer.index(after: base)]
            let len = (Int(b0) << 8) | Int(b1)
            if len == 0 {
                buffer.removeAll(keepingCapacity: false)
                break
            }
            guard buffer.count >= (2 + len) else {
                break
            }
            let payloadStart = buffer.index(base, offsetBy: 2)
            let payloadEnd = buffer.index(payloadStart, offsetBy: len)
            frames.append(Data(buffer[payloadStart..<payloadEnd]))
            buffer = Data(buffer[payloadEnd...])
        }
        return frames
    }
}

public final class GrdrDNSProxyProvider: NEDNSProxyProvider, @unchecked Sendable {
    private let hub = GrdrNeProviderHub.shared
    private var relayQueue: DispatchQueue = DispatchQueue(label: "dns-proxy")
    public var onDnsObserved: (@Sendable (GrdrDnsObservation) -> Void)?

    public func attachFollower(_ follower: OpaquePointer?) {
        hub.attachFollower(follower)
    }

    public func configureUpstreamResolver(host: String, port: UInt16) {
        hub.configureUpstreamResolver(host: host, port: port)
    }

    public func lookupCachedDomain(ipAddress: String) -> String? {
        return hub.lookupCachedDomain(ipAddress: ipAddress)
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
                relayQueue = DispatchQueue(label: "\(prefix)ne.dns-proxy")
            }
        }
        if let host = options?["upstream_dns_host"] as? String, !host.isEmpty {
            let port = (options?["upstream_dns_port"] as? NSNumber)?.uint16Value ?? 53
            hub.configureUpstreamResolver(host: host, port: port > 0 ? port : 53)
        }
        completionHandler(nil)
    }

    public override func stopProxy(
        with reason: NEProviderStopReason,
        completionHandler: @escaping () -> Void
    ) {
        hub.clearDomainCache()
        completionHandler()
    }

    public override func handleNewFlow(_ flow: NEAppProxyFlow) -> Bool {
        let lineage = hub.lookupLineage(auditTokenData: flow.metaData.sourceAppAuditToken)
        let attribution = (governed: lineage.governed, agentName: lineage.agentName)
        if let udpFlow = flow as? NEAppProxyUDPFlow {
            udpFlow.open(withLocalEndpoint: nil) { [weak self] openError in
                if openError != nil {
                    udpFlow.closeReadWithError(openError)
                    udpFlow.closeWriteWithError(openError)
                    return
                }
                self?.pumpUdpDnsFlow(udpFlow: udpFlow, attribution: attribution)
            }
            return true
        }
        if let tcpFlow = flow as? NEAppProxyTCPFlow {
            let fallback = hub.upstreamResolver()
            guard let targetEndpoint = tcpFlow.remoteEndpoint as? NWHostEndpoint,
                  let targetPort = NWEndpoint.Port(rawValue: UInt16(targetEndpoint.port) ?? fallback.port)
            else {
                return false
            }
            let conn = NWConnection(
                host: NWEndpoint.Host(targetEndpoint.hostname.isEmpty ? fallback.host : targetEndpoint.hostname),
                port: targetPort,
                using: .tcp
            )
            let clientFramer = DnsTcpFrameAccumulator()
            let serverFramer = DnsTcpFrameAccumulator()
            conn.stateUpdateHandler = { [weak self] state in
                switch state {
                case .ready:
                    tcpFlow.open(withLocalEndpoint: nil) { err in
                        if let err = err {
                            conn.cancel()
                            tcpFlow.closeReadWithError(err)
                            tcpFlow.closeWriteWithError(err)
                            return
                        }
                        self?.pumpTcpFlowToConn(tcpFlow: tcpFlow, conn: conn, framer: clientFramer, attribution: attribution)
                        self?.pumpTcpConnToFlow(tcpFlow: tcpFlow, conn: conn, framer: serverFramer, attribution: attribution)
                    }
                case .failed(let err):
                    tcpFlow.closeReadWithError(err)
                    tcpFlow.closeWriteWithError(err)
                case .cancelled:
                    tcpFlow.closeReadWithError(nil)
                    tcpFlow.closeWriteWithError(nil)
                default:
                    break
                }
            }
            conn.start(queue: relayQueue)
            return true
        }
        return false
    }

    private func pumpUdpDnsFlow(
        udpFlow: NEAppProxyUDPFlow,
        attribution: (governed: Bool, agentName: String)
    ) {
        udpFlow.readDatagrams { [weak self] datagrams, endpoints, readErr in
            guard let self = self else {
                return
            }
            if let readErr = readErr {
                udpFlow.closeReadWithError(readErr)
                udpFlow.closeWriteWithError(readErr)
                return
            }
            guard let datagrams = datagrams, let endpoints = endpoints, !datagrams.isEmpty else {
                udpFlow.closeReadWithError(nil)
                udpFlow.closeWriteWithError(nil)
                return
            }
            for idx in 0..<min(datagrams.count, endpoints.count) {
                let queryData = datagrams[idx]
                let destEndpoint = endpoints[idx]
                _ = self.parseAndRecordDnsPacket(queryData, attribution: attribution)
                self.forwardUdpDnsQuery(
                    queryData: queryData,
                    originalEndpoint: destEndpoint,
                    udpFlow: udpFlow,
                    attribution: attribution
                )
            }
            self.pumpUdpDnsFlow(udpFlow: udpFlow, attribution: attribution)
        }
    }

    private func forwardUdpDnsQuery(
        queryData: Data,
        originalEndpoint: NWEndpoint,
        udpFlow: NEAppProxyUDPFlow,
        attribution: (governed: Bool, agentName: String)
    ) {
        let fallback = hub.upstreamResolver()
        let hostStr: String
        let portNum: UInt16
        if let nwHost = originalEndpoint as? NWHostEndpoint, !nwHost.hostname.isEmpty {
            hostStr = nwHost.hostname
            portNum = UInt16(nwHost.port) ?? fallback.port
        } else {
            hostStr = fallback.host
            portNum = fallback.port
        }
        guard let port = NWEndpoint.Port(rawValue: portNum) else {
            return
        }
        let conn = NWConnection(host: NWEndpoint.Host(hostStr), port: port, using: .udp)
        conn.stateUpdateHandler = { [weak self] state in
            switch state {
            case .ready:
                conn.send(content: queryData, completion: .contentProcessed { sendErr in
                    if sendErr != nil {
                        conn.cancel()
                        return
                    }
                    conn.receiveMessage { respData, _, _, recvErr in
                        defer { conn.cancel() }
                        guard recvErr == nil, let resp = respData, !resp.isEmpty else {
                            return
                        }
                        _ = self?.parseAndRecordDnsPacket(resp, attribution: attribution)
                        udpFlow.writeDatagrams([resp], sentBy: [originalEndpoint]) { _ in }
                    }
                })
            case .failed:
                conn.cancel()
            default:
                break
            }
        }
        conn.start(queue: relayQueue)
    }

    private func pumpTcpFlowToConn(
        tcpFlow: NEAppProxyTCPFlow,
        conn: NWConnection,
        framer: DnsTcpFrameAccumulator,
        attribution: (governed: Bool, agentName: String)
    ) {
        tcpFlow.readData { [weak self] data, err in
            if let err = err {
                conn.cancel()
                tcpFlow.closeWriteWithError(err)
                return
            }
            guard let data = data, !data.isEmpty else {
                conn.send(content: nil, contentContext: .finalMessage, isComplete: true, completion: .contentProcessed { _ in })
                return
            }
            for frame in framer.appendAndExtractFrames(data) {
                _ = self?.parseAndRecordDnsPacket(frame, attribution: attribution)
            }
            conn.send(content: data, completion: .contentProcessed { sendErr in
                if sendErr != nil {
                    conn.cancel()
                    tcpFlow.closeReadWithError(sendErr)
                    return
                }
                self?.pumpTcpFlowToConn(tcpFlow: tcpFlow, conn: conn, framer: framer, attribution: attribution)
            })
        }
    }

    private func pumpTcpConnToFlow(
        tcpFlow: NEAppProxyTCPFlow,
        conn: NWConnection,
        framer: DnsTcpFrameAccumulator,
        attribution: (governed: Bool, agentName: String)
    ) {
        conn.receive(minimumIncompleteLength: 1, maximumLength: 65_536) { [weak self] data, _, isComplete, err in
            if let err = err {
                conn.cancel()
                tcpFlow.closeWriteWithError(err)
                return
            }
            if let data = data, !data.isEmpty {
                for frame in framer.appendAndExtractFrames(data) {
                    _ = self?.parseAndRecordDnsPacket(frame, attribution: attribution)
                }
                tcpFlow.write(data) { writeErr in
                    if writeErr != nil {
                        conn.cancel()
                        tcpFlow.closeReadWithError(writeErr)
                        return
                    }
                    if isComplete {
                        tcpFlow.closeWriteWithError(nil)
                    } else {
                        self?.pumpTcpConnToFlow(tcpFlow: tcpFlow, conn: conn, framer: framer, attribution: attribution)
                    }
                }
            } else if isComplete {
                tcpFlow.closeWriteWithError(nil)
            }
        }
    }

    private func parseAndRecordDnsPacket(
        _ rawBytes: Data,
        attribution: (governed: Bool, agentName: String)
    ) -> String? {
        var dnsOut = GrdrMacDnsParseOutC()
        let rc: Int32 = rawBytes.withUnsafeBytes { buf in
            let ptr = buf.bindMemory(to: UInt8.self).baseAddress
            return grdr_macos_parse_dns_packet_c(ptr, buf.count, &dnsOut)
        }
        guard rc == GRDR_MAC_FFI_OK.rawValue else {
            return nil
        }
        let qname = withUnsafeBytes(of: dnsOut.qname) { raw in
            String(decoding: raw.prefix(Int(dnsOut.qname_len)), as: UTF8.self)
        }
        guard !qname.isEmpty else {
            return nil
        }
        if dnsOut.is_response != 0 && dnsOut.ip_count > 0 {
            let ips = decodeResolvedIps(out: dnsOut)
            let ttl = max(1, min(86_400, dnsOut.min_ttl_secs))
            hub.recordResolvedIps(ips, domain: qname, ttl: ttl)
            onDnsObserved?(GrdrDnsObservation(
                domain: qname,
                resolvedIps: ips,
                ttlSeconds: ttl,
                agentName: attribution.agentName,
                governed: attribution.governed
            ))
        }
        return qname
    }

    private func decodeResolvedIps(out: GrdrMacDnsParseOutC) -> [String] {
        var ips: [String] = []
        let count = min(Int(out.ip_count), 8)
        let families: [UInt8] = withUnsafeBytes(of: out.ip_families) { Array($0.prefix(8)) }
        withUnsafeBytes(of: out.ips) { raw in
            guard let basePtr = raw.baseAddress else {
                return
            }
            for idx in 0..<count {
                let offset = idx * 16
                guard offset + 16 <= raw.count else {
                    break
                }
                if families[idx] == 4 {
                    var addr = in_addr()
                    memcpy(&addr, basePtr.advanced(by: offset), 4)
                    var buf = [CChar](repeating: 0, count: Int(INET_ADDRSTRLEN))
                    if inet_ntop(AF_INET, &addr, &buf, socklen_t(INET_ADDRSTRLEN)) != nil {
                        ips.append(String(cString: buf))
                    }
                } else if families[idx] == 6 {
                    var addr6 = in6_addr()
                    memcpy(&addr6, basePtr.advanced(by: offset), 16)
                    var buf = [CChar](repeating: 0, count: Int(INET6_ADDRSTRLEN))
                    if inet_ntop(AF_INET6, &addr6, &buf, socklen_t(INET6_ADDRSTRLEN)) != nil {
                        ips.append(String(cString: buf))
                    }
                }
            }
        }
        return ips
    }
}
#endif
