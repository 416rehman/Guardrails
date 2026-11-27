// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors

#if os(macOS)
import Darwin.bsm
import Foundation
import Network
import NetworkExtension
import GrdrSensorMacOSBridge

public final class GrdrFilterDataProvider: NEFilterDataProvider, @unchecked Sendable {
    private static let maxTlsPeekBytes: Int = 16_384

    private struct PendingFlowState {
        let pid: UInt32
        let pidversion: UInt32
        let agentName: String
        let host: String
        let port: UInt16
        var tlsBuffer: Data
    }

    private let flowLock = NSLock()
    private let hub = GrdrNeProviderHub.shared
    private var pendingFlowMeta: [ObjectIdentifier: PendingFlowState] = [:]

    public override init() {
        super.init()
    }

    public func attachFollower(_ follower: OpaquePointer?) {
        hub.attachFollower(follower)
    }

    public func configureBinaryFloorPolicy(tableBin: Data, defaultDeny: Bool) {
        hub.configureBinaryFloorPolicy(tableBin: tableBin, defaultDeny: defaultDeny)
    }

    public override func startFilter(completionHandler: @escaping (Error?) -> Void) {
        hub.ensureSyncStarted()
        completionHandler(nil)
    }

    public override func stopFilter(with reason: NEProviderStopReason, completionHandler: @escaping () -> Void) {
        flowLock.lock()
        pendingFlowMeta.removeAll()
        flowLock.unlock()
        completionHandler()
    }

    public override func handleNewFlow(_ flow: NEFilterFlow) -> NEFilterNewFlowVerdict {
        let snapshot = hub.policySnapshot()
        let fallbackVerdict: NEFilterNewFlowVerdict = (snapshot.defaultDeny != 0) ? .drop() : .allow()

        // Inspect NEFilterFlow audit token lineage BEFORE casting to NEFilterSocketFlow so non-socket agent flows fail closed cleanly.
        let flowToken = (flow as? NEFilterSocketFlow)?.sourceAppAuditToken ?? flow.sourceAppAuditToken
        let lineage = hub.lookupLineage(auditTokenData: flowToken)
        if !lineage.governed {
            return .allow()
        }

        guard let socketFlow = flow as? NEFilterSocketFlow else {
            return fallbackVerdict
        }

        let remoteHost = socketFlow.remoteEndpoint as? NWHostEndpoint
        let remotePort = UInt16(remoteHost?.port ?? "0") ?? 0
        let transportCode: UInt8 = (Int32(socketFlow.socketProtocol) == IPPROTO_UDP) ? 1 : 0
        let rawHost = (remoteHost?.hostname ?? "").trimmingCharacters(in: .whitespacesAndNewlines)
        let resolvedHost = resolveEffectiveHostName(rawHost: rawHost)

        // UDP/443 QUIC for governed processes is immediately dropped by Rust evaluator.
        if transportCode == 1 && remotePort == 443 {
            return evaluateVerdict(
                flowId: UInt64(bitPattern: Int64(flow.identifier.hashValue)),
                pid: lineage.pid,
                pidversion: lineage.pidversion,
                governed: true,
                transportCode: 1,
                remotePort: remotePort,
                hostName: resolvedHost,
                tlsSni: "",
                agentName: lineage.agentName,
                snapshot: snapshot,
                fallback: fallbackVerdict
            )
        }

        // For TCP outbound flows where hostname is missing or still an IP literal, peek multi-chunk ClientHello SNI.
        if transportCode == 0 && (resolvedHost.isEmpty || isIpLiteral(resolvedHost)) {
            flowLock.lock()
            pendingFlowMeta[ObjectIdentifier(flow)] = PendingFlowState(
                pid: lineage.pid,
                pidversion: lineage.pidversion,
                agentName: lineage.agentName,
                host: resolvedHost,
                port: remotePort,
                tlsBuffer: Data()
            )
            flowLock.unlock()
            return .filterDataVerdict(
                withFilterInbound: false,
                peekInboundBytes: 0,
                filterOutbound: true,
                peekOutboundBytes: Self.maxTlsPeekBytes
            )
        }

        return evaluateVerdict(
            flowId: UInt64(bitPattern: Int64(flow.identifier.hashValue)),
            pid: lineage.pid,
            pidversion: lineage.pidversion,
            governed: true,
            transportCode: transportCode,
            remotePort: remotePort,
            hostName: resolvedHost,
            tlsSni: "",
            agentName: lineage.agentName,
            snapshot: snapshot,
            fallback: fallbackVerdict
        )
    }

    public override func handleOutboundData(
        from flow: NEFilterFlow,
        readBytesStartOffset offset: Int,
        readBytes: Data
    ) -> NEFilterDataVerdict {
        let snapshot = hub.policySnapshot()
        let failClosedVerdict: NEFilterDataVerdict = (snapshot.defaultDeny != 0) ? .drop() : .allow()
        let flowKey = ObjectIdentifier(flow)

        flowLock.lock()
        guard var info = pendingFlowMeta[flowKey] else {
            flowLock.unlock()
            return failClosedVerdict
        }
        if offset == info.tlsBuffer.count && info.tlsBuffer.count < Self.maxTlsPeekBytes {
            let remaining = Self.maxTlsPeekBytes - info.tlsBuffer.count
            info.tlsBuffer.append(contentsOf: readBytes.prefix(remaining))
            pendingFlowMeta[flowKey] = info
        } else if offset == 0 && info.tlsBuffer.isEmpty {
            info.tlsBuffer = Data(readBytes.prefix(Self.maxTlsPeekBytes))
            pendingFlowMeta[flowKey] = info
        }
        let accumulated = info.tlsBuffer
        flowLock.unlock()

        var sniOut = GrdrMacTlsSniOutC()
        let peekRc: Int32 = accumulated.withUnsafeBytes { rawBuf in
            let ptr = rawBuf.bindMemory(to: UInt8.self).baseAddress
            return grdr_macos_peek_tls_sni_c(ptr, rawBuf.count, &sniOut)
        }

        if peekRc == GRDR_MAC_FFI_OK.rawValue && sniOut.status_code == UInt8(GRDR_MAC_TLS_SNI_NEED_MORE_BYTES.rawValue) {
            if accumulated.count < Self.maxTlsPeekBytes {
                return .needRules()
            }
        }

        flowLock.lock()
        pendingFlowMeta.removeValue(forKey: flowKey)
        flowLock.unlock()

        var extractedSni = ""
        if peekRc == GRDR_MAC_FFI_OK.rawValue && sniOut.status_code == UInt8(GRDR_MAC_TLS_SNI_FOUND.rawValue) {
            extractedSni = withUnsafeBytes(of: sniOut.sni) { raw in
                String(decoding: raw.prefix(Int(sniOut.sni_len)), as: UTF8.self)
            }
        }

        let effectiveHost = resolveEffectiveHostName(rawHost: info.host)
        guard let verdict = evaluateVerdictCode(
            flowId: UInt64(bitPattern: Int64(flow.identifier.hashValue)),
            pid: info.pid,
            pidversion: info.pidversion,
            governed: true,
            transportCode: 0,
            remotePort: info.port,
            hostName: effectiveHost,
            tlsSni: extractedSni,
            agentName: info.agentName,
            tableSnapshot: snapshot.floorTableBin,
            defaultDeny: snapshot.defaultDeny
        ) else {
            return failClosedVerdict
        }
        if verdict == UInt8(GRDR_MAC_VERDICT_DENY.rawValue) || verdict == UInt8(GRDR_MAC_VERDICT_STEP_UP.rawValue) {
            return .drop()
        }
        return .allow()
    }

    public override func handleOutboundDataComplete(for flow: NEFilterFlow) -> NEFilterDataVerdict {
        flowLock.lock()
        pendingFlowMeta.removeValue(forKey: ObjectIdentifier(flow))
        flowLock.unlock()
        return .allow()
    }

    private func resolveEffectiveHostName(rawHost: String) -> String {
        if rawHost.isEmpty || !isIpLiteral(rawHost) {
            return rawHost
        }
        return hub.lookupCachedDomain(ipAddress: rawHost) ?? rawHost
    }

    private func evaluateVerdict(
        flowId: UInt64,
        pid: UInt32,
        pidversion: UInt32,
        governed: Bool,
        transportCode: UInt8,
        remotePort: UInt16,
        hostName: String,
        tlsSni: String,
        agentName: String,
        snapshot: GrdrNePolicySnapshot,
        fallback: NEFilterNewFlowVerdict
    ) -> NEFilterNewFlowVerdict {
        guard let code = evaluateVerdictCode(
            flowId: flowId,
            pid: pid,
            pidversion: pidversion,
            governed: governed,
            transportCode: transportCode,
            remotePort: remotePort,
            hostName: hostName,
            tlsSni: tlsSni,
            agentName: agentName,
            tableSnapshot: snapshot.floorTableBin,
            defaultDeny: snapshot.defaultDeny
        ) else {
            return fallback
        }
        if code == UInt8(GRDR_MAC_VERDICT_DENY.rawValue) || code == UInt8(GRDR_MAC_VERDICT_STEP_UP.rawValue) {
            return .drop()
        }
        return .allow()
    }

    private func evaluateVerdictCode(
        flowId: UInt64,
        pid: UInt32,
        pidversion: UInt32,
        governed: Bool,
        transportCode: UInt8,
        remotePort: UInt16,
        hostName: String,
        tlsSni: String,
        agentName: String,
        tableSnapshot: Data,
        defaultDeny: UInt8
    ) -> UInt8? {
        let agentData = Data(agentName.utf8)
        let hostData = Data(hostName.utf8)
        let sniData = Data(tlsSni.utf8)

        return agentData.withUnsafeBytes { agentBuf in
            hostData.withUnsafeBytes { hostBuf in
                sniData.withUnsafeBytes { sniBuf in
                    tableSnapshot.withUnsafeBytes { binBuf in
                        var flowC = GrdrMacNeFlowC(
                            flow_id: flowId,
                            pid: pid,
                            pidversion: pidversion,
                            governed_process: governed ? 1 : 0,
                            transport_code: transportCode,
                            remote_port: remotePort,
                            default_deny: defaultDeny,
                            reserved: (0, 0, 0),
                            agent_name_ptr: agentBuf.bindMemory(to: UInt8.self).baseAddress,
                            agent_name_len: agentBuf.count,
                            host_name_ptr: hostBuf.bindMemory(to: UInt8.self).baseAddress,
                            host_name_len: hostBuf.count,
                            tls_sni_ptr: sniBuf.bindMemory(to: UInt8.self).baseAddress,
                            tls_sni_len: sniBuf.count
                        )
                        var verdictC = GrdrMacNeVerdictC()
                        let rc = grdr_macos_eval_ne_flow_bin_c(
                            &flowC,
                            binBuf.bindMemory(to: UInt8.self).baseAddress,
                            binBuf.count,
                            &verdictC
                        )
                        return (rc == GRDR_MAC_FFI_OK.rawValue) ? verdictC.verdict_code : nil
                    }
                }
            }
        }
    }

    private func isIpLiteral(_ host: String) -> Bool {
        var v4 = in_addr()
        var v6 = in6_addr()
        return inet_pton(AF_INET, host, &v4) == 1 || inet_pton(AF_INET6, host, &v6) == 1
    }
}
#endif
