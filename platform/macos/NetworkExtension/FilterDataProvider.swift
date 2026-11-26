// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors

#if os(macOS)
import Foundation
import NetworkExtension
import GrdrSensorMacOSBridge

public final class GrdrFilterDataProvider: NEFilterDataProvider {
    private let policyLock = NSLock()
    private var floorRulesJson: Data = Data("[]".utf8)
    private var defaultDeny: UInt8 = 1

    public func configureFloorPolicy(rulesJson: Data, defaultDeny: Bool) {
        policyLock.lock()
        self.floorRulesJson = rulesJson
        self.defaultDeny = defaultDeny ? 1 : 0
        policyLock.unlock()
    }

    public override func startFilter(completionHandler: @escaping (Error?) -> Void) {
        completionHandler(nil)
    }

    public override func stopFilter(with reason: NEProviderStopReason, completionHandler: @escaping () -> Void) {
        completionHandler()
    }

    public override func handleNewFlow(_ flow: NEFilterFlow) -> NEFilterNewFlowVerdict {
        policyLock.lock()
        let rulesSnapshot = floorRulesJson
        let denyFlag = defaultDeny
        policyLock.unlock()

        let fallbackVerdict: NEFilterNewFlowVerdict = (denyFlag != 0) ? .drop() : .allow()
        guard let socketFlow = flow as? NEFilterSocketFlow else {
            return fallbackVerdict
        }
        let remoteHost = socketFlow.remoteEndpoint as? NWHostEndpoint
        let remotePort = UInt16(remoteHost?.port ?? "0") ?? 0
        let transport = (Int32(socketFlow.socketProtocol) == IPPROTO_UDP) ? "udp" : "tcp"
        let hostName = remoteHost?.hostname ?? ""
        let flowId = UInt64(bitPattern: Int64(flow.identifier.hashValue))
        let flowPayload: [String: Any] = [
            "flow_id": flowId,
            "agent_name": "agent",
            "governed_process": true,
            "transport": transport,
            "remote_port": remotePort,
            "host_name": hostName,
            "tls_sni": NSNull()
        ]
        guard let jsonData = try? JSONSerialization.data(withJSONObject: flowPayload),
              let verdictStr = evaluateFlowCAbi(flowJson: jsonData, floorRulesJson: rulesSnapshot, defaultDeny: denyFlag),
              let parsed = try? JSONSerialization.jsonObject(with: Data(verdictStr.utf8)) as? [String: Any],
              let action = (parsed["verdict"] as? String)?.lowercased()
        else {
            return fallbackVerdict
        }
        switch action {
        case "drop", "deny", "block":
            return .drop()
        case "allow":
            return .allow()
        default:
            return fallbackVerdict
        }
    }

    private func evaluateFlowCAbi(flowJson: Data, floorRulesJson: Data, defaultDeny: UInt8) -> String? {
        return flowJson.withUnsafeBytes { flowBuf in
            floorRulesJson.withUnsafeBytes { floorBuf in
                let flowPtr = flowBuf.bindMemory(to: UInt8.self).baseAddress
                let floorPtr = floorBuf.bindMemory(to: UInt8.self).baseAddress
                guard let rawOut = grdr_macos_eval_ne_flow(
                    flowPtr,
                    flowBuf.count,
                    floorPtr,
                    floorBuf.count,
                    defaultDeny
                ) else {
                    return nil
                }
                defer { grdr_macos_free_string(rawOut) }
                return String(cString: rawOut)
            }
        }
    }
}
#endif
