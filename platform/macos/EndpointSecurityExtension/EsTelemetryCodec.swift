// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors

#if os(macOS)
import Foundation
import GrdrSensorMacOSBridge

public struct GrdrEsTelemetryEvent: Sendable, Equatable {
    public let seqNum: UInt64
    public let concernCode: UInt8
    public let concern: String
    public let kindCode: UInt8
    public let pid: UInt32
    public let pidversion: UInt32
    public let sessionId: String
    public let actionClassCode: UInt8
    public let verdictCode: UInt8
    public let tamperAlert: Bool
    public let synthesizedDeniedExec: Bool
    public let targetPath: String
    public let matchedRuleId: String

    public init(
        seqNum: UInt64,
        concernCode: UInt8,
        concern: String,
        kindCode: UInt8,
        pid: UInt32,
        pidversion: UInt32,
        sessionId: String,
        actionClassCode: UInt8,
        verdictCode: UInt8,
        tamperAlert: Bool,
        synthesizedDeniedExec: Bool = false,
        targetPath: String,
        matchedRuleId: String = ""
    ) {
        self.seqNum = seqNum
        self.concernCode = concernCode
        self.concern = concern
        self.kindCode = kindCode
        self.pid = pid
        self.pidversion = pidversion
        self.sessionId = sessionId
        self.actionClassCode = actionClassCode
        self.verdictCode = verdictCode
        self.tamperAlert = tamperAlert
        self.synthesizedDeniedExec = synthesizedDeniedExec
        self.targetPath = targetPath
        self.matchedRuleId = matchedRuleId
    }
}

public enum GrdrEsTelemetryCodec {
    private static let magic: [UInt8] = [0x47, 0x52, 0x44, 0x54] // "GRDT"
    private static let wireVersion: UInt8 = 1
    private static let maxFieldBytes: Int = 4_096

    public static func encodeBinary(_ event: GrdrEsTelemetryEvent) -> Data {
        let sessionBytes = Data(event.sessionId.utf8.prefix(maxFieldBytes))
        let pathBytes = Data(event.targetPath.utf8.prefix(maxFieldBytes))
        let ruleBytes = Data(event.matchedRuleId.utf8.prefix(maxFieldBytes))

        var out = Data()
        out.reserveCapacity(34 + sessionBytes.count + pathBytes.count + ruleBytes.count)
        out.append(contentsOf: magic)
        out.append(wireVersion)
        out.append(event.concernCode)
        out.append(event.kindCode)
        out.append(event.actionClassCode)
        out.append(event.verdictCode)
        out.append(event.tamperAlert ? 1 : 0)
        out.append(event.synthesizedDeniedExec ? 1 : 0)
        out.append(0)
        appendLE(event.seqNum, to: &out)
        appendLE(event.pid, to: &out)
        appendLE(event.pidversion, to: &out)
        appendLE(UInt16(sessionBytes.count), to: &out)
        appendLE(UInt16(pathBytes.count), to: &out)
        appendLE(UInt16(ruleBytes.count), to: &out)
        out.append(sessionBytes)
        out.append(pathBytes)
        out.append(ruleBytes)
        return out
    }

    public static func encodeTreeDeltaRecord(
        kindCode: UInt8,
        actorPid: UInt32,
        actorPidver: UInt32,
        actorUid: UInt32,
        targetPid: UInt32,
        targetPidver: UInt32,
        targetUid: UInt32,
        sessionId: String,
        agentName: String,
        path: String
    ) -> Data {
        let sidBytes = Data(sessionId.utf8.prefix(256))
        let agentBytes = Data(agentName.utf8.prefix(128))
        let pathBytes = Data(path.utf8.prefix(maxFieldBytes))
        var out = Data()
        out.reserveCapacity(32 + sidBytes.count + agentBytes.count + pathBytes.count)
        out.append(0x54) // 'T'
        out.append(wireVersion)
        out.append(kindCode)
        out.append(0)
        appendLE(actorPid, to: &out)
        appendLE(actorPidver, to: &out)
        appendLE(actorUid, to: &out)
        appendLE(targetPid, to: &out)
        appendLE(targetPidver, to: &out)
        appendLE(targetUid, to: &out)
        appendLE(UInt16(sidBytes.count), to: &out)
        appendLE(UInt16(agentBytes.count), to: &out)
        appendLE(UInt16(pathBytes.count), to: &out)
        out.append(sidBytes)
        out.append(agentBytes)
        out.append(pathBytes)
        return out
    }

    private static func appendLE<T: FixedWidthInteger>(_ val: T, to data: inout Data) {
        var le = val.littleEndian
        withUnsafeBytes(of: &le) { data.append(contentsOf: $0) }
    }
}
#endif
