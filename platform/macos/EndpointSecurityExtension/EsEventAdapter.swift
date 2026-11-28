// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors

#if os(macOS)
import Darwin.Mach
import Darwin.bsm
import EndpointSecurity
import Foundation
import GrdrSensorMacOSBridge

public enum GrdrEsConcern: String, CaseIterable, Sendable {
    case recorder
    case execAuthorizer
    case protectedPathGuard
    case selfProtection

    public var concernCode: UInt8 {
        switch self {
        case .recorder: return UInt8(GRDR_MAC_ES_CONCERN_RECORDER.rawValue)
        case .execAuthorizer: return UInt8(GRDR_MAC_ES_CONCERN_EXEC_AUTHORIZER.rawValue)
        case .protectedPathGuard: return UInt8(GRDR_MAC_ES_CONCERN_PROTECTED_PATH_GUARD.rawValue)
        case .selfProtection: return UInt8(GRDR_MAC_ES_CONCERN_SELF_PROTECTION.rawValue)
        }
    }
}

public enum GrdrEsClientState: String, Sendable {
    case active
    case missingEntitlement = "missing_entitlement"
    case tooManyClients = "too_many_clients"
    case notPermittedFda = "not_permitted_fda"
    case internalError = "internal_error"
    case stopped
}

struct EsEvaluatedMessage {
    let verdict: GrdrMacEsVerdictC
    let kindCode: UInt8
    let targetPath: String
    let alwaysEmitTelemetry: Bool
    let treeDeltaRecord: Data?
    let actorKey: UInt64
    let targetKey: UInt64
    let targetPid: UInt32
    let targetPidVersion: UInt32
    let targetUid: UInt32
}

enum GrdrEsEventAdapter {
    static let defaultKernelDeadlineMs: UInt64 = 10_000

    static func canonicalizeTargetPath(_ rawPath: String) -> String {
        let trimmed = rawPath.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !trimmed.isEmpty else {
            return ""
        }
        let urlResolved = URL(fileURLWithPath: trimmed)
            .standardizedFileURL
            .resolvingSymlinksInPath()
            .path
        return normalizeDarwinPrefix(urlResolved)
    }

    static func normalizeDarwinPrefix(_ path: String) -> String {
        if path == "/tmp" || path.hasPrefix("/tmp/") {
            return "/private\(path)"
        }
        if path == "/var" || path.hasPrefix("/var/") {
            return "/private\(path)"
        }
        if path == "/etc" || path.hasPrefix("/etc/") {
            return "/private\(path)"
        }
        return path
    }

    static func loadBrandMetadata() -> (
        prefix: String,
        productName: String,
        daemonLabel: String,
        appGroupId: String
    ) {
        var brand = GrdrMacBrandInfoC()
        guard grdr_macos_get_brand_info(&brand) == GRDR_MAC_FFI_OK.rawValue else {
            return ("", "", "", "")
        }
        return (
            decodeFixedUtf8(brand.own_prefix, len: brand.own_prefix_len),
            decodeFixedUtf8(brand.product_name, len: brand.product_name_len),
            decodeFixedUtf8(brand.daemon_label, len: brand.daemon_label_len),
            decodeFixedUtf8(brand.app_group_id, len: brand.app_group_id_len)
        )
    }

    static func defaultSelfPaths() -> [String] {
        var candidates: [String] = []
        if !Bundle.main.bundlePath.isEmpty {
            candidates.append(Bundle.main.bundlePath)
        }
        if let exePath = Bundle.main.executablePath, !exePath.isEmpty {
            candidates.append(exePath)
        }
        let brand = loadBrandMetadata()
        if !brand.productName.isEmpty {
            candidates.append("/Applications/\(brand.productName).app")
            candidates.append("/Library/Application Support/\(brand.productName)")
        }
        if !brand.daemonLabel.isEmpty {
            candidates.append("/Library/LaunchDaemons/\(brand.daemonLabel).plist")
        }
        if !brand.appGroupId.isEmpty {
            if let groupUrl = FileManager.default.containerURL(forSecurityApplicationGroupIdentifier: brand.appGroupId) {
                candidates.append(groupUrl.path)
            }
        }
        candidates.append(contentsOf: [
            "/usr/local/bin/grdr-daemon",
            "/usr/local/libexec/grdr-daemon",
            "/opt/homebrew/bin/grdr-daemon"
        ])
        return Array(Set(candidates.map(canonicalizeTargetPath).filter { !$0.isEmpty })).sorted()
    }

    static func processKey(pid: UInt32, pidversion: UInt32) -> UInt64 {
        return (UInt64(pid) << 32) | UInt64(pidversion)
    }

    static func remainingKernelDeadlineMs(
        deadline: UInt64,
        now: UInt64,
        timebase: mach_timebase_info_data_t
    ) -> UInt64 {
        guard deadline > now else {
            return 0
        }
        let delta = deadline - now
        let ns = (delta &* UInt64(timebase.numer)) / UInt64(max(1, timebase.denom))
        return ns / 1_000_000
    }

    static func evaluateMessage(
        concern: GrdrEsConcern,
        follower f: OpaquePointer,
        message: UnsafePointer<es_message_t>,
        floorTableBin: Data,
        defaultDeny: UInt8,
        seqNum: UInt64,
        elapsedMs: UInt64,
        kernelDeadlineMs: UInt64
    ) -> EsEvaluatedMessage {
        let msg = message.pointee
        let actorProc = msg.process.pointee
        var targetProc = actorProc
        var primaryPath = ""
        var secondaryPath = ""
        var accessFlags: UInt32 = 0
        var eventFlags: UInt32 = 0
        var kindCode: UInt8 = 0
        var alwaysEmit = false
        var isLifecycleDelta = false
        var isAuthExec = false

        switch msg.event_type {
        case ES_EVENT_TYPE_AUTH_EXEC:
            kindCode = UInt8(GRDR_MAC_ES_AUTH_EXEC.rawValue)
            targetProc = msg.event.exec.target.pointee
            primaryPath = stringFromEsToken(targetProc.executable.pointee.path)
            if hasImmutableSigningFlags(targetProc.codesigning_flags) {
                eventFlags |= GRDR_MAC_ES_FLAG_IMMUTABLE_CDHASH
            }
            isLifecycleDelta = true
            isAuthExec = true
        case ES_EVENT_TYPE_NOTIFY_EXEC:
            kindCode = UInt8(GRDR_MAC_ES_NOTIFY_EXEC.rawValue)
            targetProc = msg.event.exec.target.pointee
            primaryPath = stringFromEsToken(targetProc.executable.pointee.path)
            isLifecycleDelta = true
        case ES_EVENT_TYPE_NOTIFY_FORK:
            kindCode = UInt8(GRDR_MAC_ES_NOTIFY_FORK.rawValue)
            targetProc = msg.event.fork.child.pointee
            isLifecycleDelta = true
        case ES_EVENT_TYPE_NOTIFY_EXIT:
            kindCode = UInt8(GRDR_MAC_ES_NOTIFY_EXIT.rawValue)
            isLifecycleDelta = true
        case ES_EVENT_TYPE_AUTH_OPEN:
            kindCode = UInt8(GRDR_MAC_ES_AUTH_OPEN.rawValue)
            primaryPath = stringFromEsToken(msg.event.open.file.pointee.path)
            let writeMask = Int32(FWRITE) | O_APPEND | O_TRUNC | O_CREAT
            accessFlags = (msg.event.open.fflag & writeMask) != 0 ? 0x2 : 0x1
        case ES_EVENT_TYPE_AUTH_CREATE:
            kindCode = UInt8(GRDR_MAC_ES_AUTH_CREATE.rawValue)
            primaryPath = resolveDestinationCreatePath(msg.event.create)
        case ES_EVENT_TYPE_AUTH_TRUNCATE:
            kindCode = UInt8(GRDR_MAC_ES_AUTH_TRUNCATE.rawValue)
            primaryPath = stringFromEsToken(msg.event.truncate.target.pointee.path)
        case ES_EVENT_TYPE_AUTH_LINK:
            kindCode = UInt8(GRDR_MAC_ES_AUTH_LINK.rawValue)
            primaryPath = stringFromEsToken(msg.event.link.source.pointee.path)
            secondaryPath = joinDirAndName(
                msg.event.link.target_dir.pointee.path,
                msg.event.link.target_filename
            )
        case ES_EVENT_TYPE_AUTH_CLONE:
            kindCode = UInt8(GRDR_MAC_ES_AUTH_CLONE.rawValue)
            primaryPath = stringFromEsToken(msg.event.clone.source.pointee.path)
            secondaryPath = joinDirAndName(
                msg.event.clone.target_dir.pointee.path,
                msg.event.clone.target_name
            )
        case ES_EVENT_TYPE_AUTH_UNLINK:
            kindCode = UInt8(GRDR_MAC_ES_AUTH_UNLINK.rawValue)
            primaryPath = stringFromEsToken(msg.event.unlink.target.pointee.path)
        case ES_EVENT_TYPE_NOTIFY_UNLINK:
            kindCode = UInt8(GRDR_MAC_ES_NOTIFY_UNLINK.rawValue)
            primaryPath = stringFromEsToken(msg.event.unlink.target.pointee.path)
        case ES_EVENT_TYPE_AUTH_RENAME:
            kindCode = UInt8(GRDR_MAC_ES_AUTH_RENAME.rawValue)
            primaryPath = stringFromEsToken(msg.event.rename.source.pointee.path)
            secondaryPath = resolveRenameDestPath(msg.event.rename)
        case ES_EVENT_TYPE_NOTIFY_RENAME:
            kindCode = UInt8(GRDR_MAC_ES_NOTIFY_RENAME.rawValue)
            primaryPath = stringFromEsToken(msg.event.rename.source.pointee.path)
            secondaryPath = resolveRenameDestPath(msg.event.rename)
        case ES_EVENT_TYPE_NOTIFY_CREATE:
            kindCode = UInt8(GRDR_MAC_ES_NOTIFY_CREATE.rawValue)
            primaryPath = resolveDestinationCreatePath(msg.event.create)
        case ES_EVENT_TYPE_AUTH_UIPC_CONNECT:
            kindCode = UInt8(GRDR_MAC_ES_AUTH_UIPC_CONNECT.rawValue)
            primaryPath = stringFromEsToken(msg.event.uipc_connect.file.pointee.path)
        case ES_EVENT_TYPE_AUTH_SIGNAL:
            kindCode = UInt8(GRDR_MAC_ES_AUTH_SIGNAL.rawValue)
            targetProc = msg.event.signal.target.pointee
        case ES_EVENT_TYPE_AUTH_GET_TASK:
            kindCode = UInt8(GRDR_MAC_ES_AUTH_GET_TASK.rawValue)
            targetProc = msg.event.get_task.target.pointee
        case ES_EVENT_TYPE_AUTH_PROC_SUSPEND_RESUME:
            kindCode = UInt8(GRDR_MAC_ES_AUTH_PROC_SUSPEND_RESUME.rawValue)
            targetProc = msg.event.proc_suspend_resume.target.pointee
        case ES_EVENT_TYPE_NOTIFY_UIPC_CONNECT:
            kindCode = UInt8(GRDR_MAC_ES_NOTIFY_UIPC_CONNECT.rawValue)
            primaryPath = stringFromEsToken(msg.event.uipc_connect.file.pointee.path)
        case ES_EVENT_TYPE_NOTIFY_XPC_CONNECT:
            kindCode = UInt8(GRDR_MAC_ES_NOTIFY_XPC_CONNECT.rawValue)
            primaryPath = stringFromEsToken(msg.event.xpc_connect.service_name)
        case ES_EVENT_TYPE_NOTIFY_SUDO:
            kindCode = UInt8(GRDR_MAC_ES_NOTIFY_SUDO.rawValue)
            alwaysEmit = true
        case ES_EVENT_TYPE_NOTIFY_SU:
            kindCode = UInt8(GRDR_MAC_ES_NOTIFY_SU.rawValue)
            alwaysEmit = true
        case ES_EVENT_TYPE_NOTIFY_AUTHORIZATION_PETITION:
            kindCode = UInt8(GRDR_MAC_ES_NOTIFY_AUTH_PETITION.rawValue)
            alwaysEmit = true
        case ES_EVENT_TYPE_NOTIFY_AUTHORIZATION_JUDGEMENT:
            kindCode = UInt8(GRDR_MAC_ES_NOTIFY_AUTH_JUDGEMENT.rawValue)
            alwaysEmit = true
        case ES_EVENT_TYPE_NOTIFY_TCC_MODIFY:
            kindCode = UInt8(GRDR_MAC_ES_NOTIFY_TCC_MODIFY.rawValue)
            primaryPath = stringFromEsToken(msg.event.tcc_modify.service)
            alwaysEmit = true
        case ES_EVENT_TYPE_NOTIFY_BTM_LAUNCH_ITEM_ADD:
            kindCode = UInt8(GRDR_MAC_ES_NOTIFY_BTM_LAUNCH_ITEM_ADD.rawValue)
            primaryPath = stringFromEsToken(msg.event.btm_launch_item_add.item.pointee.item_url)
            alwaysEmit = true
        default:
            if #available(macOS 27.0, *), msg.event_type == ES_EVENT_TYPE_NOTIFY_BOOTSTRAP_LOOKUP {
                kindCode = UInt8(GRDR_MAC_ES_NOTIFY_BOOTSTRAP_LOOKUP.rawValue)
                primaryPath = stringFromEsToken(msg.event.bootstrap_lookup.service_name)
                alwaysEmit = true
            } else {
                var allowVerdict = GrdrMacEsVerdictC()
                allowVerdict.verdict_code = UInt8(GRDR_MAC_VERDICT_ALLOW.rawValue)
                return EsEvaluatedMessage(
                    verdict: allowVerdict,
                    kindCode: 0,
                    targetPath: "",
                    alwaysEmitTelemetry: false,
                    treeDeltaRecord: nil,
                    actorKey: 0,
                    targetKey: 0,
                    targetPid: 0,
                    targetPidVersion: 0,
                    targetUid: 0
                )
            }
        }

        let actorTeam = stringFromEsToken(actorProc.team_id)
        let targetTeam = stringFromEsToken(targetProc.team_id)
        let actorTeamData = Data(actorTeam.utf8)
        let targetTeamData = Data(targetTeam.utf8)
        let pathData = Data(primaryPath.utf8)
        let secondaryData = Data(secondaryPath.utf8)

        var outVerdict = GrdrMacEsVerdictC()
        outVerdict.verdict_code = UInt8(GRDR_MAC_VERDICT_ALLOW.rawValue)

        _ = actorTeamData.withUnsafeBytes { actorTeamBuf in
            targetTeamData.withUnsafeBytes { targetTeamBuf in
                pathData.withUnsafeBytes { pathBuf in
                    secondaryData.withUnsafeBytes { secBuf in
                        floorTableBin.withUnsafeBytes { binBuf in
                            var ev = emptyEsEvent(kindCode: kindCode, concernCode: concern.concernCode)
                            ev.default_deny = defaultDeny
                            ev.access_flags = accessFlags
                            ev.event_flags = eventFlags
                            ev.seq_num = seqNum
                            ev.elapsed_ms = elapsedMs
                            ev.kernel_deadline_ms = kernelDeadlineMs
                            ev.actor = makeTokenC(process: actorProc, teamPtr: actorTeamBuf.bindMemory(to: UInt8.self).baseAddress, teamLen: actorTeamBuf.count)
                            ev.target = makeTokenC(process: targetProc, teamPtr: targetTeamBuf.bindMemory(to: UInt8.self).baseAddress, teamLen: targetTeamBuf.count)
                            ev.path_ptr = pathBuf.bindMemory(to: UInt8.self).baseAddress
                            ev.path_len = pathBuf.count
                            ev.secondary_path_ptr = secBuf.bindMemory(to: UInt8.self).baseAddress
                            ev.secondary_path_len = secBuf.count

                            return grdr_macos_eval_es_event_bin_c(
                                f,
                                &ev,
                                binBuf.bindMemory(to: UInt8.self).baseAddress,
                                binBuf.count,
                                &outVerdict
                            )
                        }
                    }
                }
            }
        }

        let actorTok = actorProc.audit_token
        let actorPid = UInt32(max(0, audit_token_to_pid(actorTok)))
        let actorPidver = UInt32(max(0, audit_token_to_pidversion(actorTok)))
        let actorUid = audit_token_to_euid(actorTok)
        let targetTok = targetProc.audit_token
        let targetPid = UInt32(max(0, audit_token_to_pid(targetTok)))
        let targetPidver = UInt32(max(0, audit_token_to_pidversion(targetTok)))
        let targetUid = audit_token_to_euid(targetTok)

        let allowSync = !isAuthExec || outVerdict.verdict_code == UInt8(GRDR_MAC_VERDICT_ALLOW.rawValue)
        var deltaData: Data?
        if isLifecycleDelta && allowSync && outVerdict.governed_member != 0 {
            let sid = withUnsafeBytes(of: outVerdict.session_id) { raw in
                String(decoding: raw.prefix(Int(outVerdict.session_id_len)), as: UTF8.self)
            }
            if !sid.isEmpty {
                deltaData = GrdrEsTelemetryCodec.encodeTreeDeltaRecord(
                    kindCode: kindCode,
                    actorPid: actorPid,
                    actorPidver: actorPidver,
                    actorUid: actorUid,
                    targetPid: targetPid,
                    targetPidver: targetPidver,
                    targetUid: targetUid,
                    sessionId: sid,
                    agentName: "",
                    path: primaryPath
                )
            }
        }

        return EsEvaluatedMessage(
            verdict: outVerdict,
            kindCode: kindCode,
            targetPath: primaryPath,
            alwaysEmitTelemetry: alwaysEmit,
            treeDeltaRecord: deltaData,
            actorKey: processKey(pid: actorPid, pidversion: actorPidver),
            targetKey: processKey(pid: targetPid, pidversion: targetPidver),
            targetPid: targetPid,
            targetPidVersion: targetPidver,
            targetUid: targetUid
        )
    }

    static func emptyEsEvent(kindCode: UInt8, concernCode: UInt8) -> GrdrMacEsEventC {
        let zeroKey = GrdrMacProcessKeyC(pid: 0, pidversion: 0)
        let zeroTok = GrdrMacAuditTokenC(key: zeroKey, uid: 0, reserved: 0, team_id_ptr: nil, team_id_len: 0)
        return GrdrMacEsEventC(
            kind_code: kindCode,
            concern_code: concernCode,
            default_deny: 1,
            reserved0: 0,
            access_flags: 0,
            event_flags: 0,
            reserved1: 0,
            seq_num: 0,
            timestamp_ns: 0,
            elapsed_ms: 0,
            kernel_deadline_ms: defaultKernelDeadlineMs,
            actor: zeroTok,
            target: zeroTok,
            path_ptr: nil,
            path_len: 0,
            secondary_path_ptr: nil,
            secondary_path_len: 0,
            session_id_ptr: nil,
            session_id_len: 0,
            agent_name_ptr: nil,
            agent_name_len: 0
        )
    }

    static func stringFromEsToken(_ token: es_string_token_t) -> String {
        guard let ptr = token.data, token.length > 0 else {
            return ""
        }
        let raw = UnsafeRawPointer(ptr).assumingMemoryBound(to: UInt8.self)
        return String(bytes: UnsafeBufferPointer(start: raw, count: token.length), encoding: .utf8) ?? ""
    }

    private static func hasImmutableSigningFlags(_ flags: UInt32) -> Bool {
        let required: UInt32 = 0x0001 | 0x0100 | 0x0200
        let forbidden: UInt32 = 0x0002 | 0x0004 | 0x0010
        return (flags & required) == required && (flags & forbidden) == 0
    }

    private static func joinDirAndName(_ dirTok: es_string_token_t, _ fileTok: es_string_token_t) -> String {
        let dir = stringFromEsToken(dirTok)
        let file = stringFromEsToken(fileTok)
        return dir.isEmpty ? file : "\(dir)/\(file)"
    }

    private static func resolveDestinationCreatePath(_ create: es_event_create_t) -> String {
        if create.destination_type == ES_DESTINATION_TYPE_EXISTING_FILE {
            return stringFromEsToken(create.destination.existing_file.pointee.path)
        }
        return joinDirAndName(
            create.destination.new_path.dir.pointee.path,
            create.destination.new_path.filename
        )
    }

    private static func resolveRenameDestPath(_ rename: es_event_rename_t) -> String {
        if rename.destination_type == ES_DESTINATION_TYPE_EXISTING_FILE {
            return stringFromEsToken(rename.destination.existing_file.pointee.path)
        }
        return joinDirAndName(
            rename.destination.new_path.dir.pointee.path,
            rename.destination.new_path.filename
        )
    }

    private static func makeTokenC(process: es_process_t, teamPtr: UnsafePointer<UInt8>?, teamLen: Int) -> GrdrMacAuditTokenC {
        let tok = process.audit_token
        return GrdrMacAuditTokenC(
            key: GrdrMacProcessKeyC(
                pid: UInt32(max(0, audit_token_to_pid(tok))),
                pidversion: UInt32(max(0, audit_token_to_pidversion(tok)))
            ),
            uid: audit_token_to_euid(tok),
            reserved: 0,
            team_id_ptr: teamPtr,
            team_id_len: teamLen
        )
    }

    private static func decodeFixedUtf8<T>(_ tuple: T, len: UInt16) -> String {
        return withUnsafeBytes(of: tuple) { raw in
            let count = min(Int(len), raw.count)
            return String(decoding: raw.prefix(count), as: UTF8.self)
        }
    }
}
#endif
