// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors

/*
 * Guardrails ADR Optional Windows Kernel Sensor Driver (W2 tier).
 * [EXT] Production signing requires WDK build + EV certificate + WHCP HLK certification.
 */

#include <fltKernel.h>
#include <ntddk.h>

#include "grdr_driver_protocol.h"

#define GRDR_POOL_TAG 'rdrG'
#define GRDR_BOOT_COUNTER_VALUE_NAME L"EarlyBugcheckCount"
#define GRDR_MAX_PATH_WCHARS 260u

typedef struct GrdrDriverEventMessage {
    GrdrDriverProtocolHeader header;
    uint32_t actor_pid;
    uint32_t target_pid;
    uint32_t path_bytes;
    uint32_t reserved;
    wchar_t path_preview[GRDR_MAX_PATH_WCHARS];
} GrdrDriverEventMessage;

typedef struct GrdrDriverGlobals {
    PFLT_FILTER filter_handle;
    PFLT_PORT server_port;
    volatile PFLT_PORT client_port;
    EX_RUNDOWN_REF client_rundown;
    FAST_MUTEX connect_lock;
    BOOLEAN notify_registered;
    volatile LONG active_state;
    volatile LONG fail_closed_on_fault;
    USHORT registry_path_len;
    wchar_t registry_path_buf[GRDR_MAX_PATH_WCHARS];
} GrdrDriverGlobals;

static GrdrDriverGlobals g_grdr = { 0 };
static const uint8_t k_protocol_magic[8] = GRDR_DRIVER_PROTOCOL_MAGIC_BYTES;

DRIVER_INITIALIZE DriverEntry;
static NTSTATUS GrdrCheckBootGuard(_In_ PUNICODE_STRING registry_path, _Out_ PBOOLEAN disabled_out);
static VOID GrdrWriteBootGuardCounter(_In_ PUNICODE_STRING registry_path, _In_ ULONG count);
static NTSTATUS GrdrBuildSystemOnlySecurityDescriptor(
    _Out_ PSECURITY_DESCRIPTOR sd_out,
    _Outptr_ PACL* dacl_out
);
static BOOLEAN GrdrCallerIsLocalSystem(VOID);
static NTSTATUS GrdrConnectNotify(
    _In_ PFLT_PORT client_port,
    _In_opt_ PVOID server_port_cookie,
    _In_reads_bytes_opt_(size_of_context) PVOID connection_context,
    _In_ ULONG size_of_context,
    _Outptr_result_maybenull_ PVOID* connection_cookie
);
static VOID GrdrDisconnectNotify(_In_opt_ PVOID connection_cookie);
static FLT_PREOP_CALLBACK_STATUS GrdrPreCreateCallback(
    _Inout_ PFLT_CALLBACK_DATA data,
    _In_ PCFLT_RELATED_OBJECTS flt_objects,
    _Outptr_result_maybenull_ PVOID* completion_context
);
static NTSTATUS GrdrFilterUnload(_In_ FLT_FILTER_UNLOAD_FLAGS flags);
static VOID GrdrProcessNotifyEx2(
    _Inout_ PEPROCESS process,
    _In_ HANDLE process_id,
    _Inout_opt_ PPS_CREATE_NOTIFY_INFO create_info
);

static const FLT_OPERATION_REGISTRATION g_callbacks[] = {
    { IRP_MJ_CREATE, 0, GrdrPreCreateCallback, NULL },
    { IRP_MJ_OPERATION_END }
};

static const FLT_REGISTRATION g_filter_registration = {
    sizeof(FLT_REGISTRATION),
    FLT_REGISTRATION_VERSION,
    0,
    NULL,
    g_callbacks,
    GrdrFilterUnload,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL
};

NTSTATUS DriverEntry(_In_ PDRIVER_OBJECT driver_object, _In_ PUNICODE_STRING registry_path) {
    ExInitializeFastMutex(&g_grdr.connect_lock);
    ExInitializeRundownProtection(&g_grdr.client_rundown);
    ExRundownCompleted(&g_grdr.client_rundown);

    BOOLEAN boot_disabled = FALSE;
    NTSTATUS status = GrdrCheckBootGuard(registry_path, &boot_disabled);
    if (!NT_SUCCESS(status) || boot_disabled) {
        return STATUS_CANCELLED;
    }

    if (registry_path != NULL && registry_path->Buffer != NULL) {
        USHORT copy_bytes = registry_path->Length;
        USHORT max_bytes = (USHORT)((GRDR_MAX_PATH_WCHARS - 1u) * sizeof(wchar_t));
        if (copy_bytes > max_bytes) {
            copy_bytes = max_bytes;
        }
        RtlCopyMemory(g_grdr.registry_path_buf, registry_path->Buffer, copy_bytes);
        g_grdr.registry_path_buf[copy_bytes / sizeof(wchar_t)] = L'\0';
        g_grdr.registry_path_len = copy_bytes;
    }

    status = FltRegisterFilter(driver_object, &g_filter_registration, &g_grdr.filter_handle);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    SECURITY_DESCRIPTOR sd_storage = { 0 };
    PACL system_dacl = NULL;
    status = GrdrBuildSystemOnlySecurityDescriptor(&sd_storage, &system_dacl);
    if (!NT_SUCCESS(status)) {
        FltUnregisterFilter(g_grdr.filter_handle);
        g_grdr.filter_handle = NULL;
        return status;
    }

    UNICODE_STRING port_name = RTL_CONSTANT_STRING(GRDR_PORT_NAME);
    OBJECT_ATTRIBUTES oa;
    InitializeObjectAttributes(
        &oa,
        &port_name,
        OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE,
        NULL,
        &sd_storage
    );

    status = FltCreateCommunicationPort(
        g_grdr.filter_handle,
        &g_grdr.server_port,
        &oa,
        NULL,
        GrdrConnectNotify,
        GrdrDisconnectNotify,
        NULL,
        1
    );
    ExFreePoolWithTag(system_dacl, GRDR_POOL_TAG);
    if (!NT_SUCCESS(status)) {
        FltUnregisterFilter(g_grdr.filter_handle);
        g_grdr.filter_handle = NULL;
        return status;
    }

    status = PsSetCreateProcessNotifyRoutineEx2(
        PsCreateProcessNotifySubsystems,
        GrdrProcessNotifyEx2,
        FALSE
    );
    if (NT_SUCCESS(status)) {
        g_grdr.notify_registered = TRUE;
    }

    status = FltStartFiltering(g_grdr.filter_handle);
    if (!NT_SUCCESS(status)) {
        GrdrFilterUnload(0);
        return status;
    }

    InterlockedExchange(&g_grdr.active_state, 1);
    if (g_grdr.registry_path_len > 0) {
        UNICODE_STRING init_reg;
        init_reg.Length = g_grdr.registry_path_len;
        init_reg.MaximumLength = (USHORT)sizeof(g_grdr.registry_path_buf);
        init_reg.Buffer = g_grdr.registry_path_buf;
        GrdrWriteBootGuardCounter(&init_reg, 0);
    }
    return STATUS_SUCCESS;
}

static NTSTATUS GrdrBuildSystemOnlySecurityDescriptor(
    _Out_ PSECURITY_DESCRIPTOR sd_out,
    _Outptr_ PACL* dacl_out
) {
    *dacl_out = NULL;
    if (SeExports == NULL || SeExports->SeLocalSystemSid == NULL) {
        return STATUS_INVALID_PARAMETER;
    }
    NTSTATUS status = RtlCreateSecurityDescriptor(sd_out, SECURITY_DESCRIPTOR_REVISION);
    if (!NT_SUCCESS(status)) {
        return status;
    }
    ULONG sid_len = RtlLengthSid(SeExports->SeLocalSystemSid);
    ULONG acl_len = (ULONG)(sizeof(ACL) + sizeof(ACCESS_ALLOWED_ACE) - sizeof(ULONG) + sid_len);
    PACL dacl = (PACL)ExAllocatePool2(POOL_FLAG_PAGED, acl_len, GRDR_POOL_TAG);
    if (dacl == NULL) {
        return STATUS_INSUFFICIENT_RESOURCES;
    }
    status = RtlCreateAcl(dacl, acl_len, ACL_REVISION);
    if (!NT_SUCCESS(status)) {
        ExFreePoolWithTag(dacl, GRDR_POOL_TAG);
        return status;
    }
    status = RtlAddAccessAllowedAce(dacl, ACL_REVISION, FLT_PORT_ALL_ACCESS, SeExports->SeLocalSystemSid);
    if (!NT_SUCCESS(status)) {
        ExFreePoolWithTag(dacl, GRDR_POOL_TAG);
        return status;
    }
    status = RtlSetDaclSecurityDescriptor(sd_out, TRUE, dacl, FALSE);
    if (!NT_SUCCESS(status)) {
        ExFreePoolWithTag(dacl, GRDR_POOL_TAG);
        return status;
    }
    *dacl_out = dacl;
    return STATUS_SUCCESS;
}

static BOOLEAN GrdrCallerIsLocalSystem(VOID) {
    if (SeExports == NULL || SeExports->SeLocalSystemSid == NULL) {
        return FALSE;
    }
    PACCESS_TOKEN token = PsReferencePrimaryToken(PsGetCurrentProcess());
    if (token == NULL) {
        return FALSE;
    }
    PTOKEN_USER token_user = NULL;
    BOOLEAN is_system = FALSE;
    NTSTATUS status = SeQueryInformationToken(token, TokenUser, (PVOID*)&token_user);
    if (NT_SUCCESS(status) && token_user != NULL) {
        is_system = RtlEqualSid(token_user->User.Sid, SeExports->SeLocalSystemSid);
        ExFreePool(token_user);
    }
    PsDereferencePrimaryToken(token);
    return is_system;
}

static NTSTATUS GrdrCheckBootGuard(_In_ PUNICODE_STRING registry_path, _Out_ PBOOLEAN disabled_out) {
    *disabled_out = FALSE;
    if (registry_path == NULL) {
        return STATUS_SUCCESS;
    }

    HANDLE key_handle = NULL;
    OBJECT_ATTRIBUTES oa;
    InitializeObjectAttributes(&oa, registry_path, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, NULL);
    NTSTATUS status = ZwOpenKey(&key_handle, KEY_READ | KEY_WRITE, &oa);
    if (!NT_SUCCESS(status)) {
        return STATUS_SUCCESS;
    }

    UNICODE_STRING val_name = RTL_CONSTANT_STRING(GRDR_BOOT_COUNTER_VALUE_NAME);
    UCHAR buf[sizeof(KEY_VALUE_PARTIAL_INFORMATION) + sizeof(ULONG)];
    ULONG result_len = 0;
    ULONG current_count = 0;
    status = ZwQueryValueKey(key_handle, &val_name, KeyValuePartialInformation, buf, sizeof(buf), &result_len);
    if (NT_SUCCESS(status)) {
        PKEY_VALUE_PARTIAL_INFORMATION info = (PKEY_VALUE_PARTIAL_INFORMATION)buf;
        if (info->Type == REG_DWORD && info->DataLength == sizeof(ULONG)) {
            current_count = *(ULONG*)info->Data;
            if (current_count >= GRDR_MAX_EARLY_BUGCHECKS) {
                *disabled_out = TRUE;
                ZwClose(key_handle);
                return STATUS_SUCCESS;
            }
        }
    }
    ULONG next_count = current_count + 1u;
    (void)ZwSetValueKey(key_handle, &val_name, 0, REG_DWORD, &next_count, sizeof(next_count));
    ZwClose(key_handle);
    return STATUS_SUCCESS;
}

static VOID GrdrWriteBootGuardCounter(_In_ PUNICODE_STRING registry_path, _In_ ULONG count) {
    if (registry_path == NULL || registry_path->Buffer == NULL || registry_path->Length == 0) {
        return;
    }
    HANDLE key_handle = NULL;
    OBJECT_ATTRIBUTES oa;
    InitializeObjectAttributes(&oa, registry_path, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, NULL);
    if (NT_SUCCESS(ZwOpenKey(&key_handle, KEY_WRITE, &oa))) {
        UNICODE_STRING val_name = RTL_CONSTANT_STRING(GRDR_BOOT_COUNTER_VALUE_NAME);
        (void)ZwSetValueKey(key_handle, &val_name, 0, REG_DWORD, &count, sizeof(count));
        ZwClose(key_handle);
    }
}

static NTSTATUS GrdrConnectNotify(
    _In_ PFLT_PORT client_port,
    _In_opt_ PVOID server_port_cookie,
    _In_reads_bytes_opt_(size_of_context) PVOID connection_context,
    _In_ ULONG size_of_context,
    _Outptr_result_maybenull_ PVOID* connection_cookie
) {
    UNREFERENCED_PARAMETER(server_port_cookie);
    UNREFERENCED_PARAMETER(connection_context);
    UNREFERENCED_PARAMETER(size_of_context);
    if (connection_cookie != NULL) {
        *connection_cookie = NULL;
    }
    if (!GrdrCallerIsLocalSystem()) {
        return STATUS_ACCESS_DENIED;
    }

    ExAcquireFastMutex(&g_grdr.connect_lock);
    if (g_grdr.client_port != NULL) {
        ExReleaseFastMutex(&g_grdr.connect_lock);
        return STATUS_CONNECTION_ACTIVE;
    }
    ExReInitializeRundownProtection(&g_grdr.client_rundown);
    InterlockedExchangePointer((volatile PVOID*)&g_grdr.client_port, client_port);
    ExReleaseFastMutex(&g_grdr.connect_lock);
    return STATUS_SUCCESS;
}

static VOID GrdrDisconnectNotify(_In_opt_ PVOID connection_cookie) {
    UNREFERENCED_PARAMETER(connection_cookie);
    ExAcquireFastMutex(&g_grdr.connect_lock);
    PFLT_PORT port = (PFLT_PORT)InterlockedExchangePointer((volatile PVOID*)&g_grdr.client_port, NULL);
    ExWaitForRundownProtectionRelease(&g_grdr.client_rundown);
    if (port != NULL) {
        FltCloseClientPort(g_grdr.filter_handle, &port);
    }
    ExReleaseFastMutex(&g_grdr.connect_lock);
}

static BOOLEAN GrdrReplyIsValid(_In_ const GrdrDriverVerdictReply* reply, _In_ ULONG reply_len) {
    if (reply_len < sizeof(GrdrDriverVerdictReply)) {
        return FALSE;
    }
    if (!RtlEqualMemory(reply->header.magic, k_protocol_magic, sizeof(k_protocol_magic))) {
        return FALSE;
    }
    if (reply->header.version != GRDR_DRIVER_PROTOCOL_VERSION) {
        return FALSE;
    }
    return TRUE;
}

static VOID GrdrPopulatePath(_Out_ GrdrDriverEventMessage* msg, _In_opt_ PCUNICODE_STRING path) {
    RtlZeroMemory(msg->path_preview, sizeof(msg->path_preview));
    msg->path_bytes = 0;
    if (path == NULL || path->Buffer == NULL || path->Length == 0) {
        return;
    }
    USHORT max_bytes = (USHORT)((GRDR_MAX_PATH_WCHARS - 1u) * sizeof(wchar_t));
    USHORT copy_bytes = (path->Length > max_bytes) ? max_bytes : path->Length;
    RtlCopyMemory(msg->path_preview, path->Buffer, copy_bytes);
    msg->path_bytes = copy_bytes;
}

static NTSTATUS GrdrSendVerdictSync(
    _In_ uint32_t kind,
    _In_ uint32_t actor_pid,
    _In_ uint32_t target_pid,
    _In_opt_ PCUNICODE_STRING path,
    _Out_ PBOOLEAN deny_out
) {
    *deny_out = FALSE;
    if (!ExAcquireRundownProtection(&g_grdr.client_rundown)) {
        return STATUS_PORT_DISCONNECTED;
    }
    PFLT_PORT local_port = (PFLT_PORT)InterlockedCompareExchangePointer((volatile PVOID*)&g_grdr.client_port, NULL, NULL);
    if (local_port == NULL) {
        ExReleaseRundownProtection(&g_grdr.client_rundown);
        return STATUS_PORT_DISCONNECTED;
    }

    GrdrDriverEventMessage msg = { 0 };
    RtlCopyMemory(msg.header.magic, k_protocol_magic, sizeof(k_protocol_magic));
    msg.header.version = GRDR_DRIVER_PROTOCOL_VERSION;
    msg.header.message_kind = kind;
    msg.actor_pid = actor_pid;
    msg.target_pid = target_pid;
    GrdrPopulatePath(&msg, path);
    msg.header.payload_len = (uint32_t)(sizeof(msg.actor_pid) + sizeof(msg.target_pid)
        + sizeof(msg.path_bytes) + sizeof(msg.reserved) + msg.path_bytes);
    msg.header.reply_deadline_ms = GRDR_DRIVER_REPLY_DEADLINE_MS;

    GrdrDriverVerdictReply reply = { 0 };
    ULONG reply_len = sizeof(reply);
    LARGE_INTEGER timeout;
    timeout.QuadPart = -((LONGLONG)GRDR_DRIVER_REPLY_DEADLINE_MS * 10000LL);

    NTSTATUS status = FltSendMessage(
        g_grdr.filter_handle,
        &local_port,
        &msg,
        sizeof(GrdrDriverProtocolHeader) + msg.header.payload_len,
        &reply,
        &reply_len,
        &timeout
    );
    ExReleaseRundownProtection(&g_grdr.client_rundown);

    if (NT_SUCCESS(status) && GrdrReplyIsValid(&reply, reply_len) && reply.verdict == GRDR_VERDICT_DENY) {
        *deny_out = TRUE;
    }
    return status;
}

static FLT_PREOP_CALLBACK_STATUS GrdrPreCreateCallback(
    _Inout_ PFLT_CALLBACK_DATA data,
    _In_ PCFLT_RELATED_OBJECTS flt_objects,
    _Outptr_result_maybenull_ PVOID* completion_context
) {
    if (completion_context != NULL) {
        *completion_context = NULL;
    }
    if (ExGetPreviousMode() == KernelMode || InterlockedCompareExchange(&g_grdr.active_state, 0, 0) == 0) {
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

    uint32_t req_pid = IoGetRequestorProcessId(data);
    PCUNICODE_STRING target_name = (flt_objects != NULL && flt_objects->FileObject != NULL)
        ? &flt_objects->FileObject->FileName
        : NULL;
    BOOLEAN deny = FALSE;
    NTSTATUS ipc_status = GrdrSendVerdictSync(
        GRDR_MSG_FILE_PRE_CREATE,
        req_pid,
        req_pid,
        target_name,
        &deny
    );
    if (!NT_SUCCESS(ipc_status) && InterlockedCompareExchange(&g_grdr.fail_closed_on_fault, 0, 0) != 0) {
        deny = TRUE;
    }
    if (deny) {
        data->IoStatus.Status = STATUS_ACCESS_DENIED;
        data->IoStatus.Information = 0;
        return FLT_PREOP_COMPLETE;
    }
    return FLT_PREOP_SUCCESS_NO_CALLBACK;
}

static VOID GrdrProcessNotifyEx2(
    _Inout_ PEPROCESS process,
    _In_ HANDLE process_id,
    _Inout_opt_ PPS_CREATE_NOTIFY_INFO create_info
) {
    UNREFERENCED_PARAMETER(process);
    if (create_info == NULL || InterlockedCompareExchange(&g_grdr.active_state, 0, 0) == 0) {
        return;
    }

    uint32_t actor_pid = HandleToULong(PsGetCurrentProcessId());
    uint32_t target_pid = HandleToULong(process_id);
    BOOLEAN deny = FALSE;
    NTSTATUS ipc_status = GrdrSendVerdictSync(
        GRDR_MSG_PROCESS_CREATE,
        actor_pid,
        target_pid,
        create_info->ImageFileName,
        &deny
    );
    if (!NT_SUCCESS(ipc_status) && InterlockedCompareExchange(&g_grdr.fail_closed_on_fault, 0, 0) != 0) {
        deny = TRUE;
    }
    if (deny) {
        create_info->CreationStatus = STATUS_ACCESS_DENIED;
    }
}

static NTSTATUS GrdrFilterUnload(_In_ FLT_FILTER_UNLOAD_FLAGS flags) {
    UNREFERENCED_PARAMETER(flags);
    InterlockedExchange(&g_grdr.active_state, 0);
    if (g_grdr.notify_registered) {
        PsSetCreateProcessNotifyRoutineEx2(
            PsCreateProcessNotifySubsystems,
            GrdrProcessNotifyEx2,
            TRUE
        );
        g_grdr.notify_registered = FALSE;
    }
    GrdrDisconnectNotify(NULL);
    if (g_grdr.server_port != NULL) {
        FltCloseCommunicationPort(g_grdr.server_port);
        g_grdr.server_port = NULL;
    }
    if (g_grdr.filter_handle != NULL) {
        FltUnregisterFilter(g_grdr.filter_handle);
        g_grdr.filter_handle = NULL;
    }
    if (g_grdr.registry_path_len > 0) {
        UNICODE_STRING reg_path;
        reg_path.Length = g_grdr.registry_path_len;
        reg_path.MaximumLength = (USHORT)sizeof(g_grdr.registry_path_buf);
        reg_path.Buffer = g_grdr.registry_path_buf;
        GrdrWriteBootGuardCounter(&reg_path, 0);
    }
    return STATUS_SUCCESS;
}
