// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors

/*
 * Guardrails ADR WSL2 Plugin DLL (grdr-wsl.dll).
 * Registered under HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Lxss\Plugins\GuardrailsADR.
 *
 * Security invariants:
 * - Zero text parsing in C plugin; JSON/YAML rules stay inside grdr-engine.
 * - Enrollment token handed to grdr-wsl-guest ONLY via stdin pipe (never argv or environment).
 * - Bounded overlapped I/O + SYSTEM server check + truncated-token rejection + API version check.
 */

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <stdint.h>
#include <stddef.h>
#include <string.h>

#define GRDR_WSL_GUEST_BIN "/opt/guardrails/bin/grdr-wsl-guest"
#define GRDR_WSL_ENROLL_PIPE L"\\\\.\\pipe\\grdr-wsl-enroll"
#define GRDR_MAX_ENROLL_TOKEN 256u
#define GRDR_WSL_PIPE_TIMEOUT_MS 500u

typedef struct WSLSessionInformation {
    uint32_t session_id;
    uint32_t vm_id;
} WSLSessionInformation;

typedef struct WSLVmCreationSettings {
    const wchar_t* custom_config_path;
} WSLVmCreationSettings;

typedef struct WSLDistributionInformation {
    const wchar_t* name;
    const wchar_t* package_family_name;
    uint32_t pid_namespace;
} WSLDistributionInformation;

typedef struct WSLPluginHooksV1 {
    HRESULT (CALLBACK* on_vm_started)(const WSLSessionInformation* session, const WSLVmCreationSettings* settings);
    HRESULT (CALLBACK* on_vm_stopping)(const WSLSessionInformation* session);
    HRESULT (CALLBACK* on_distribution_started)(const WSLSessionInformation* session, const WSLDistributionInformation* distro);
    HRESULT (CALLBACK* on_distribution_stopping)(const WSLSessionInformation* session, const WSLDistributionInformation* distro);
    HRESULT (CALLBACK* on_distribution_registered)(const WSLSessionInformation* session, const WSLDistributionInformation* distro);
    HRESULT (CALLBACK* on_distribution_unregistered)(const WSLSessionInformation* session, const WSLDistributionInformation* distro);
} WSLPluginHooksV1;

typedef HRESULT (CALLBACK* PFN_EXECUTE_BINARY)(
    uint32_t session_id,
    const char* path,
    const char* const* argv,
    HANDLE* socket_handle
);

typedef struct WSLPluginAPIV1 {
    struct {
        uint32_t major;
        uint32_t minor;
        uint32_t revision;
    } version;
    PFN_EXECUTE_BINARY execute_binary;
    HRESULT (CALLBACK* plugin_error)(const wchar_t* message);
} WSLPluginAPIV1;

static WSLPluginAPIV1 g_wsl_api = { 0 };

static BOOL grdr_verify_system_pipe_server(HANDLE pipe) {
    ULONG server_pid = 0;
    if (!GetNamedPipeServerProcessId(pipe, &server_pid) || server_pid == 0) {
        return FALSE;
    }
    HANDLE proc = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, server_pid);
    if (proc == NULL) {
        return FALSE;
    }
    HANDLE token = NULL;
    BOOL ok = FALSE;
    if (OpenProcessToken(proc, TOKEN_QUERY, &token)) {
        uint8_t sid_buf[sizeof(TOKEN_USER) + SECURITY_MAX_SID_SIZE];
        DWORD ret_len = 0;
        if (GetTokenInformation(token, TokenUser, sid_buf, sizeof(sid_buf), &ret_len)) {
            PTOKEN_USER tu = (PTOKEN_USER)sid_buf;
            ok = IsWellKnownSid(tu->User.Sid, WinLocalSystemSid);
        }
        CloseHandle(token);
    }
    CloseHandle(proc);
    return ok;
}

static void grdr_fetch_single_use_token(char* out_buf, size_t out_cap, DWORD* out_len) {
    *out_len = 0;
    if (out_cap < 2u || out_cap > GRDR_MAX_ENROLL_TOKEN) {
        return;
    }
    if (!WaitNamedPipeW(GRDR_WSL_ENROLL_PIPE, GRDR_WSL_PIPE_TIMEOUT_MS)) {
        return;
    }
    HANDLE pipe = CreateFileW(
        GRDR_WSL_ENROLL_PIPE,
        GENERIC_READ,
        0,
        NULL,
        OPEN_EXISTING,
        SECURITY_SQOS_PRESENT | SECURITY_IDENTIFICATION | FILE_FLAG_OVERLAPPED,
        NULL
    );
    if (pipe == INVALID_HANDLE_VALUE) {
        return;
    }
    if (!grdr_verify_system_pipe_server(pipe)) {
        CloseHandle(pipe);
        return;
    }

    HANDLE ev = CreateEventW(NULL, TRUE, FALSE, NULL);
    if (ev == NULL) {
        CloseHandle(pipe);
        return;
    }

    DWORD total_read = 0;
    BOOL read_ok = TRUE;
    while (total_read < (DWORD)out_cap) {
        ResetEvent(ev);
        OVERLAPPED ov = { 0 };
        ov.hEvent = ev;
        DWORD chunk = 0;
        if (!ReadFile(pipe, out_buf + total_read, (DWORD)(out_cap - total_read), &chunk, &ov)) {
            DWORD err = GetLastError();
            if (err == ERROR_BROKEN_PIPE || err == ERROR_HANDLE_EOF) {
                break;
            }
            if (err != ERROR_IO_PENDING) {
                read_ok = FALSE;
                break;
            }
            if (WaitForSingleObject(ev, GRDR_WSL_PIPE_TIMEOUT_MS) != WAIT_OBJECT_0) {
                (void)CancelIoEx(pipe, &ov);
                DWORD dummy = 0;
                (void)GetOverlappedResult(pipe, &ov, &dummy, TRUE);
                read_ok = FALSE;
                break;
            }
            if (!GetOverlappedResult(pipe, &ov, &chunk, FALSE)) {
                DWORD ov_err = GetLastError();
                if (ov_err == ERROR_BROKEN_PIPE || ov_err == ERROR_HANDLE_EOF) {
                    break;
                }
                read_ok = FALSE;
                break;
            }
        }
        if (chunk == 0) {
            break;
        }
        total_read += chunk;
    }

    CloseHandle(ev);
    CloseHandle(pipe);

    if (!read_ok || total_read == 0 || total_read >= (DWORD)out_cap) {
        SecureZeroMemory(out_buf, out_cap);
        *out_len = 0;
        return;
    }
    out_buf[total_read] = '\0';
    *out_len = total_read;
}

static HRESULT CALLBACK GrdrOnVMStarted(
    const WSLSessionInformation* session,
    const WSLVmCreationSettings* settings
) {
    (void)session;
    (void)settings;
    return S_OK;
}

static HRESULT CALLBACK GrdrOnVMStopping(const WSLSessionInformation* session) {
    (void)session;
    return S_OK;
}

static HRESULT CALLBACK GrdrOnDistributionStarted(
    const WSLSessionInformation* session,
    const WSLDistributionInformation* distro
) {
    (void)distro;
    if (session == NULL || g_wsl_api.execute_binary == NULL) {
        return S_OK;
    }

    char token_buf[GRDR_MAX_ENROLL_TOKEN];
    DWORD token_len = 0;
    grdr_fetch_single_use_token(token_buf, sizeof(token_buf), &token_len);
    if (token_len == 0) {
        SecureZeroMemory(token_buf, sizeof(token_buf));
        return S_OK;
    }

    const char* guest_argv[] = { GRDR_WSL_GUEST_BIN, "--enroll-stdin", NULL };
    HANDLE guest_socket = INVALID_HANDLE_VALUE;
    HRESULT hr = g_wsl_api.execute_binary(
        session->session_id,
        GRDR_WSL_GUEST_BIN,
        guest_argv,
        &guest_socket
    );
    if (SUCCEEDED(hr) && guest_socket != INVALID_HANDLE_VALUE && guest_socket != NULL) {
        DWORD offset = 0;
        while (offset < token_len) {
            DWORD written = 0;
            if (!WriteFile(guest_socket, token_buf + offset, token_len - offset, &written, NULL)
                || written == 0) {
                break;
            }
            offset += written;
        }
        CloseHandle(guest_socket);
    }
    SecureZeroMemory(token_buf, sizeof(token_buf));
    return S_OK;
}

static HRESULT CALLBACK GrdrOnDistributionStopping(
    const WSLSessionInformation* session,
    const WSLDistributionInformation* distro
) {
    (void)session;
    (void)distro;
    return S_OK;
}

HRESULT __cdecl WSLPLUGINAPI_ENTRYPOINTV1(
    const WSLPluginAPIV1* api,
    WSLPluginHooksV1* hooks
) {
    if (api == NULL || hooks == NULL) {
        return E_INVALIDARG;
    }
    if (api->version.major != 1u || api->execute_binary == NULL) {
        return E_NOINTERFACE;
    }
    memcpy(&g_wsl_api, api, sizeof(g_wsl_api));
    memset(hooks, 0, sizeof(*hooks));
    hooks->on_vm_started = GrdrOnVMStarted;
    hooks->on_vm_stopping = GrdrOnVMStopping;
    hooks->on_distribution_started = GrdrOnDistributionStarted;
    hooks->on_distribution_stopping = GrdrOnDistributionStopping;
    return S_OK;
}
