// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors

/*
 * Guardrails ADR Opt-In AMSI Provider (grdr-amsi.dll).
 *
 * Security & reliability invariants:
 * - Zero parsing in-process (SR-05): forwards raw buffer length + PID over bounded named pipe.
 * - Read-only Global\ lineage bitmap early-out: non-agent processes immediately return AMSI_RESULT_NOT_DETECTED.
 * - 50 ms bounded overlapped I/O + SYSTEM server identity check + 3-fault circuit breaker.
 */

#define WIN32_LEAN_AND_MEAN
#define COBJMACROS
#include <windows.h>
#include <objbase.h>
#include <amsi.h>
#include <stdint.h>
#include <stddef.h>

#define GRDR_AMSI_LINEAGE_MAP_NAME L"Global\\GrdrAmsiLineageBitmapV1"
#define GRDR_AMSI_PIPE_NAME L"\\\\.\\pipe\\grdr-amsi-eval"
#define GRDR_AMSI_BITMAP_BITS 65536u
#define GRDR_AMSI_TIMEOUT_MS 50u
#define GRDR_AMSI_MAX_FAULTS 3L
#define GRDR_AMSI_MAX_PAYLOAD (256u * 1024u)

/* {9D4B6C21-3E7A-4F8B-9C12-7A1E4D5B8F01} */
static const CLSID CLSID_GrdrAmsiProvider = {
    0x9d4b6c21u,
    0x3e7au,
    0x4f8bu,
    { 0x9cu, 0x12u, 0x7au, 0x1eu, 0x4du, 0x5bu, 0x8fu, 0x01u }
};

static LONG g_dll_ref_count = 0;
static LONG g_fault_count = 0;
static volatile LONG g_circuit_open = 0;

typedef struct GrdrAmsiForwardHeader {
    uint32_t magic;
    uint32_t pid;
    uint32_t content_bytes;
} GrdrAmsiForwardHeader;

typedef struct GrdrAmsiProviderObj {
    const IAntimalwareProviderVtbl* lpVtbl;
    LONG ref_count;
} GrdrAmsiProviderObj;

typedef struct GrdrClassFactoryObj {
    const IClassFactoryVtbl* lpVtbl;
    LONG ref_count;
} GrdrClassFactoryObj;

static BOOL grdr_pid_in_agent_lineage(uint32_t pid) {
    HANDLE mapping = OpenFileMappingW(FILE_MAP_READ, FALSE, GRDR_AMSI_LINEAGE_MAP_NAME);
    if (mapping == NULL) {
        return FALSE;
    }
    const uint8_t* bits = (const uint8_t*)MapViewOfFile(
        mapping,
        FILE_MAP_READ,
        0,
        0,
        GRDR_AMSI_BITMAP_BITS / 8u
    );
    BOOL match = FALSE;
    if (bits != NULL) {
        uint32_t idx = pid % GRDR_AMSI_BITMAP_BITS;
        match = ((bits[idx / 8u] >> (idx % 8u)) & 1u) != 0;
        UnmapViewOfFile(bits);
    }
    CloseHandle(mapping);
    return match;
}

static void grdr_record_fault_and_trip_if_needed(void) {
    LONG faults = InterlockedIncrement(&g_fault_count);
    if (faults >= GRDR_AMSI_MAX_FAULTS) {
        InterlockedExchange(&g_circuit_open, 1);
    }
}

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

static BOOL grdr_wait_overlapped(HANDLE pipe, OVERLAPPED* ov, DWORD* transferred_out) {
    DWORD wait_rc = WaitForSingleObject(ov->hEvent, GRDR_AMSI_TIMEOUT_MS);
    if (wait_rc != WAIT_OBJECT_0) {
        (void)CancelIoEx(pipe, ov);
        DWORD dummy = 0;
        (void)GetOverlappedResult(pipe, ov, &dummy, TRUE);
        return FALSE;
    }
    return GetOverlappedResult(pipe, ov, transferred_out, FALSE);
}

static BOOL grdr_write_all_overlapped(HANDLE pipe, const void* buf, uint32_t len, HANDLE ev) {
    const uint8_t* cursor = (const uint8_t*)buf;
    uint32_t remaining = len;
    while (remaining > 0) {
        ResetEvent(ev);
        OVERLAPPED ov = { 0 };
        ov.hEvent = ev;
        DWORD chunk = 0;
        if (!WriteFile(pipe, cursor, remaining, &chunk, &ov)) {
            if (GetLastError() != ERROR_IO_PENDING) {
                return FALSE;
            }
            if (!grdr_wait_overlapped(pipe, &ov, &chunk)) {
                return FALSE;
            }
        }
        if (chunk == 0 || chunk > remaining) {
            return FALSE;
        }
        cursor += chunk;
        remaining -= chunk;
    }
    return TRUE;
}

static BOOL grdr_read_exact_overlapped(HANDLE pipe, void* buf, uint32_t len, HANDLE ev) {
    uint8_t* cursor = (uint8_t*)buf;
    uint32_t remaining = len;
    while (remaining > 0) {
        ResetEvent(ev);
        OVERLAPPED ov = { 0 };
        ov.hEvent = ev;
        DWORD chunk = 0;
        if (!ReadFile(pipe, cursor, remaining, &chunk, &ov)) {
            if (GetLastError() != ERROR_IO_PENDING) {
                return FALSE;
            }
            if (!grdr_wait_overlapped(pipe, &ov, &chunk)) {
                return FALSE;
            }
        }
        if (chunk == 0 || chunk > remaining) {
            return FALSE;
        }
        cursor += chunk;
        remaining -= chunk;
    }
    return TRUE;
}

uint32_t __stdcall GrdrAmsiScanBuffer(
    const void* buffer,
    uint32_t length_bytes,
    const wchar_t* content_name
) {
    (void)content_name;
    if (InterlockedCompareExchange(&g_circuit_open, 0, 0) != 0) {
        return AMSI_RESULT_NOT_DETECTED;
    }

    uint32_t current_pid = GetCurrentProcessId();
    if (!grdr_pid_in_agent_lineage(current_pid)) {
        return AMSI_RESULT_NOT_DETECTED;
    }
    if (buffer == NULL || length_bytes == 0u || length_bytes > GRDR_AMSI_MAX_PAYLOAD) {
        return AMSI_RESULT_NOT_DETECTED;
    }

    if (!WaitNamedPipeW(GRDR_AMSI_PIPE_NAME, GRDR_AMSI_TIMEOUT_MS)) {
        return AMSI_RESULT_NOT_DETECTED;
    }
    HANDLE pipe = CreateFileW(
        GRDR_AMSI_PIPE_NAME,
        GENERIC_READ | GENERIC_WRITE,
        0,
        NULL,
        OPEN_EXISTING,
        SECURITY_SQOS_PRESENT | SECURITY_IDENTIFICATION | FILE_FLAG_OVERLAPPED,
        NULL
    );
    if (pipe == INVALID_HANDLE_VALUE) {
        grdr_record_fault_and_trip_if_needed();
        return AMSI_RESULT_NOT_DETECTED;
    }
    if (!grdr_verify_system_pipe_server(pipe)) {
        CloseHandle(pipe);
        grdr_record_fault_and_trip_if_needed();
        return AMSI_RESULT_NOT_DETECTED;
    }

    HANDLE ev = CreateEventW(NULL, TRUE, FALSE, NULL);
    if (ev == NULL) {
        CloseHandle(pipe);
        grdr_record_fault_and_trip_if_needed();
        return AMSI_RESULT_NOT_DETECTED;
    }

    GrdrAmsiForwardHeader hdr = { 0x4752414Du, current_pid, length_bytes };
    uint32_t verdict = AMSI_RESULT_NOT_DETECTED;
    uint32_t reply = 0;
    if (grdr_write_all_overlapped(pipe, &hdr, (uint32_t)sizeof(hdr), ev)
        && grdr_write_all_overlapped(pipe, buffer, length_bytes, ev)
        && grdr_read_exact_overlapped(pipe, &reply, (uint32_t)sizeof(reply), ev)) {
        if (reply == 1u) {
            verdict = AMSI_RESULT_DETECTED;
        }
    } else {
        grdr_record_fault_and_trip_if_needed();
    }

    CloseHandle(ev);
    CloseHandle(pipe);
    return verdict;
}

static HRESULT STDMETHODCALLTYPE GrdrProvider_QueryInterface(
    IAntimalwareProvider* this_ptr,
    REFIID riid,
    void** ppv
) {
    if (ppv == NULL) {
        return E_POINTER;
    }
    *ppv = NULL;
    if (IsEqualIID(riid, &IID_IUnknown) || IsEqualIID(riid, &IID_IAntimalwareProvider)) {
        *ppv = this_ptr;
        IAntimalwareProvider_AddRef(this_ptr);
        return S_OK;
    }
    return E_NOINTERFACE;
}

static ULONG STDMETHODCALLTYPE GrdrProvider_AddRef(IAntimalwareProvider* this_ptr) {
    GrdrAmsiProviderObj* self = (GrdrAmsiProviderObj*)this_ptr;
    return (ULONG)InterlockedIncrement(&self->ref_count);
}

static ULONG STDMETHODCALLTYPE GrdrProvider_Release(IAntimalwareProvider* this_ptr) {
    GrdrAmsiProviderObj* self = (GrdrAmsiProviderObj*)this_ptr;
    LONG refs = InterlockedDecrement(&self->ref_count);
    if (refs == 0) {
        HeapFree(GetProcessHeap(), 0, self);
        InterlockedDecrement(&g_dll_ref_count);
    }
    return (ULONG)refs;
}

static HRESULT STDMETHODCALLTYPE GrdrProvider_Scan(
    IAntimalwareProvider* this_ptr,
    IAmsiStream* stream,
    AMSI_RESULT* result
) {
    (void)this_ptr;
    if (stream == NULL || result == NULL) {
        return E_INVALIDARG;
    }
    *result = AMSI_RESULT_NOT_DETECTED;

    ULONGLONG size64 = 0;
    ULONG ret_bytes = 0;
    if (FAILED(IAmsiStream_GetAttribute(stream, AMSI_ATTRIBUTE_CONTENT_SIZE, sizeof(size64), (PBYTE)&size64, &ret_bytes))
        || size64 == 0 || size64 > GRDR_AMSI_MAX_PAYLOAD) {
        return S_OK;
    }
    uint32_t content_len = (uint32_t)size64;

    PVOID direct_ptr = NULL;
    ULONG addr_bytes = 0;
    if (SUCCEEDED(IAmsiStream_GetAttribute(stream, AMSI_ATTRIBUTE_CONTENT_ADDRESS, sizeof(direct_ptr), (PBYTE)&direct_ptr, &addr_bytes))
        && direct_ptr != NULL) {
        *result = (AMSI_RESULT)GrdrAmsiScanBuffer(direct_ptr, content_len, NULL);
        return S_OK;
    }

    uint8_t* copy_buf = (uint8_t*)HeapAlloc(GetProcessHeap(), 0, content_len);
    if (copy_buf == NULL) {
        return S_OK;
    }
    ULONG read_len = 0;
    if (SUCCEEDED(IAmsiStream_Read(stream, 0, content_len, copy_buf, &read_len)) && read_len > 0) {
        *result = (AMSI_RESULT)GrdrAmsiScanBuffer(copy_buf, read_len, NULL);
    }
    SecureZeroMemory(copy_buf, content_len);
    HeapFree(GetProcessHeap(), 0, copy_buf);
    return S_OK;
}

static void STDMETHODCALLTYPE GrdrProvider_CloseSession(
    IAntimalwareProvider* this_ptr,
    ULONGLONG session
) {
    (void)this_ptr;
    (void)session;
}

static HRESULT STDMETHODCALLTYPE GrdrProvider_DisplayName(
    IAntimalwareProvider* this_ptr,
    LPWSTR* display_name
) {
    (void)this_ptr;
    if (display_name == NULL) {
        return E_POINTER;
    }
    static const wchar_t k_name[] = L"Guardrails ADR AMSI Provider";
    LPWSTR copy = (LPWSTR)CoTaskMemAlloc(sizeof(k_name));
    if (copy == NULL) {
        return E_OUTOFMEMORY;
    }
    CopyMemory(copy, k_name, sizeof(k_name));
    *display_name = copy;
    return S_OK;
}

static const IAntimalwareProviderVtbl g_provider_vtbl = {
    GrdrProvider_QueryInterface,
    GrdrProvider_AddRef,
    GrdrProvider_Release,
    GrdrProvider_Scan,
    GrdrProvider_CloseSession,
    GrdrProvider_DisplayName
};

static HRESULT STDMETHODCALLTYPE GrdrFactory_QueryInterface(
    IClassFactory* this_ptr,
    REFIID riid,
    void** ppv
) {
    if (ppv == NULL) {
        return E_POINTER;
    }
    *ppv = NULL;
    if (IsEqualIID(riid, &IID_IUnknown) || IsEqualIID(riid, &IID_IClassFactory)) {
        *ppv = this_ptr;
        IClassFactory_AddRef(this_ptr);
        return S_OK;
    }
    return E_NOINTERFACE;
}

static ULONG STDMETHODCALLTYPE GrdrFactory_AddRef(IClassFactory* this_ptr) {
    GrdrClassFactoryObj* self = (GrdrClassFactoryObj*)this_ptr;
    return (ULONG)InterlockedIncrement(&self->ref_count);
}

static ULONG STDMETHODCALLTYPE GrdrFactory_Release(IClassFactory* this_ptr) {
    GrdrClassFactoryObj* self = (GrdrClassFactoryObj*)this_ptr;
    LONG refs = InterlockedDecrement(&self->ref_count);
    if (refs == 0) {
        HeapFree(GetProcessHeap(), 0, self);
        InterlockedDecrement(&g_dll_ref_count);
    }
    return (ULONG)refs;
}

static HRESULT STDMETHODCALLTYPE GrdrFactory_CreateInstance(
    IClassFactory* this_ptr,
    IUnknown* pUnkOuter,
    REFIID riid,
    void** ppv
) {
    (void)this_ptr;
    if (pUnkOuter != NULL) {
        return CLASS_E_NOAGGREGATION;
    }
    GrdrAmsiProviderObj* provider = (GrdrAmsiProviderObj*)HeapAlloc(
        GetProcessHeap(),
        HEAP_ZERO_MEMORY,
        sizeof(GrdrAmsiProviderObj)
    );
    if (provider == NULL) {
        return E_OUTOFMEMORY;
    }
    provider->lpVtbl = &g_provider_vtbl;
    provider->ref_count = 1;
    InterlockedIncrement(&g_dll_ref_count);
    HRESULT hr = GrdrProvider_QueryInterface((IAntimalwareProvider*)provider, riid, ppv);
    GrdrProvider_Release((IAntimalwareProvider*)provider);
    return hr;
}

static HRESULT STDMETHODCALLTYPE GrdrFactory_LockServer(IClassFactory* this_ptr, BOOL flock) {
    (void)this_ptr;
    if (flock) {
        InterlockedIncrement(&g_dll_ref_count);
    } else {
        InterlockedDecrement(&g_dll_ref_count);
    }
    return S_OK;
}

static const IClassFactoryVtbl g_factory_vtbl = {
    GrdrFactory_QueryInterface,
    GrdrFactory_AddRef,
    GrdrFactory_Release,
    GrdrFactory_CreateInstance,
    GrdrFactory_LockServer
};

HRESULT __stdcall DllGetClassObject(REFCLSID rclsid, REFIID riid, LPVOID* ppv) {
    if (ppv == NULL) {
        return E_POINTER;
    }
    *ppv = NULL;
    if (!IsEqualCLSID(rclsid, &CLSID_GrdrAmsiProvider)) {
        return CLASS_E_CLASSNOTAVAILABLE;
    }
    GrdrClassFactoryObj* factory = (GrdrClassFactoryObj*)HeapAlloc(
        GetProcessHeap(),
        HEAP_ZERO_MEMORY,
        sizeof(GrdrClassFactoryObj)
    );
    if (factory == NULL) {
        return E_OUTOFMEMORY;
    }
    factory->lpVtbl = &g_factory_vtbl;
    factory->ref_count = 1;
    InterlockedIncrement(&g_dll_ref_count);
    HRESULT hr = GrdrFactory_QueryInterface((IClassFactory*)factory, riid, ppv);
    GrdrFactory_Release((IClassFactory*)factory);
    return hr;
}

HRESULT __stdcall DllCanUnloadNow(void) {
    return (InterlockedCompareExchange(&g_dll_ref_count, 0, 0) == 0) ? S_OK : S_FALSE;
}

HRESULT __stdcall DllRegisterServer(void) {
    return S_OK;
}

HRESULT __stdcall DllUnregisterServer(void) {
    InterlockedExchange(&g_circuit_open, 1);
    return S_OK;
}
