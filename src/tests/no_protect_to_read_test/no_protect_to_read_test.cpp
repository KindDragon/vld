// no_protect_to_read_test.cpp - VLD must not change page protection just to
// read memory.
//
// While resolving import thunks (FindRealCode) VLD used to VirtualProtect the
// thunk, the IAT slot and every jump target to PAGE_EXECUTE_READ and restore it
// afterwards. Under x64 emulation on ARM64 the system DLLs are ARM64X images
// whose IAT slots live in ntdll data pages; protecting such a page notifies the
// loader, which writes to the page VLD just made read-only and faults. The
// unwind skips the restore, the ntdll data page stays read-only and the process
// later crashes in FLS cleanup. Natively the transition is a latent race.
//
// The crash depends on the OS build, so this test checks the cause instead:
// it loads VLD dynamically, redirects VLD's VirtualProtect import to a wrapper
// before VLD's initializers run, and fails if VLD ever requests a non-writable
// protection that is not the restore of one of its own earlier calls.

#include <Windows.h>
#include <winternl.h>

#include <cstdio>
#include <cstring>

#ifndef VLD_DLL_NAME
#error VLD_DLL_NAME must be defined
#endif

namespace
{
typedef struct _LDR_DLL_LOADED_NOTIFICATION_DATA
{
    ULONG Flags;
    PCUNICODE_STRING FullDllName;
    PCUNICODE_STRING BaseDllName;
    PVOID DllBase;
    ULONG SizeOfImage;
} LDR_DLL_LOADED_NOTIFICATION_DATA;

typedef VOID(CALLBACK* LDR_DLL_NOTIFICATION_FUNCTION)(ULONG, const LDR_DLL_LOADED_NOTIFICATION_DATA*, PVOID);
typedef NTSTATUS(NTAPI* LdrRegisterDllNotification_t)(ULONG, LDR_DLL_NOTIFICATION_FUNCTION, PVOID, PVOID*);
typedef NTSTATUS(NTAPI* LdrUnregisterDllNotification_t)(PVOID);

const ULONG LDR_DLL_NOTIFICATION_REASON_LOADED = 1;

using VirtualProtectFunction = decltype(&VirtualProtect);
VirtualProtectFunction g_realVirtualProtect = nullptr;
volatile LONG g_hooked = 0;

// The static UCRT linked into VLD makes its own .fptable section read-only on
// purpose; that is hardening, not a read.
unsigned char* g_fptableBegin = nullptr;
unsigned char* g_fptableEnd = nullptr;

struct PendingRestore
{
    LPVOID address;
    SIZE_T size;
    DWORD oldProtect;
};

struct Violation
{
    LPVOID address;
    DWORD newProtect;
    DWORD oldProtect;
};

const size_t MAX_PENDING = 4096;
const size_t MAX_REPORTED = 16;

SRWLOCK g_lock = SRWLOCK_INIT;
PendingRestore g_pending[MAX_PENDING];
size_t g_pendingCount = 0;
size_t g_totalCalls = 0;
size_t g_violations = 0;
Violation g_reported[MAX_REPORTED];

bool IsWritable(DWORD protect)
{
    switch (protect & 0xFF)
    {
    case PAGE_READWRITE:
    case PAGE_WRITECOPY:
    case PAGE_EXECUTE_READWRITE:
    case PAGE_EXECUTE_WRITECOPY:
        return true;
    default:
        return false;
    }
}

BOOL WINAPI CountingVirtualProtect(LPVOID address, SIZE_T size, DWORD newProtect, PDWORD oldProtect)
{
    DWORD previous = 0;
    BOOL result = g_realVirtualProtect(address, size, newProtect, &previous);
    if (oldProtect != nullptr)
    {
        *oldProtect = previous;
    }
    if (!result)
    {
        return result;
    }

    AcquireSRWLockExclusive(&g_lock);
    g_totalCalls++;

    bool isRestore = false;
    for (size_t i = g_pendingCount; i > 0; i--)
    {
        if (g_pending[i - 1].address == address && g_pending[i - 1].size == size &&
            g_pending[i - 1].oldProtect == newProtect)
        {
            g_pending[i - 1] = g_pending[--g_pendingCount];
            isRestore = true;
            break;
        }
    }

    if (!isRestore)
    {
        bool isFptable = static_cast<unsigned char*>(address) >= g_fptableBegin &&
            static_cast<unsigned char*>(address) < g_fptableEnd;
        if (!IsWritable(newProtect) && !isFptable)
        {
            if (g_violations < MAX_REPORTED)
            {
                g_reported[g_violations] = { address, newProtect, previous };
            }
            g_violations++;
        }
        if (g_pendingCount < MAX_PENDING)
        {
            g_pending[g_pendingCount++] = { address, size, previous };
        }
    }

    ReleaseSRWLockExclusive(&g_lock);
    return result;
}

bool HookVirtualProtectImport(unsigned char* imageBase)
{
    auto* dosHeader = reinterpret_cast<IMAGE_DOS_HEADER*>(imageBase);
    auto* ntHeaders = reinterpret_cast<IMAGE_NT_HEADERS*>(imageBase + dosHeader->e_lfanew);

    IMAGE_SECTION_HEADER* section = IMAGE_FIRST_SECTION(ntHeaders);
    for (WORD i = 0; i < ntHeaders->FileHeader.NumberOfSections; i++, section++)
    {
        if (std::strncmp(reinterpret_cast<const char*>(section->Name), ".fptable", IMAGE_SIZEOF_SHORT_NAME) == 0)
        {
            g_fptableBegin = imageBase + section->VirtualAddress;
            g_fptableEnd = g_fptableBegin + section->Misc.VirtualSize;
        }
    }

    const IMAGE_DATA_DIRECTORY& importDirectory =
        ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
    if (importDirectory.VirtualAddress == 0)
    {
        return false;
    }

    auto* importDescriptor = reinterpret_cast<IMAGE_IMPORT_DESCRIPTOR*>(imageBase + importDirectory.VirtualAddress);
    for (; importDescriptor->Name != 0; ++importDescriptor)
    {
        if (importDescriptor->OriginalFirstThunk == 0)
        {
            continue;
        }

        auto* nameThunk = reinterpret_cast<IMAGE_THUNK_DATA*>(imageBase + importDescriptor->OriginalFirstThunk);
        auto* addressThunk = reinterpret_cast<IMAGE_THUNK_DATA*>(imageBase + importDescriptor->FirstThunk);
        for (; nameThunk->u1.AddressOfData != 0; ++nameThunk, ++addressThunk)
        {
            if (IMAGE_SNAP_BY_ORDINAL(nameThunk->u1.Ordinal))
            {
                continue;
            }

            auto* importByName = reinterpret_cast<IMAGE_IMPORT_BY_NAME*>(imageBase + nameThunk->u1.AddressOfData);
            if (std::strcmp(reinterpret_cast<const char*>(importByName->Name), "VirtualProtect") != 0)
            {
                continue;
            }

            DWORD oldProtection;
            if (!VirtualProtect(&addressThunk->u1.Function, sizeof(addressThunk->u1.Function), PAGE_READWRITE, &oldProtection))
            {
                return false;
            }
            g_realVirtualProtect = reinterpret_cast<VirtualProtectFunction>(addressThunk->u1.Function);
            addressThunk->u1.Function = reinterpret_cast<ULONG_PTR>(&CountingVirtualProtect);
            DWORD ignored;
            VirtualProtect(&addressThunk->u1.Function, sizeof(addressThunk->u1.Function), oldProtection, &ignored);
            return true;
        }
    }
    return false;
}

// Runs after the VLD DLL's imports are bound and before its initializers.
VOID CALLBACK OnDllNotification(ULONG reason, const LDR_DLL_LOADED_NOTIFICATION_DATA* data, PVOID)
{
    if (reason != LDR_DLL_NOTIFICATION_REASON_LOADED || data->BaseDllName == nullptr)
    {
        return;
    }

    const wchar_t* vldName = VLD_DLL_NAME;
    size_t nameLength = wcslen(vldName);
    if (data->BaseDllName->Length / sizeof(wchar_t) != nameLength ||
        _wcsnicmp(data->BaseDllName->Buffer, vldName, nameLength) != 0)
    {
        return;
    }

    if (HookVirtualProtectImport(static_cast<unsigned char*>(data->DllBase)))
    {
        InterlockedExchange(&g_hooked, 1);
    }
}
}

int main()
{
    HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");
    auto registerNotification = reinterpret_cast<LdrRegisterDllNotification_t>(
        GetProcAddress(ntdll, "LdrRegisterDllNotification"));
    auto unregisterNotification = reinterpret_cast<LdrUnregisterDllNotification_t>(
        GetProcAddress(ntdll, "LdrUnregisterDllNotification"));
    if (registerNotification == nullptr || unregisterNotification == nullptr)
    {
        std::printf("FAIL: LdrRegisterDllNotification not found\n");
        return 2;
    }

    PVOID cookie = nullptr;
    if (registerNotification(0, &OnDllNotification, nullptr, &cookie) != 0)
    {
        std::printf("FAIL: LdrRegisterDllNotification failed\n");
        return 2;
    }

    // Loading VLD runs its initialization, which patches every loaded module.
    HMODULE vld = LoadLibraryW(VLD_DLL_NAME);
    if (vld == nullptr)
    {
        std::printf("FAIL: LoadLibrary(%ls) failed, error %lu\n", VLD_DLL_NAME, GetLastError());
        return 2;
    }
    if (InterlockedCompareExchange(&g_hooked, 0, 0) == 0)
    {
        std::printf("FAIL: could not hook VirtualProtect in %ls\n", VLD_DLL_NAME);
        return 2;
    }

    // A DLL loaded after VLD is patched from VLD's load notification.
    if (LoadLibraryW(L"version.dll") == nullptr)
    {
        std::printf("FAIL: LoadLibrary(version.dll) failed, error %lu\n", GetLastError());
        return 2;
    }

    unregisterNotification(cookie);

    AcquireSRWLockExclusive(&g_lock);
    size_t totalCalls = g_totalCalls;
    size_t violations = g_violations;
    ReleaseSRWLockExclusive(&g_lock);

    std::printf("VLD VirtualProtect calls: %zu, non-writable protections that are not restores: %zu\n",
        totalCalls, violations);
    for (size_t i = 0; i < violations && i < MAX_REPORTED; i++)
    {
        HMODULE owner = nullptr;
        wchar_t ownerName[MAX_PATH] = L"?";
        if (GetModuleHandleExW(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS | GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
                static_cast<LPCWSTR>(g_reported[i].address), &owner))
        {
            GetModuleFileNameW(owner, ownerName, MAX_PATH);
        }
        std::printf("  %ls+0x%zX new=0x%lX old=0x%lX\n",
            ownerName,
            static_cast<size_t>(static_cast<unsigned char*>(g_reported[i].address) - reinterpret_cast<unsigned char*>(owner)),
            g_reported[i].newProtect, g_reported[i].oldProtect);
    }

    if (totalCalls == 0)
    {
        std::printf("FAIL: no VirtualProtect call went through the hook\n");
        return 2;
    }
    if (violations != 0)
    {
        std::printf("FAIL: VLD changed page protection to read memory\n");
        return 1;
    }
    std::printf("PASS\n");
    return 0;
}
