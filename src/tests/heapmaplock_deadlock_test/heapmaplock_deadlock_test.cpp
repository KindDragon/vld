// heapmaplock_deadlock_test.cpp - VLD must not resolve symbols while holding
// g_heapMapLock.
//
// VLDGetLeaksCount holds g_heapMapLock (taken by every allocation hook) while
// it resolves leak call stacks with dbghelp. dbghelp loads a module's symbols
// on first use, and that load can need the loader lock (a symbol server path
// makes symsrv/wininet load DLLs). A thread running DLL_THREAD_ATTACH holds the
// loader lock and blocks in VLD's allocation hook on g_heapMapLock: deadlock.
//
// This test makes that ordering deterministic. A dbghelp callback on the
// deferred symbol load of the helper DLL starts a thread whose
// DLL_THREAD_ATTACH in the helper allocates, waits until that thread is inside
// thread attach (holding the loader lock), then calls LoadLibrary, standing in
// for symsrv. If VLD is inside g_heapMapLock at that point, neither thread can
// proceed; a watchdog reports the deadlock and terminates the process.

#include <windows.h>
#include <stdio.h>
#include <string.h>
#include "vld.h"

namespace
{
// From the SDK dbghelp.h, which this test cannot include (VLD's src/dbghelp.h
// shadows it).
const ULONG CBA_DEFERRED_SYMBOL_LOAD_START = 0x00000001;
struct DeferredSymbolLoadW64
{
    DWORD SizeOfStruct;
    DWORD64 BaseOfImage;
    DWORD CheckSum;
    DWORD TimeDateStamp;
    WCHAR FileName[MAX_PATH + 1];
};
typedef BOOL (CALLBACK* SymbolRegisteredCallback64)(HANDLE, ULONG, ULONG64, ULONG64);

typedef void (*ArmThreadAttach_t)(HANDLE);
typedef LONG (*IsInThreadAttachAlloc_t)();
typedef void* (*LeakFromHelper_t)(size_t);
typedef BOOL (WINAPI* SymRegisterCallbackW64_t)(HANDLE, SymbolRegisteredCallback64, ULONG64);

const DWORD WATCHDOG_MS = 30000;
const wchar_t HELPER_DLL[] = L"heapmaplock_deadlock_dll.dll";

ArmThreadAttach_t g_armThreadAttach = NULL;
IsInThreadAttachAlloc_t g_isInThreadAttachAlloc = NULL;
HANDLE g_inThreadAttach = NULL;
HANDLE g_done = NULL;
volatile LONG g_callbackArmed = 0;
volatile LONG g_callbackFired = 0;
volatile LONG g_inLoadLibrary = 0;

void WriteStdout(const char* text)
{
    DWORD written;
    WriteFile(GetStdHandle(STD_OUTPUT_HANDLE), text, (DWORD)strlen(text), &written, NULL);
}

DWORD WINAPI Watchdog(LPVOID)
{
    if (WaitForSingleObject(g_done, WATCHDOG_MS) == WAIT_TIMEOUT)
    {
        char state[256];
        sprintf_s(state, "main thread: in VLDGetLeaksCount -> dbghelp deferred symbol load -> LoadLibrary: %s\n"
            "new thread: in helper DLL_THREAD_ATTACH (loader lock held) -> malloc -> VLD hook: %s\n",
            InterlockedCompareExchange(&g_inLoadLibrary, 0, 0) ? "yes" : "no",
            g_isInThreadAttachAlloc() ? "yes" : "no");
        WriteStdout(state);
        // ExitProcess would need the loader lock, which is part of the deadlock.
        WriteStdout("FAIL: DEADLOCK - VLD resolved symbols while holding g_heapMapLock\n");
        TerminateProcess(GetCurrentProcess(), 3);
    }
    return 0;
}

DWORD WINAPI NewThread(LPVOID)
{
    return 0;
}

BOOL CALLBACK SymbolCallback(HANDLE, ULONG action, ULONG64 data, ULONG64)
{
    if (action != CBA_DEFERRED_SYMBOL_LOAD_START || data == 0)
        return FALSE;
    const DeferredSymbolLoadW64* load = (const DeferredSymbolLoadW64*)data;
    if (wcsstr(load->FileName, L"heapmaplock_deadlock_dll") == NULL)
        return FALSE;
    if (InterlockedExchange(&g_callbackArmed, 0) == 0)
        return FALSE;
    InterlockedExchange(&g_callbackFired, 1);

    // A thread that holds the loader lock (DLL_THREAD_ATTACH) and allocates.
    g_armThreadAttach(g_inThreadAttach);
    HANDLE thread = CreateThread(NULL, 0, NewThread, NULL, 0, NULL);
    if (thread == NULL || WaitForSingleObject(g_inThreadAttach, 10000) != WAIT_OBJECT_0)
    {
        WriteStdout("FAIL: helper DLL_THREAD_ATTACH did not run\n");
        TerminateProcess(GetCurrentProcess(), 2);
    }

    // What symsrv/wininet do while loading symbols: take the loader lock.
    InterlockedExchange(&g_inLoadLibrary, 1);
    HMODULE version = LoadLibraryW(L"version.dll");
    InterlockedExchange(&g_inLoadLibrary, 0);
    if (version != NULL)
        FreeLibrary(version);
    WaitForSingleObject(thread, INFINITE);
    CloseHandle(thread);
    return FALSE;
}
}

int main()
{
    g_done = CreateEventW(NULL, TRUE, FALSE, NULL);
    g_inThreadAttach = CreateEventW(NULL, TRUE, FALSE, NULL);
    HANDLE watchdog = CreateThread(NULL, 0, Watchdog, NULL, 0, NULL);
    if (g_done == NULL || g_inThreadAttach == NULL || watchdog == NULL)
    {
        printf("FAIL: setup\n");
        return 2;
    }

    HMODULE helper = LoadLibraryW(HELPER_DLL);
    if (helper == NULL)
    {
        printf("FAIL: LoadLibrary(%ls) failed, error %lu\n", HELPER_DLL, GetLastError());
        return 2;
    }
    g_armThreadAttach = (ArmThreadAttach_t)GetProcAddress(helper, "ArmThreadAttach");
    g_isInThreadAttachAlloc = (IsInThreadAttachAlloc_t)GetProcAddress(helper, "IsInThreadAttachAlloc");
    LeakFromHelper_t leakFromHelper = (LeakFromHelper_t)GetProcAddress(helper, "LeakFromHelper");

    // The same dbghelp instance and process handle VLD uses.
    HMODULE dbghelp = GetModuleHandleW(L"dbghelp.dll");
    SymRegisterCallbackW64_t symRegisterCallbackW64 = dbghelp == NULL ? NULL :
        (SymRegisterCallbackW64_t)GetProcAddress(dbghelp, "SymRegisterCallbackW64");
    if (g_armThreadAttach == NULL || g_isInThreadAttachAlloc == NULL || leakFromHelper == NULL ||
        symRegisterCallbackW64 == NULL ||
        !symRegisterCallbackW64(GetCurrentProcess(), SymbolCallback, 0))
    {
        printf("FAIL: could not set up the helper DLL or the dbghelp callback\n");
        return 2;
    }

    // A leak whose call stack runs through the helper, whose symbols are not loaded yet.
    void* leak = leakFromHelper(64);

    InterlockedExchange(&g_callbackArmed, 1);
    SIZE_T leaks = VLDGetLeaksCount();
    SetEvent(g_done);
    WaitForSingleObject(watchdog, INFINITE);

    free(leak);
    VLDMarkAllLeaksAsReported();

    if (InterlockedCompareExchange(&g_callbackFired, 0, 0) == 0)
    {
        printf("FAIL: the deferred symbol load of the helper DLL never happened (inconclusive)\n");
        return 2;
    }
    printf("PASS: no deadlock (%zu leaks counted)\n", leaks);
    return 0;
}
