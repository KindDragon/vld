// heapmaplock_deadlock_dll.cpp - helper for heapmaplock_deadlock_test.
//
// Links VLD so that its allocations are tracked (VLD's allocation hooks take
// g_heapMapLock). Once armed, the next DLL_THREAD_ATTACH, which runs while
// the new thread holds the loader lock, signals the test and then allocates.

#include <windows.h>
#include <stdlib.h>
#include "vld.h"

static volatile LONG g_armed = 0;
static volatile LONG g_inThreadAttachAlloc = 0;
static HANDLE g_inThreadAttach = NULL;

extern "C" __declspec(dllexport) void ArmThreadAttach(HANDLE inThreadAttach)
{
    g_inThreadAttach = inThreadAttach;
    InterlockedExchange(&g_armed, 1);
}

extern "C" __declspec(dllexport) LONG IsInThreadAttachAlloc()
{
    return InterlockedCompareExchange(&g_inThreadAttachAlloc, 0, 0);
}

#pragma optimize("", off)
extern "C" __declspec(dllexport) __declspec(noinline) void* LeakFromHelper(size_t size)
{
    return malloc(size);
}
#pragma optimize("", on)

BOOL APIENTRY DllMain(HMODULE, DWORD reason, LPVOID)
{
    if (reason == DLL_THREAD_ATTACH && InterlockedExchange(&g_armed, 0) != 0)
    {
        InterlockedExchange(&g_inThreadAttachAlloc, 1);
        SetEvent(g_inThreadAttach);
        void* p = malloc(16);
        free(p);
        InterlockedExchange(&g_inThreadAttachAlloc, 0);
    }
    return TRUE;
}
