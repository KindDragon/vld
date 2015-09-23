////////////////////////////////////////////////////////////////////////////////
//
//  Visual Leak Detector - Test Suite
//  Copyright (c) 2005-2014 VLD Team
//
//  This library is free software; you can redistribute it and/or
//  modify it under the terms of the GNU Lesser General Public
//  License as published by the Free Software Foundation; either
//  version 2.1 of the License, or (at your option) any later version.
//
//  This library is distributed in the hope that it will be useful,
//  but WITHOUT ANY WARRANTY; without even the implied warranty of
//  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
//  Lesser General Public License for more details.
//
//  You should have received a copy of the GNU Lesser General Public
//  License along with this library; if not, write to the Free Software
//  Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
//
//  See COPYING.txt for the full terms of the GNU Lesser General Public License.
//
////////////////////////////////////////////////////////////////////////////////

////////////////////////////////////////////////////////////////////////////////
//
//  Test suite for Visual Leak Detector
//
////////////////////////////////////////////////////////////////////////////////

#include <cassert>
#include <cstdio>
#include <windows.h>
#include <tchar.h>
#include <process.h>

#include <vld.h>

#include <gtest/gtest.h>

enum action_e {
    a_calloc,
    a_comalloc,
    a_getprocmalloc,
    a_heapalloc,
    a_icomalloc,
    a_ignored,
    a_malloc,
    a_new,
    numactions
};

// Name of the debug C Runtime Library DLL on this system
#ifdef _DEBUG
#if _MSC_VER == 1400	// VS 2005
#define CRTDLLNAME   _T("msvcr80d.dll")
#elif _MSC_VER == 1500	// VS 2008
#define CRTDLLNAME   _T("msvcr90d.dll")
#elif _MSC_VER == 1600	// VS 2010
#define CRTDLLNAME   _T("msvcr100d.dll")
#elif _MSC_VER == 1700	// VS 2012
#define CRTDLLNAME   _T("msvcr110d.dll")
#elif _MSC_VER == 1800	// VS 2013
#define CRTDLLNAME   _T("msvcr120d.dll")
#elif _MSC_VER == 1900	// VS 2015
#define CRTDLLNAME   _T("ucrtbased.dll")
#else
#error Unsupported compiler
#endif
#else
#if _MSC_VER == 1400	// VS 2005
#define CRTDLLNAME   _T("msvcr80.dll")
#elif _MSC_VER == 1500	// VS 2008
#define CRTDLLNAME   _T("msvcr90.dll")
#elif _MSC_VER == 1600	// VS 2010
#define CRTDLLNAME   _T("msvcr100.dll")
#elif _MSC_VER == 1700	// VS 2012
#define CRTDLLNAME   _T("msvcr110.dll")
#elif _MSC_VER == 1800	// VS 2013
#define CRTDLLNAME   _T("msvcr120.dll")
#elif _MSC_VER == 1900	// VS 2015
#define CRTDLLNAME   _T("ucrtbase.dll")
#else
#error Unsupported compiler
#endif
#endif

//#define FASTSTACKWALK

static int MAXALLOC = 0;                     // Maximum number of allocations of each type to perform, per thread
static int NUMTHREADS = 0;                   // Number of threads to run simultaneously
static int MAXBLOCKS = 0;                    // Total maximum number of allocations, per thread

static const int MAXDEPTH = 32;              // Maximum depth of the allocation call stack
static const int MAXSIZE = 64;               // Maximum block size to allocate
static const int MINDEPTH = 0;               // Minimum depth of the allocation call stack
static const int MINSIZE = 16;               // Minimum block size to allocate
static const int NUMDUPLEAKS = 3;            // Number of times to duplicate each leak
static const int ONCEINAWHILE = 10;          // Free a random block approx. once every...

struct blockholder_t {
    PVOID    block;
    action_e action;
    bool     leak;
};

typedef void* (__cdecl *free_t) (void* mem);
typedef void* (__cdecl *malloc_t) (size_t size);

struct threadcontext_t {
    UINT  index;
    BOOL  leaky;
    DWORD seed;
    unsigned threadid;
};

__declspec(thread) blockholder_t *blocks = NULL;
__declspec(thread) ULONG          freeBlock = (ULONG)0;
__declspec(thread) ULONG          counts [numactions] = { 0 };
__declspec(thread) IMalloc       *imalloc = NULL;
__declspec(thread) free_t         pfree = NULL;
__declspec(thread) malloc_t       pmalloc = NULL;
__declspec(thread) HANDLE         threadheap;
__declspec(thread) ULONG          total_allocs = 0;

volatile           LONG           leaks_count = 0;

ULONG random (ULONG max)
{
    FLOAT d;
    FLOAT r;
    ULONG v;

    r = ((FLOAT)rand()) / ((FLOAT)RAND_MAX);
    r *= ((FLOAT)max);
    d = r - ((ULONG)r);
    if (d >= 0.5) {
        v = ((ULONG)r) + 1;
    }
    else {
        v = (ULONG)r;
    }

    return v;
}

VOID allocateblock (action_e action, SIZE_T size)
{
    HMODULE  crt;
    ULONG    index;
    ULONG    index2;
    LPCSTR   name;
    PVOID   *pblock;
    HRESULT  status;

    // Find the first unused index.
    index = freeBlock;
    for (index2 = freeBlock + 1; index2 < MAXBLOCKS; index2++) {
        if (blocks[index2].block == NULL) {
            freeBlock = index2;
            break;
        }
    }
    blocks[index].action = action;

    // Now do the randomized allocation.
    pblock = &blocks[index].block;
    switch (action) {
    case a_calloc:
        name = "calloc";
        *pblock = calloc(1, size);
        break;

    case a_comalloc:
        name = "CoTaskMemAlloc";
        *pblock = CoTaskMemAlloc(size);
        break;

    case a_getprocmalloc:
        name = "GetProcAddress";
        if (pmalloc == NULL) {
            crt = LoadLibrary(CRTDLLNAME);
            assert(crt != NULL);
            pmalloc = (malloc_t)GetProcAddress(crt, "malloc");
            assert(pmalloc !=  NULL);
        }
        *pblock = pmalloc(size);
        break;

    case a_heapalloc:
        name = "HeapAlloc";
        if (threadheap == NULL) {
            threadheap = HeapCreate(0x0, 0, 0);
        }
        *pblock = HeapAlloc(threadheap, 0x0, size);
        break;

    case a_icomalloc:
        name = "IMalloc";
        if (imalloc == NULL) {
            status = CoGetMalloc(1, &imalloc);
            assert(status == S_OK);
        }
        *pblock = imalloc->Alloc(size);
        break;

    case a_ignored:
        name = "Ignored";
        VLDDisable();
        *pblock = malloc(size);
        VLDRestore();
        break;

    case a_malloc:
        name = "malloc";
        *pblock = malloc(size);
        break;

    case a_new:
        name = "new";
        *pblock = new BYTE [size];
        break;

    default:
        assert(FALSE);
    }
    counts[action]++;
    total_allocs++;

    strncpy_s((char*)*pblock, size, name, _TRUNCATE);
}

VOID freeblock (ULONG index)
{
    PVOID   block;
    HMODULE crt;

    block = blocks[index].block;
    switch (blocks[index].action) {
    case a_calloc:
        free(block);
        break;

    case a_comalloc:
        CoTaskMemFree(block);
        break;

    case a_getprocmalloc:
        if (pfree == NULL) {
            crt = GetModuleHandle(CRTDLLNAME);
            assert(crt != NULL);
            pfree = (free_t)GetProcAddress(crt, "free");
            assert(pfree != NULL);
        }
        pfree(block);
        break;

    case a_heapalloc:
        HeapFree(threadheap, 0x0, block);
        break;

    case a_icomalloc:
        imalloc->Free(block);
        break;

    case a_ignored:
        free(block);
        break;

    case a_malloc:
        free(block);
        break;

    case a_new:
        delete [] block;
        break;

    default:
        assert(FALSE);
    }
    blocks[index].block = NULL;
    if (index < freeBlock)
        freeBlock = index;
    counts[blocks[index].action]--;
    total_allocs--;
}

VOID recursivelyallocate (UINT depth, action_e action, SIZE_T size)
{
    if (depth == 0) {
        allocateblock(action, size);
    }
    else {
        recursivelyallocate(depth - 1, action, size);
    }
}

unsigned __stdcall threadproc_test (LPVOID param)
{
    threadcontext_t* context = (threadcontext_t*)param;
    assert(context);

    blocks = new blockholder_t[MAXBLOCKS];
    for (ULONG index = 0; index < MAXBLOCKS; index++) {
        blocks[index].block = NULL;
        blocks[index].leak = FALSE;
    }

    srand(context->seed);

    BOOL   allocate_more = TRUE;
    while (allocate_more != FALSE) {
        // Select a random allocation action and a random size.
        action_e action = (action_e)random(numactions - 1);
        SIZE_T size = random(MAXSIZE);
        if (size < MINSIZE) {
            size = MINSIZE;
        }
        if (counts[action] == MAXALLOC) {
            // We've done enough of this type of allocation. Select another.
            continue;
        }

        // Allocate a block, using recursion to build up a stack of random
        // depth.
        UINT depth = random(MAXDEPTH);
        recursivelyallocate(depth, action, size);

        // Every once in a while, free a random block.
        if (random(ONCEINAWHILE) == ONCEINAWHILE) {
            ULONG index = random(total_allocs);
            if (blocks[index].block != NULL) {
                freeblock(index);
            }
        }

        // See if we have allocated enough blocks using each type of action.
        for (USHORT action_index = 0; action_index < numactions; action_index++) {
            if (counts[action_index] < MAXALLOC) {
                allocate_more = TRUE;
                break;
            }
            allocate_more = FALSE;
        }
    }

    if (context->leaky != FALSE) {
        // This is the leaky thread. Randomly select one block to be leaked from
        // each type of allocation action.
        for (USHORT action_index = 0; action_index < numactions; action_index++) {
            UINT leaks_selected = 0;
            do {
                ULONG index = random(MAXBLOCKS);
                if (!blocks[index].leak && (blocks[index].block != NULL) && (blocks[index].action == (action_e)action_index)) {
                    blocks[index].leak = TRUE;
                    leaks_selected++;
                    if (blocks[index].action != a_ignored)
                        InterlockedIncrement(&leaks_count);
                }
            } while (leaks_selected < (1 + NUMDUPLEAKS));
        }
    }

    // Free all blocks except for those marked as leaks.
    for (ULONG index = 0; index < MAXBLOCKS; index++) {
        if ((blocks[index].block != NULL) && (blocks[index].leak == FALSE)) {
            freeblock(index);
        }
    }

    // Do a sanity check.
    if (context->leaky != FALSE) {
        assert(total_allocs == (numactions * (1 + NUMDUPLEAKS)));
    }
    else {
        assert(total_allocs == 0);
    }

    delete[] blocks;
    return 0;
}

void RunTestSuite()
{
    if (!(VLDGetOptions() & VLD_OPT_SAFE_STACK_WALK))
    {
        MAXALLOC = 1000;
        NUMTHREADS = 63;
    }
    else
    {
        MAXALLOC = 10;
        NUMTHREADS = 15;
    }
    MAXBLOCKS = (MAXALLOC * numactions);

    threadcontext_t* contexts = new threadcontext_t[NUMTHREADS];

    // Select a random thread to be the leaker.
    UINT leakythread = random(NUMTHREADS - 1);
    HANDLE* threads = new HANDLE[NUMTHREADS];

    for (UINT index = 0; index < NUMTHREADS; ++index) {
        contexts[index].index = index;
        if (index == leakythread)
            contexts[index].leaky = TRUE;
        else
            contexts[index].leaky = FALSE;
        contexts[index].seed = random(RAND_MAX);
        HANDLE hthread = (HANDLE)_beginthreadex(NULL, 0, threadproc_test, &contexts[index], 0, &contexts[index].threadid);
        threads[index] = hthread;
    }

    // Wait for all threads to terminate.
    BOOL wait_for_all = TRUE;
    DWORD result = WaitForMultipleObjects(NUMTHREADS, threads, wait_for_all, INFINITE);
    switch (result)
    {
    case WAIT_OBJECT_0:
        _tprintf(_T("All threads finished correctly.\n"));
        break;
    case WAIT_ABANDONED_0:
        _tprintf(_T("Abandoned mutex.\n"));
        break;
    case WAIT_TIMEOUT:
        _tprintf(_T("All threads timed out\n"));
        break;
    case WAIT_FAILED:
        {
            _tprintf(_T("Function call to Wait failed with unknown error\n"));
            TCHAR lpMsgBuf[MAX_PATH] = {0};
            FormatMessage(
                FORMAT_MESSAGE_FROM_SYSTEM |
                FORMAT_MESSAGE_IGNORE_INSERTS,
                NULL,
                GetLastError(),
                MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
                lpMsgBuf,
                MAX_PATH,
                NULL );

            _tprintf(_T("%s"), lpMsgBuf);
        }

        break;
    default:
        _tprintf(_T("Some other return value\n"));
        break;
    }
    delete[] contexts;
    delete[] threads;
}

TEST(TestSuit, MultiThread)
{
    int prevleaks = static_cast<int>(VLDGetLeaksCount());
    RunTestSuite();
    int totalleaks = static_cast<int>(VLDGetLeaksCount());
    int leaks = totalleaks - prevleaks;
    ASSERT_EQ(leaks, leaks_count);
}

int main(int argc, char **argv) {
    ::testing::InitGoogleTest(&argc, argv);
    int res = RUN_ALL_TESTS();
    VLDMarkAllLeaksAsReported();
    return res;
}
