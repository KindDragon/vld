////////////////////////////////////////////////////////////////////////////////
//
//  Visual Leak Detector - VisualLeakDetector Class Implementation
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

#include "stdafx.h"

#pragma comment(lib, "dbghelp.lib")

#include <sys/stat.h>

#define VLDBUILD         // Declares that we are building Visual Leak Detector.
#include "callstack.h"   // Provides a class for handling call stacks.
#include "crtmfcpatch.h" // Provides CRT and MFC patch functions.
#include "map.h"         // Provides a lightweight STL-like map template.
#include "ntapi.h"       // Provides access to NT APIs.
#include "set.h"         // Provides a lightweight STL-like set template.
#include "utility.h"     // Provides various utility functions.
#include "vldheap.h"     // Provides internal new and delete operators.
#include "vldint.h"      // Provides access to the Visual Leak Detector internals.

//#define PRINTHOOKCALLS
//#define PRINTHOOKCALLS2
#include <tchar.h>

extern HANDLE           g_currentProcess;
extern CriticalSection  g_heapMapLock;
extern CriticalSection  g_symbolLock;

void VisualLeakDetector::firstAllocCall(tls_t * tls)
{
    if (tls->blockWithoutGuard)
    {
        context_t context = tls->context;
        blockinfo_t* pblockInfo = NULL;
        if (tls->newBlockWithoutGuard == NULL)
            AllocateHeap(tls, pblockInfo);
        else
            ReAllocateHeap(tls, pblockInfo);

        // Reset thread local flags and variables in case dbghelp.dll try allocate some data.
        tls->context.fp = NULL;
        tls->context.func = 0x0;
        tls->blockWithoutGuard = NULL;
        tls->flags &= ~VLD_TLS_DEBUGCRTALLOC;

        CallStack* callstack;
        getCallStack(callstack, context);
        pblockInfo->callStack.reset(callstack);
        return;
    }

    // Reset thread local flags and variables for the next allocation.
    tls->context.fp = NULL;
    tls->context.func = 0x0;
    tls->blockWithoutGuard = NULL;
    tls->flags &= ~VLD_TLS_DEBUGCRTALLOC;
}

////////////////////////////////////////////////////////////////////////////////
//
// Standard CRT and MFC IAT Replacement Functions
//
// The addresses of these functions are not actually directly patched into the
// import address tables, but these functions do get indirectly called by the
// patch functions that are placed in the import address tables.
//
////////////////////////////////////////////////////////////////////////////////

// _calloc - This function is just a wrapper around the real calloc that sets
//   appropriate flags to be consulted when the memory is actually allocated by
//   RtlAllocateHeap.
//
//  - pcalloc (IN): Pointer to the particular calloc implementation to call.
//
//  - fp (IN): Frame pointer from the call that initiated this allocation.
//
//  - num (IN): The number of blocks, of size 'size', to be allocated.
//
//  - size (IN): The size, in bytes, of the memory block to be allocated.
//
//  Return Value:
//
//    Returns the value returned from the specified calloc.
//
void* VisualLeakDetector::_calloc (calloc_t pcalloc,
    context_t&  context,
    bool	    debugRuntime,
    size_t      num,
    size_t      size)
{
#ifdef PRINTHOOKCALLS
	DbgReport(_T(__FUNCTION__ "\n"));
#endif
    tls_t *tls = g_vld.getTls();

    // malloc is a CRT function and allocates from the CRT heap.
    if (debugRuntime)
        tls->flags |= VLD_TLS_DEBUGCRTALLOC;

    bool firstcall = (tls->context.fp == 0x0);
    if (firstcall) {
        // This is the first call to enter VLD for the current allocation.
        // Record the current frame pointer.
        tls->context = context;
    }

    // Do the allocation. The block will be mapped by _RtlAllocateHeap.
    void* block = pcalloc(num, size);

    if (firstcall)
        firstAllocCall(tls);

    return block;
}

// _malloc - This function is just a wrapper around the real malloc that sets
//   appropriate flags to be consulted when the memory is actually allocated by
//   RtlAllocateHeap.
//
//  - pmalloc (IN): Pointer to the particular malloc implementation to call.
//
//  - fp (IN): Frame pointer from the call that initiated this allocation.
//
//  - size (IN): The size, in bytes, of the memory block to be allocated.
//
//  Return Value:
//
//    Returns the value returned from the specified malloc.
//
void *VisualLeakDetector::_malloc (malloc_t pmalloc, context_t& context, bool debugRuntime, size_t size)
{
#ifdef PRINTHOOKCALLS
	DbgReport(_T(__FUNCTION__ "\n"));
#endif
    tls_t   *tls = g_vld.getTls();

    // malloc is a CRT function and allocates from the CRT heap.
    if (debugRuntime)
        tls->flags |= VLD_TLS_DEBUGCRTALLOC;

    bool firstcall = (tls->context.fp == 0x0);
    if (firstcall) {
        // This is the first call to enter VLD for the current allocation.
        // Record the current frame pointer.
        tls->context = context;
    }

    // Do the allocation. The block will be mapped by _RtlAllocateHeap.
    void* block = pmalloc(size);

    if (firstcall)
        firstAllocCall(tls);

    return block;
}

// _new - This function is just a wrapper around the real CRT and MFC new
//   operators that sets appropriate flags to be consulted when the memory is
//   actually allocated by RtlAllocateHeap.
//
//  - pnew (IN): Pointer to the particular new implementation to call.
//
//  - fp (IN): Frame pointer from the call that initiated this allocation.
//
//  - size (IN): The size, in bytes, of the memory block to be allocated.
//
//  Return Value:
//
//    Returns the value returned by the specified CRT new operator.
//
void* VisualLeakDetector::_new (new_t pnew, context_t& context, bool debugRuntime, size_t size)
{
#ifdef PRINTHOOKCALLS
	DbgReport(_T(__FUNCTION__ "\n"));
#endif
    tls_t* tls = g_vld.getTls();

    // The new operator is a CRT function and allocates from the CRT heap.
    if (debugRuntime)
        tls->flags |= VLD_TLS_DEBUGCRTALLOC;

    bool firstcall = (tls->context.fp == NULL);
    if (firstcall) {
        // This is the first call to enter VLD for the current allocation.
        // Record the current frame pointer.
        tls->context = context;
    }

	// Do the allocation. The block will be mapped by _RtlAllocateHeap.
	void* block = pnew(size);

    if (firstcall)
        firstAllocCall(tls);

    return block;
}

// _realloc - This function is just a wrapper around the real realloc that sets
//   appropriate flags to be consulted when the memory is actually allocated by
//   RtlAllocateHeap.
//
//  - prealloc (IN): Pointer to the particular realloc implementation to call.
//
//  - fp (IN): Frame pointer from the call that initiated this allocation.
//
//  - mem (IN): Pointer to the memory block to reallocate.
//
//  - size (IN): Size of the memory block to reallocate.
//
//  Return Value:
//
//    Returns the value returned from the specified realloc.
//
void* VisualLeakDetector::_realloc (realloc_t  prealloc,
    context_t&  context,
    bool        debugRuntime,
    void       *mem,
    size_t      size)
{
#ifdef PRINTHOOKCALLS
	DbgReport(_T(__FUNCTION__ "\n"));
#endif
    tls_t *tls = g_vld.getTls();

    // realloc is a CRT function and allocates from the CRT heap.
    if (debugRuntime)
        tls->flags |= VLD_TLS_DEBUGCRTALLOC;

    bool firstcall = (tls->context.fp == 0x0);
    if (firstcall) {
        // This is the first call to enter VLD for the current allocation.
        // Record the current frame pointer.
        tls->context = context;
    }

    // Do the allocation. The block will be mapped by _RtlReAllocateHeap.
    void* block = prealloc(mem, size);

    if (firstcall)
        firstAllocCall(tls);

    return block;
}

// _recalloc - This function is just a wrapper around the real _recalloc that sets
//   appropriate flags to be consulted when the memory is actually allocated by
//   RtlAllocateHeap.
//
//  - prealloc (IN): Pointer to the particular realloc implementation to call.
//
//  - fp (IN): Frame pointer from the call that initiated this allocation.
//
//  - mem (IN): Pointer to the memory block to reallocate.
//
//  - size (IN): Size of the memory block to reallocate.
//
//  Return Value:
//
//    Returns the value returned from the specified realloc.
//
void* VisualLeakDetector::__recalloc (_recalloc_t  precalloc,
    context_t&  context,
    bool        debugRuntime,
    void       *mem,
    size_t      num,
    size_t      size)
{
#ifdef PRINTHOOKCALLS
	DbgReport(_T(__FUNCTION__ "\n"));
#endif
    tls_t *tls = g_vld.getTls();

    // realloc is a CRT function and allocates from the CRT heap.
    if (debugRuntime)
        tls->flags |= VLD_TLS_DEBUGCRTALLOC;

    bool firstcall = (tls->context.fp == 0x0);
    if (firstcall) {
        // This is the first call to enter VLD for the current allocation.
        // Record the current frame pointer.
        tls->context = context;
    }

    // Do the allocation. The block will be mapped by _RtlReAllocateHeap.
    void* block = precalloc(mem, num, size);

    if (firstcall)
        firstAllocCall(tls);

    return block;
}

char* VisualLeakDetector::__strdup( _strdup_t pstrdup, context_t& context, bool debugRuntime, const char* src )
{
#ifdef PRINTHOOKCALLS
	DbgReport(_T(__FUNCTION__ "\n"));
#endif
    tls_t *tls = g_vld.getTls();

    // realloc is a CRT function and allocates from the CRT heap.
    if (debugRuntime)
        tls->flags |= VLD_TLS_DEBUGCRTALLOC;

    bool firstcall = (tls->context.fp == 0x0);
    if (firstcall) {
        // This is the first call to enter VLD for the current allocation.
        // Record the current frame pointer.
        tls->context = context;
    }

    // Do the allocation. The block will be mapped by _RtlReAllocateHeap.
    char* block = pstrdup(src);

    if (firstcall)
        firstAllocCall(tls);

    return block;
}

wchar_t* VisualLeakDetector::__wcsdup( _wcsdup_t pwcsdup, context_t& context, bool debugRuntime, const wchar_t* src )
{
#ifdef PRINTHOOKCALLS
	DbgReport(_T(__FUNCTION__ "\n"));
#endif
    tls_t *tls = g_vld.getTls();

    // realloc is a CRT function and allocates from the CRT heap.
    if (debugRuntime)
        tls->flags |= VLD_TLS_DEBUGCRTALLOC;

    bool firstcall = (tls->context.fp == 0x0);
    if (firstcall) {
        // This is the first call to enter VLD for the current allocation.
        // Record the current frame pointer.
        tls->context = context;
    }

    // Do the allocation. The block will be mapped by _RtlReAllocateHeap.
    wchar_t* block = pwcsdup(src);

    if (firstcall)
        firstAllocCall(tls);

    return block;
}

// __aligned_malloc - This function is just a wrapper around the real malloc that sets
//   appropriate flags to be consulted when the memory is actually allocated by
//   RtlAllocateHeap.
//
//  - pmalloc (IN): Pointer to the particular malloc implementation to call.
//
//  - fp (IN): Frame pointer from the call that initiated this allocation.
//
//  - size (IN): The size, in bytes, of the memory block to be allocated.
//
//  Return Value:
//
//    Returns the value returned from the specified malloc.
//
void *VisualLeakDetector::__aligned_malloc (_aligned_malloc_t pmalloc, context_t& context, bool debugRuntime,
    size_t size, size_t alignment)
{
#ifdef PRINTHOOKCALLS
	DbgReport(_T(__FUNCTION__ "\n"));
#endif
    tls_t   *tls = g_vld.getTls();

    // malloc is a CRT function and allocates from the CRT heap.
    if (debugRuntime)
        tls->flags |= VLD_TLS_DEBUGCRTALLOC;

    bool firstcall = (tls->context.fp == 0x0);
    if (firstcall) {
        // This is the first call to enter VLD for the current allocation.
        // Record the current frame pointer.
        tls->context = context;
    }

    // Do the allocation. The block will be mapped by _RtlAllocateHeap.
    void* block = pmalloc(size, alignment);

    if (firstcall)
        firstAllocCall(tls);

    return block;
}

// __aligned_offset_malloc - This function is just a wrapper around the real malloc that sets
//   appropriate flags to be consulted when the memory is actually allocated by
//   RtlAllocateHeap.
//
//  - pmalloc (IN): Pointer to the particular malloc implementation to call.
//
//  - fp (IN): Frame pointer from the call that initiated this allocation.
//
//  - size (IN): The size, in bytes, of the memory block to be allocated.
//
//  Return Value:
//
//    Returns the value returned from the specified _aligned_offset_malloc.
//
void *VisualLeakDetector::__aligned_offset_malloc (_aligned_offset_malloc_t pmalloc, context_t& context, bool debugRuntime,
    size_t size, size_t alignment, size_t offset)
{
#ifdef PRINTHOOKCALLS
	DbgReport(_T(__FUNCTION__ "\n"));
#endif
    tls_t   *tls = g_vld.getTls();

    // malloc is a CRT function and allocates from the CRT heap.
    if (debugRuntime)
        tls->flags |= VLD_TLS_DEBUGCRTALLOC;

    bool firstcall = (tls->context.fp == 0x0);
    if (firstcall) {
        // This is the first call to enter VLD for the current allocation.
        // Record the current frame pointer.
        tls->context = context;
    }

    // Do the allocation. The block will be mapped by _RtlAllocateHeap.
    void* block = pmalloc(size, alignment, offset);

    if (firstcall)
        firstAllocCall(tls);

    return block;
}

// __aligned_realloc - This function is just a wrapper around the real realloc that sets
//   appropriate flags to be consulted when the memory is actually allocated by
//   RtlAllocateHeap.
//
//  - prealloc (IN): Pointer to the particular realloc implementation to call.
//
//  - fp (IN): Frame pointer from the call that initiated this allocation.
//
//  - mem (IN): Pointer to the memory block to reallocate.
//
//  - size (IN): Size of the memory block to reallocate.
//
//  Return Value:
//
//    Returns the value returned from the specified _aligned_realloc.
//
void* VisualLeakDetector::__aligned_realloc (_aligned_realloc_t  prealloc,
    context_t&  context,
    bool        debugRuntime,
    void       *mem,
    size_t      size,
    size_t      alignment)
{
#ifdef PRINTHOOKCALLS
	DbgReport(_T(__FUNCTION__ "\n"));
#endif
    tls_t *tls = g_vld.getTls();

    // realloc is a CRT function and allocates from the CRT heap.
    if (debugRuntime)
        tls->flags |= VLD_TLS_DEBUGCRTALLOC;

    bool firstcall = (tls->context.fp == 0x0);
    if (firstcall) {
        // This is the first call to enter VLD for the current allocation.
        // Record the current frame pointer.
        tls->context = context;
    }

    // Do the allocation. The block will be mapped by _RtlReAllocateHeap.
    void* block = prealloc(mem, size, alignment);

    if (firstcall)
        firstAllocCall(tls);

    return block;
}

// __aligned_offset_realloc - This function is just a wrapper around the real realloc that sets
//   appropriate flags to be consulted when the memory is actually allocated by
//   RtlAllocateHeap.
//
//  - prealloc (IN): Pointer to the particular realloc implementation to call.
//
//  - fp (IN): Frame pointer from the call that initiated this allocation.
//
//  - mem (IN): Pointer to the memory block to reallocate.
//
//  - size (IN): Size of the memory block to reallocate.
//
//  Return Value:
//
//    Returns the value returned from the specified _aligned_offset_realloc.
//
void* VisualLeakDetector::__aligned_offset_realloc (_aligned_offset_realloc_t  prealloc,
    context_t&  context,
    bool        debugRuntime,
    void       *mem,
    size_t      size,
    size_t      alignment,
    size_t      offset)
{
#ifdef PRINTHOOKCALLS
	DbgReport(_T(__FUNCTION__ "\n"));
#endif
    tls_t *tls = g_vld.getTls();

    // realloc is a CRT function and allocates from the CRT heap.
    if (debugRuntime)
        tls->flags |= VLD_TLS_DEBUGCRTALLOC;

    bool firstcall = (tls->context.fp == 0x0);
    if (firstcall) {
        // This is the first call to enter VLD for the current allocation.
        // Record the current frame pointer.
        tls->context = context;
    }

    // Do the allocation. The block will be mapped by _RtlReAllocateHeap.
    void* block = prealloc(mem, size, alignment, offset);

    if (firstcall)
        firstAllocCall(tls);

    return block;
}

// __aligned_recalloc - This function is just a wrapper around the real recalloc that sets
//   appropriate flags to be consulted when the memory is actually allocated by
//   RtlAllocateHeap.
//
//  - precalloc (IN): Pointer to the particular recalloc implementation to call.
//
//  - fp (IN): Frame pointer from the call that initiated this allocation.
//
//  - mem (IN): Pointer to the memory block to reallocate.
//
//  - num (IN): Count of the memory block to reallocate.
//
//  - size (IN): Size of the memory block to reallocate.
//
//  Return Value:
//
//    Returns the value returned from the specified _aligned_realloc.
//
void* VisualLeakDetector::__aligned_recalloc (_aligned_recalloc_t  precalloc,
    context_t&  context,
    bool        debugRuntime,
    void       *mem,
    size_t      num,
    size_t      size,
    size_t      alignment)
{
#ifdef PRINTHOOKCALLS
	DbgReport(_T(__FUNCTION__ "\n"));
#endif
    tls_t *tls = g_vld.getTls();

    // realloc is a CRT function and allocates from the CRT heap.
    if (debugRuntime)
        tls->flags |= VLD_TLS_DEBUGCRTALLOC;

    bool firstcall = (tls->context.fp == 0x0);
    if (firstcall) {
        // This is the first call to enter VLD for the current allocation.
        // Record the current frame pointer.
        tls->context = context;
    }

    // Do the allocation. The block will be mapped by _RtlReAllocateHeap.
    void* block = precalloc(mem, num, size, alignment);

    if (firstcall)
        firstAllocCall(tls);

    return block;
}

// __aligned_offset_recalloc - This function is just a wrapper around the real recalloc that sets
//   appropriate flags to be consulted when the memory is actually allocated by
//   RtlAllocateHeap.
//
//  - precalloc (IN): Pointer to the particular realloc implementation to call.
//
//  - fp (IN): Frame pointer from the call that initiated this allocation.
//
//  - mem (IN): Pointer to the memory block to reallocate.
//
//  - num (IN): Count of the memory block to reallocate.
//
//  - size (IN): Size of the memory block to reallocate.
//
//  Return Value:
//
//    Returns the value returned from the specified _aligned_offset_realloc.
//
void* VisualLeakDetector::__aligned_offset_recalloc (_aligned_offset_recalloc_t  precalloc,
    context_t& context,
    bool       debugRuntime,
    void      *mem,
    size_t     num,
    size_t     size,
    size_t     alignment,
    size_t     offset)
{
#ifdef PRINTHOOKCALLS
	DbgReport(_T(__FUNCTION__ "\n"));
#endif
    tls_t *tls = g_vld.getTls();

    // realloc is a CRT function and allocates from the CRT heap.
    if (debugRuntime)
        tls->flags |= VLD_TLS_DEBUGCRTALLOC;

    bool firstcall = (tls->context.fp == 0x0);
    if (firstcall) {
        // This is the first call to enter VLD for the current allocation.
        // Record the current frame pointer.
        tls->context = context;
    }

    // Do the allocation. The block will be mapped by _RtlReAllocateHeap.
    void* block = precalloc(mem, num, size, alignment, offset);

    if (firstcall)
        firstAllocCall(tls);

    return block;
}

// __aligned_malloc_dbg - This function is just a wrapper around the real _aligned_malloc_dbg
//   that sets appropriate flags to be consulted when the memory is actually
//   allocated by RtlAllocateHeap.
//
//  - p_malloc_dbg (IN): Pointer to the particular _malloc_dbg implementation to
//      call.
//
//  - fp (IN): Frame pointer from the call that initiated this allocation.
//
//  - size (IN): The size, in bytes, of the memory block to be allocated.
//
//  - type (IN): The CRT "use type" of the block to be allocated.
//
//  - file (IN): The name of the file from which this function is being called.
//
//  - line (IN): The line number, in the above file, at which this function is
//      being called.
//
//  Return Value:
//
//    Returns the value returned by the specified _aligned_malloc_dbg.
//
void* VisualLeakDetector::__aligned_malloc_dbg (_aligned_malloc_dbg_t  p_malloc_dbg,
    context_t&     context,
    bool           debugRuntime,
    size_t         size,
    size_t         alignment,
    int            type,
    char const    *file,
    int            line)
{
#ifdef PRINTHOOKCALLS
	DbgReport(_T(__FUNCTION__ "\n"));
#endif
    tls_t *tls = g_vld.getTls();

    // _malloc_dbg is a CRT function and allocates from the CRT heap.
    if (debugRuntime)
        tls->flags |= VLD_TLS_DEBUGCRTALLOC;

    bool firstcall = (tls->context.fp == 0x0);
    if (firstcall) {
        // This is the first call to enter VLD for the current allocation.
        // Record the current frame pointer.
        tls->context = context;
    }

    // Do the allocation. The block will be mapped by _RtlAllocateHeap.
    void* block = p_malloc_dbg(size, alignment, type, file, line);

    if (firstcall)
        firstAllocCall(tls);

    return block;
}

// __aligned_offset_malloc_dbg - This function is just a wrapper around the real
//   _aligned_offset_malloc_dbg that sets appropriate flags to be consulted when
//   the memory is actually allocated by RtlAllocateHeap.
//
//  - p_malloc_dbg (IN): Pointer to the particular _malloc_dbg implementation to
//      call.
//
//  - fp (IN): Frame pointer from the call that initiated this allocation.
//
//  - size (IN): The size, in bytes, of the memory block to be allocated.
//
//  - type (IN): The CRT "use type" of the block to be allocated.
//
//  - file (IN): The name of the file from which this function is being called.
//
//  - line (IN): The line number, in the above file, at which this function is
//      being called.
//
//  Return Value:
//
//    Returns the value returned by the specified _aligned_malloc_dbg.
//
void* VisualLeakDetector::__aligned_offset_malloc_dbg (_aligned_offset_malloc_dbg_t  p_malloc_dbg,
    context_t&     context,
    bool           debugRuntime,
    size_t         size,
    size_t         alignment,
    size_t         offset,
    int            type,
    char const    *file,
    int            line)
{
#ifdef PRINTHOOKCALLS
	DbgReport(_T(__FUNCTION__ "\n"));
#endif
    tls_t *tls = g_vld.getTls();

    // _malloc_dbg is a CRT function and allocates from the CRT heap.
    if (debugRuntime)
        tls->flags |= VLD_TLS_DEBUGCRTALLOC;

    bool firstcall = (tls->context.fp == 0x0);
    if (firstcall) {
        // This is the first call to enter VLD for the current allocation.
        // Record the current frame pointer.
        tls->context = context;
    }

    // Do the allocation. The block will be mapped by _RtlAllocateHeap.
    void* block = p_malloc_dbg(size, alignment, offset, type, file, line);

    if (firstcall)
        firstAllocCall(tls);

    return block;
}

// _aligned_realloc_debug - This function is just a wrapper around the real
//   _aligned_realloc_dbg that sets appropriate flags to be consulted when the memory is
//   actually allocated by RtlAllocateHeap.
//
//  - p_realloc_dbg (IN): Pointer to the particular __realloc_dbg implementation
//      to call.
//
//  - fp (IN): Frame pointer from the call that initiated this allocation.
//
//  - mem (IN): Pointer to the memory block to be reallocated.
//
//  - size (IN): The size of the memory block to reallocate.
//
//  - type (IN): The CRT "use type" of the block to be reallocated.
//
//  - file (IN): The name of the file from which this function is being called.
//
//  - line (IN): The line number, in the above file, at which this function is
//      being called.
//
//  Return Value:
//
//    Returns the value returned by the specified _realloc_dbg.
//
void* VisualLeakDetector::__aligned_realloc_dbg (_aligned_realloc_dbg_t  p_realloc_dbg,
    context_t&      context,
    bool            debugRuntime,
    void           *mem,
    size_t          size,
    size_t          alignment,
    int             type,
    char const     *file,
    int             line)
{
#ifdef PRINTHOOKCALLS
	DbgReport(_T(__FUNCTION__ "\n"));
#endif
    tls_t *tls = g_vld.getTls();

    // _realloc_dbg is a CRT function and allocates from the CRT heap.
    if (debugRuntime)
        tls->flags |= VLD_TLS_DEBUGCRTALLOC;

    bool firstcall = (tls->context.fp == 0x0);
    if (firstcall) {
        // This is the first call to enter VLD for the current allocation.
        // Record the current frame pointer.
        tls->context = context;
    }

    // Do the allocation. The block will be mapped by _RtlReAllocateHeap.
    void* block = p_realloc_dbg(mem, size, alignment, type, file, line);

    if (firstcall)
        firstAllocCall(tls);

    return block;
}

// _aligned_offset_realloc_debug - This function is just a wrapper around the real
//   _aligned_offset_realloc_dbg that sets appropriate flags to be consulted when
//   the memory is actually allocated by RtlAllocateHeap.
//
//  - p_realloc_dbg (IN): Pointer to the particular __realloc_dbg implementation
//      to call.
//
//  - fp (IN): Frame pointer from the call that initiated this allocation.
//
//  - mem (IN): Pointer to the memory block to be reallocated.
//
//  - size (IN): The size of the memory block to reallocate.
//
//  - type (IN): The CRT "use type" of the block to be reallocated.
//
//  - file (IN): The name of the file from which this function is being called.
//
//  - line (IN): The line number, in the above file, at which this function is
//      being called.
//
//  Return Value:
//
//    Returns the value returned by the specified _realloc_dbg.
//
void* VisualLeakDetector::__aligned_offset_realloc_dbg (_aligned_offset_realloc_dbg_t  p_realloc_dbg,
    context_t&      context,
    bool            debugRuntime,
    void           *mem,
    size_t          size,
    size_t          alignment,
    size_t          offset,
    int             type,
    char const     *file,
    int             line)
{
#ifdef PRINTHOOKCALLS
	DbgReport(_T(__FUNCTION__ "\n"));
#endif
    tls_t *tls = g_vld.getTls();

    // _realloc_dbg is a CRT function and allocates from the CRT heap.
    if (debugRuntime)
        tls->flags |= VLD_TLS_DEBUGCRTALLOC;

    bool firstcall = (tls->context.fp == 0x0);
    if (firstcall) {
        // This is the first call to enter VLD for the current allocation.
        // Record the current frame pointer.
        tls->context = context;
    }

    // Do the allocation. The block will be mapped by _RtlReAllocateHeap.
    void* block = p_realloc_dbg(mem, size, alignment, offset, type, file, line);

    if (firstcall)
        firstAllocCall(tls);

    return block;
}

// _aligned_recalloc_debug - This function is just a wrapper around the real
//   _aligned_realloc_dbg that sets appropriate flags to be consulted when the memory is
//   actually allocated by RtlAllocateHeap.
//
//  - p_recalloc_dbg (IN): Pointer to the particular __recalloc_dbg implementation
//      to call.
//
//  - fp (IN): Frame pointer from the call that initiated this allocation.
//
//  - mem (IN): Pointer to the memory block to be reallocated.
//
//  - num (IN): The number of memory blocks to reallocate.
//
//  - size (IN): The size of the memory block to reallocate.
//
//  - type (IN): The CRT "use type" of the block to be reallocated.
//
//  - file (IN): The name of the file from which this function is being called.
//
//  - line (IN): The line number, in the above file, at which this function is
//      being called.
//
//  Return Value:
//
//    Returns the value returned by the specified _realloc_dbg.
//
void* VisualLeakDetector::__aligned_recalloc_dbg (_aligned_recalloc_dbg_t  p_recalloc_dbg,
    context_t&      context,
    bool            debugRuntime,
    void           *mem,
    size_t          num,
    size_t          size,
    size_t          alignment,
    int             type,
    char const     *file,
    int             line)
{
#ifdef PRINTHOOKCALLS
	DbgReport(_T(__FUNCTION__ "\n"));
#endif
    tls_t *tls = g_vld.getTls();

    // _realloc_dbg is a CRT function and allocates from the CRT heap.
    if (debugRuntime)
        tls->flags |= VLD_TLS_DEBUGCRTALLOC;

    bool firstcall = (tls->context.fp == 0x0);
    if (firstcall) {
        // This is the first call to enter VLD for the current allocation.
        // Record the current frame pointer.
        tls->context = context;
    }

    // Do the allocation. The block will be mapped by _RtlReAllocateHeap.
    void* block = p_recalloc_dbg(mem, num, size, alignment, type, file, line);

    if (firstcall)
        firstAllocCall(tls);

    return block;
}

// _aligned_offset_recalloc_debug - This function is just a wrapper around the real
//   _aligned_offset_recalloc_dbg that sets appropriate flags to be consulted when
//   the memory is actually allocated by RtlAllocateHeap.
//
//  - p_recalloc_dbg (IN): Pointer to the particular __recalloc_dbg implementation
//      to call.
//
//  - fp (IN): Frame pointer from the call that initiated this allocation.
//
//  - mem (IN): Pointer to the memory block to be reallocated.
//
//  - num (IN): The number of memory blocks to reallocate.
//
//  - size (IN): The size of the memory block to reallocate.
//
//  - type (IN): The CRT "use type" of the block to be reallocated.
//
//  - file (IN): The name of the file from which this function is being called.
//
//  - line (IN): The line number, in the above file, at which this function is
//      being called.
//
//  Return Value:
//
//    Returns the value returned by the specified _realloc_dbg.
//
void* VisualLeakDetector::__aligned_offset_recalloc_dbg (_aligned_offset_recalloc_dbg_t  p_recalloc_dbg,
    context_t&      context,
    bool            debugRuntime,
    void           *mem,
    size_t          num,
    size_t          size,
    size_t          alignment,
    size_t          offset,
    int             type,
    char const     *file,
    int             line)
{
#ifdef PRINTHOOKCALLS
	DbgReport(_T(__FUNCTION__ "\n"));
#endif
    tls_t *tls = g_vld.getTls();

    // _realloc_dbg is a CRT function and allocates from the CRT heap.
    if (debugRuntime)
        tls->flags |= VLD_TLS_DEBUGCRTALLOC;

    bool firstcall = (tls->context.fp == 0x0);
    if (firstcall) {
        // This is the first call to enter VLD for the current allocation.
        // Record the current frame pointer.
        tls->context = context;
    }

    // Do the allocation. The block will be mapped by _RtlReAllocateHeap.
    void* block = p_recalloc_dbg(mem, num, size, alignment, offset, type, file, line);

    if (firstcall)
        firstAllocCall(tls);

    return block;
}

////////////////////////////////////////////////////////////////////////////////
//
// Debug CRT and MFC IAT Replacement Functions
//
// The addresses of these functions are not actually directly patched into the
// import address tables, but these functions do get indirectly called by the
// patch functions that are placed in the import address tables.
//
////////////////////////////////////////////////////////////////////////////////

// __calloc_dbg - This function is just a wrapper around the real _calloc_dbg
//   that sets appropriate flags to be consulted when the memory is actually
//   allocated by RtlAllocateHeap.
//
//  - p_calloc_dbg: Pointer to the particular _calloc_dbg implementation to
//      call.
//
//  - fp (IN): Frame pointer from the call that initiated this allocation.
//
//  - size (IN): The size, in bytes, of the memory block to be allocated.
//
//  - type (IN): The CRT "use type" of the block to be allocated.
//
//  - file (IN): The name of the file from which this function is being called.
//
//  - line (IN): The line number, in the above file, at which this function is
//      being called.
//
//  Return Value:
//
//    Returns the value returned by the specified _calloc_dbg.
//
void* VisualLeakDetector::__calloc_dbg (_calloc_dbg_t  p_calloc_dbg,
    context_t&      context,
    bool            debugRuntime,
    size_t          num,
    size_t          size,
    int             type,
    char const     *file,
    int             line)
{
#ifdef PRINTHOOKCALLS
	DbgReport(_T(__FUNCTION__ "\n"));
#endif
    tls_t *tls = g_vld.getTls();

    // _malloc_dbg is a CRT function and allocates from the CRT heap.
    if (debugRuntime)
        tls->flags |= VLD_TLS_DEBUGCRTALLOC;

    bool firstcall = (tls->context.fp == 0x0);
    if (firstcall) {
        // This is the first call to enter VLD for the current allocation.
        // Record the current frame pointer.
        tls->context = context;
    }

    // Do the allocation. The block will be mapped by _RtlAllocateHeap.
    void* block = p_calloc_dbg(num, size, type, file, line);

    if (firstcall)
        firstAllocCall(tls);

    return block;
}

// __malloc_dbg - This function is just a wrapper around the real _malloc_dbg
//   that sets appropriate flags to be consulted when the memory is actually
//   allocated by RtlAllocateHeap.
//
//  - p_malloc_dbg (IN): Pointer to the particular _malloc_dbg implementation to
//      call.
//
//  - fp (IN): Frame pointer from the call that initiated this allocation.
//
//  - size (IN): The size, in bytes, of the memory block to be allocated.
//
//  - type (IN): The CRT "use type" of the block to be allocated.
//
//  - file (IN): The name of the file from which this function is being called.
//
//  - line (IN): The line number, in the above file, at which this function is
//      being called.
//
//  Return Value:
//
//    Returns the value returned by the specified _malloc_dbg.
//
void* VisualLeakDetector::__malloc_dbg (_malloc_dbg_t  p_malloc_dbg,
    context_t&      context,
    bool            debugRuntime,
    size_t          size,
    int             type,
    char const     *file,
    int             line)
{
#ifdef PRINTHOOKCALLS
	DbgReport(_T(__FUNCTION__ "\n"));
#endif
    tls_t *tls = g_vld.getTls();

    // _malloc_dbg is a CRT function and allocates from the CRT heap.
    if (debugRuntime)
        tls->flags |= VLD_TLS_DEBUGCRTALLOC;

    bool firstcall = (tls->context.fp == 0x0);
    if (firstcall) {
        // This is the first call to enter VLD for the current allocation.
        // Record the current frame pointer.
        tls->context = context;
    }

    // Do the allocation. The block will be mapped by _RtlAllocateHeap.
    void* block = p_malloc_dbg(size, type, file, line);

    if (firstcall)
        firstAllocCall(tls);

    return block;
}

char* VisualLeakDetector::__strdup_dbg (_strdup_dbg_t p_strdup_dbg,
    context_t& context,
    bool debugRuntime,
    const char* src,
    int type,
    char const *file,
    int line)
{
#ifdef PRINTHOOKCALLS
	DbgReport(_T(__FUNCTION__ "\n"));
#endif
    tls_t *tls = g_vld.getTls();

    // _malloc_dbg is a CRT function and allocates from the CRT heap.
    if (debugRuntime)
        tls->flags |= VLD_TLS_DEBUGCRTALLOC;

    bool firstcall = (tls->context.fp == 0x0);
    if (firstcall) {
        // This is the first call to enter VLD for the current allocation.
        // Record the current frame pointer.
        tls->context = context;
    }

    // Do the allocation. The block will be mapped by _RtlAllocateHeap.
    char* block = p_strdup_dbg(src, type, file, line);

    if (firstcall)
        firstAllocCall(tls);

    return block;
}

wchar_t* VisualLeakDetector::__wcsdup_dbg (_wcsdup_dbg_t p_wcsdup_dbg,
    context_t& context,
    bool debugRuntime,
    const wchar_t* src,
    int type,
    char const *file,
    int line)
{
#ifdef PRINTHOOKCALLS
	DbgReport(_T(__FUNCTION__ "\n"));
#endif
    tls_t *tls = g_vld.getTls();

    // _malloc_dbg is a CRT function and allocates from the CRT heap.
    if (debugRuntime)
        tls->flags |= VLD_TLS_DEBUGCRTALLOC;

    bool firstcall = (tls->context.fp == 0x0);
    if (firstcall) {
        // This is the first call to enter VLD for the current allocation.
        // Record the current frame pointer.
        tls->context = context;
    }

    // Do the allocation. The block will be mapped by _RtlAllocateHeap.
    wchar_t* block = p_wcsdup_dbg(src, type, file, line);

    if (firstcall)
        firstAllocCall(tls);

    return block;
}

// new_dbg_crt - This function is just a wrapper around the real CRT debug new
//   operators that sets appropriate flags to be consulted when the memory is
//   actually allocated by RtlAllocateHeap.
//
//  - pnew_dbg_crt (IN): Pointer to the particular CRT new operator
//      implementation to call.
//
//  - fp (IN): Frame pointer from the call that initiated this allocation.
//
//  - size (IN): The size, in bytes, of the memory block to be allocated.
//
//  - type (IN): The CRT "use type" of the block to be allocated.
//
//  - file (IN): The name of the file from which this function is being called.
//
//  - line (IN): The line number, in the above file, at which this function is
//      being called.
//
//  Return Value:
//
//    Returns the value returned by the specified CRT debug new operator.
//
void* VisualLeakDetector::__new_dbg_crt (new_dbg_crt_t  pnew_dbg_crt,
    context_t&      context,
    bool            debugRuntime,
    size_t          size,
    int             type,
    char const     *file,
    int             line)
{
#ifdef PRINTHOOKCALLS
	DbgReport(_T(__FUNCTION__ "\n"));
#endif
    tls_t *tls = g_vld.getTls();

    // The debug new operator is a CRT function and allocates from the CRT heap.
    if (debugRuntime)
        tls->flags |= VLD_TLS_DEBUGCRTALLOC;

    bool firstcall = (tls->context.fp == 0x0);
    if (firstcall) {
        // This is the first call to enter VLD for the current allocation.
        // Record the current frame pointer.
        tls->context = context;
    }

    // Do the allocation. The block will be mapped by _RtlAllocateHeap.
    void* block = pnew_dbg_crt(size, type, file, line);

    if (firstcall)
        firstAllocCall(tls);

    return block;
}

// new_dbg_mfc - This function is just a wrapper around the real MFC debug new
//   operators that sets appropriate flags to be consulted when the memory is
//   actually allocated by RtlAllocateHeap.
//
//  - pnew_dbg (IN): Pointer to the particular CRT new operator
//      implementation to call.
//
//  - fp (IN): Frame pointer from the call that initiated this allocation.
//
//  - size (IN): The size, in bytes, of the memory block to be allocated.
//
//  - type (IN): The CRT "use type" of the block to be allocated.
//
//  - file (IN): The name of the file from which this function is being called.
//
//  - line (IN): The line number, in the above file, at which this function is
//      being called.
//
//  Return Value:
//
//    Returns the value returned by the specified CRT debug new operator.
//
void* VisualLeakDetector::__new_dbg_mfc (new_dbg_crt_t  pnew_dbg,
    context_t&      context,
    size_t          size,
    int             type,
    char const     *file,
    int             line)
{
#ifdef PRINTHOOKCALLS
	DbgReport(_T(__FUNCTION__ "\n"));
#endif
    tls_t *tls = g_vld.getTls();

    bool firstcall = (tls->context.fp == 0x0);
    if (firstcall) {
        // This is the first call to enter VLD for the current allocation.
        // Record the current frame pointer.
        tls->context = context;
    }

    // Do the allocation. The block will be mapped by _RtlAllocateHeap.
    void* block = pnew_dbg(size, type, file, line);

    if (firstcall)
        firstAllocCall(tls);

    return block;
}

// new_dbg_mfc - This function is just a wrapper around the real MFC debug new
//   operators that sets appropriate flags to be consulted when the memory is
//   actually allocated by RtlAllocateHeap.
//
//  - pnew_dbg_mfc (IN): Pointer to the particular MFC new operator
//      implementation to call.
//
//  - fp (IN): Frame pointer of the call that initiated this allocation.
//
//  - size (IN): The size, in bytes, of the memory block to be allocated.
//
//  - file (IN): The name of the file from which this function is being called.
//
//  - line (IN): The line number, in the above file, at which this function is
//      being called.
//
//  Return Value:
//
//    Returns the value returned by the specified MFC debug new operator.
//
void* VisualLeakDetector::__new_dbg_mfc (new_dbg_mfc_t  pnew_dbg_mfc,
    context_t&      context,
    size_t          size,
    char const     *file,
    int             line)
{
#ifdef PRINTHOOKCALLS
	DbgReport(_T(__FUNCTION__ "\n"));
#endif
    tls_t *tls = g_vld.getTls();

    bool firstcall = (tls->context.fp == 0x0);
    if (firstcall) {
        // This is the first call to enter VLD for the current allocation.
        // Record the current frame pointer.
        tls->context = context;
    }

    // Do the allocation. The block will be mapped by _RtlAllocateHeap.
    void* block = pnew_dbg_mfc(size, file, line);

    if (firstcall)
        firstAllocCall(tls);

    return block;
}

// __realloc_debug - This function is just a wrapper around the real
//   _realloc_dbg that sets appropriate flags to be consulted when the memory is
//   actually allocated by RtlAllocateHeap.
//
//  - p_realloc_dbg (IN): Pointer to the particular __realloc_dbg implementation
//      to call.
//
//  - fp (IN): Frame pointer from the call that initiated this allocation.
//
//  - mem (IN): Pointer to the memory block to be reallocated.
//
//  - size (IN): The size of the memory block to reallocate.
//
//  - type (IN): The CRT "use type" of the block to be reallocated.
//
//  - file (IN): The name of the file from which this function is being called.
//
//  - line (IN): The line number, in the above file, at which this function is
//      being called.
//
//  Return Value:
//
//    Returns the value returned by the specified _realloc_dbg.
//
void* VisualLeakDetector::__realloc_dbg (_realloc_dbg_t  p_realloc_dbg,
    context_t&      context,
    bool            debugRuntime,
    void           *mem,
    size_t          size,
    int             type,
    char const     *file,
    int             line)
{
#ifdef PRINTHOOKCALLS
	DbgReport(_T(__FUNCTION__ "\n"));
#endif
    tls_t *tls = g_vld.getTls();

    // _realloc_dbg is a CRT function and allocates from the CRT heap.
    if (debugRuntime)
        tls->flags |= VLD_TLS_DEBUGCRTALLOC;

    bool firstcall = (tls->context.fp == 0x0);
    if (firstcall) {
        // This is the first call to enter VLD for the current allocation.
        // Record the current frame pointer.
        tls->context = context;
    }

    // Do the allocation. The block will be mapped by _RtlReAllocateHeap.
    void* block = p_realloc_dbg(mem, size, type, file, line);

    if (firstcall)
        firstAllocCall(tls);

    return block;
}

// __recalloc_debug - This function is just a wrapper around the real
//   _recalloc_dbg that sets appropriate flags to be consulted when the memory is
//   actually allocated by RtlAllocateHeap.
//
//  - p_recalloc_dbg (IN): Pointer to the particular __realloc_dbg implementation
//      to call.
//
//  - fp (IN): Frame pointer from the call that initiated this allocation.
//
//  - mem (IN): Pointer to the memory block to be reallocated.
//
//  - size (IN): The size of the memory block to reallocate.
//
//  - type (IN): The CRT "use type" of the block to be reallocated.
//
//  - file (IN): The name of the file from which this function is being called.
//
//  - line (IN): The line number, in the above file, at which this function is
//      being called.
//
//  Return Value:
//
//    Returns the value returned by the specified _realloc_dbg.
//
void* VisualLeakDetector::__recalloc_dbg (_recalloc_dbg_t  p_recalloc_dbg,
    context_t&      context,
    bool            debugRuntime,
    void           *mem,
    size_t          num,
    size_t          size,
    int             type,
    char const     *file,
    int             line)
{
#ifdef PRINTHOOKCALLS
	DbgReport(_T(__FUNCTION__ "\n"));
#endif
    tls_t *tls = g_vld.getTls();

    // _realloc_dbg is a CRT function and allocates from the CRT heap.
    if (debugRuntime)
        tls->flags |= VLD_TLS_DEBUGCRTALLOC;

    bool firstcall = (tls->context.fp == 0x0);
    if (firstcall) {
        // This is the first call to enter VLD for the current allocation.
        // Record the current frame pointer.
        tls->context = context;
    }

    // Do the allocation. The block will be mapped by _RtlReAllocateHeap.
    void* block = p_recalloc_dbg(mem, num, size, type, file, line);

    if (firstcall)
        firstAllocCall(tls);

    return block;
}

// GetProcessHeap - Calls to GetProcessHeap are patched through to this function. This
//   function is just a wrapper around the real GetProcessHeap.
//
//  Return Value:
//
//    Returns the value returned by GetProcessHeap.
//
HANDLE VisualLeakDetector::_GetProcessHeap()
{
#ifdef PRINTHOOKCALLS
	DbgReport(_T(__FUNCTION__ "\n"));
#endif
    // Get the process heap.
    HANDLE heap = m_GetProcessHeap();

    CriticalSectionLocker cs(g_heapMapLock);
    HeapMap::Iterator heapit = g_vld.m_heapMap->find(heap);
    if (heapit == g_vld.m_heapMap->end())
    {
        g_vld.mapHeap(heap);
        heapit = g_vld.m_heapMap->find(heap);
    }

    return heap;
}

// _HeapCreate - Calls to HeapCreate are patched through to this function. This
//   function is just a wrapper around the real HeapCreate that calls VLD's heap
//   creation tracking function after the heap has been created.
//
//  - options (IN): Heap options.
//
//  - initsize (IN): Initial size of the heap.
//
//  - maxsize (IN): Maximum size of the heap.
//
//  Return Value:
//
//    Returns the value returned by HeapCreate.
//
HANDLE VisualLeakDetector::_HeapCreate (DWORD options, SIZE_T initsize, SIZE_T maxsize)
{
#ifdef PRINTHOOKCALLS
	DbgReport(_T(__FUNCTION__ "\n"));
#endif
    // Create the heap.
    HANDLE heap = m_HeapCreate(options, initsize, maxsize);

    // Map the created heap handle to a new block map.
    g_vld.mapHeap(heap);

    CriticalSectionLocker cs(g_heapMapLock);
    HeapMap::Iterator heapit = g_vld.m_heapMap->find(heap);
    assert(heapit != g_vld.m_heapMap->end());

    return heap;
}

// _HeapDestroy - Calls to HeapDestroy are patched through to this function.
//   This function is just a wrapper around the real HeapDestroy that calls
//   VLD's heap destruction tracking function after the heap has been destroyed.
//
//  - heap (IN): Handle to the heap to be destroyed.
//
//  Return Value:
//
//    Returns the valued returned by HeapDestroy.
//
BOOL VisualLeakDetector::_HeapDestroy (HANDLE heap)
{
#ifdef PRINTHOOKCALLS
	DbgReport(_T(__FUNCTION__ "\n"));
#endif
    // After this heap is destroyed, the heap's address space will be unmapped
    // from the process's address space. So, we'd better generate a leak report
    // for this heap now, while we can still read from the memory blocks
    // allocated to it.
    if (!(g_vld.m_options & VLD_OPT_SKIP_HEAPFREE_LEAKS))
        g_vld.reportHeapLeaks(heap);

    g_vld.unmapHeap(heap);

    return HeapDestroy(heap);
}

// _RtlAllocateHeap - Calls to RtlAllocateHeap are patched through to this
//   function. This function invokes the real RtlAllocateHeap and then calls
//   VLD's allocation tracking function. Pretty much all memory allocations
//   will eventually result in a call to RtlAllocateHeap, so this is where we
//   finally map the allocated block.
//
//  - heap (IN): Handle to the heap from which to allocate memory.
//
//  - flags (IN): Heap allocation control flags.
//
//  - size (IN): Size, in bytes, of the block to allocate.
//
//  Return Value:
//
//    Returns the return value from RtlAllocateHeap.
//
LPVOID VisualLeakDetector::_RtlAllocateHeap (HANDLE heap, DWORD flags, SIZE_T size)
{
#ifdef PRINTHOOKCALLS2
	DbgReport(_T(__FUNCTION__ "\n"));
#endif
    // Allocate the block.
    LPVOID block = RtlAllocateHeap(heap, flags, size);

    if ((block == NULL) || !g_vld.enabled())
        return block;

    tls_t* tls = g_vld.getTls();
    bool firstcall = (tls->context.fp == 0x0);
    context_t context;
    if (firstcall) {
        // This is the first call to enter VLD for the current allocation.
        // Record the current frame pointer.
        CAPTURE_CONTEXT(context, RtlAllocateHeap);
    }
    else
        context = tls->context;

    if (isModuleExcluded(GET_RETURN_ADDRESS(context)))
    {
        assert(tls->blockWithoutGuard == NULL);
        return block;
    }

    if (!firstcall && (g_vld.m_options & VLD_OPT_TRACE_INTERNAL_FRAMES)) {
        // Begin the stack trace with the current frame. Obtain the current
        // frame pointer.
        firstcall = true;
        CAPTURE_CONTEXT(context, RtlAllocateHeap);
    }

    tls->context = context;
    tls->heap = heap;
    tls->blockWithoutGuard = block;
    tls->newBlockWithoutGuard = NULL;
    tls->size = size;

    if (firstcall)
        firstAllocCall(tls);

    return block;
}

// HeapAlloc (kernel32.dll) call RtlAllocateHeap (ntdll.dll)
LPVOID VisualLeakDetector::_HeapAlloc (HANDLE heap, DWORD flags, SIZE_T size)
{
#ifdef PRINTHOOKCALLS2
	DbgReport(_T(__FUNCTION__ "\n"));
#endif
    // Allocate the block.
    LPVOID block = HeapAlloc(heap, flags, size);

    if ((block == NULL) || !g_vld.enabled())
        return block;

    tls_t* tls = g_vld.getTls();
    bool firstcall = (tls->context.fp == 0x0);
    context_t context;
    if (firstcall) {
        // This is the first call to enter VLD for the current allocation.
        // Record the current frame pointer.
        CAPTURE_CONTEXT(context, HeapAlloc);
    }
    else
        context = tls->context;

    if (isModuleExcluded(GET_RETURN_ADDRESS(context)))
    {
        assert(tls->blockWithoutGuard == NULL);
        return block;
    }

    if (!firstcall && (g_vld.m_options & VLD_OPT_TRACE_INTERNAL_FRAMES)) {
        // Begin the stack trace with the current frame. Obtain the current
        // frame pointer.
        firstcall = true;
        CAPTURE_CONTEXT(context, HeapAlloc);
    }

    tls->context = context;
    tls->heap = heap;
    tls->blockWithoutGuard = block;
    tls->newBlockWithoutGuard = NULL;
    tls->size = size;

    if (firstcall)
        firstAllocCall(tls);

    return block;
}

void VisualLeakDetector::AllocateHeap (tls_t* tls, blockinfo_t* &pblockInfo)
{
    bool debugcrtalloc = (tls->flags & VLD_TLS_DEBUGCRTALLOC) ? true : false;

    // The module that initiated this allocation is included in leak
    // detection. Map this block to the specified heap.
    g_vld.mapBlock(tls->heap, tls->blockWithoutGuard, tls->size, debugcrtalloc, tls->threadId, pblockInfo);
}

// _RtlFreeHeap - Calls to RtlFreeHeap are patched through to this function.
//   This function calls VLD's free tracking function and then invokes the real
//   RtlFreeHeap. Pretty much all memory frees will eventually result in a call
//   to RtlFreeHeap, so this is where we finally unmap the freed block.
//
//  - heap (IN): Handle to the heap to which the block being freed belongs.
//
//  - flags (IN): Heap control flags.
//
//  - mem (IN): Pointer to the memory block being freed.
//
//  Return Value:
//
//    Returns the value returned by RtlFreeHeap.
//
BYTE VisualLeakDetector::_RtlFreeHeap (HANDLE heap, DWORD flags, LPVOID mem)
{
#ifdef PRINTHOOKCALLS2
	DbgReport(_T(__FUNCTION__ "\n"));
#endif
    BYTE status;

    if (!g_symbolLock.IsLockedByCurrentThread()) // skip dbghelp.dll calls
    {
        context_t context;
        // Record the current frame pointer.
        CAPTURE_CONTEXT(context, RtlFreeHeap);

        // Unmap the block from the specified heap.
        g_vld.unmapBlock(heap, mem, context);
    }

    status = RtlFreeHeap(heap, flags, mem);

    return status;
}

// HeapFree (kernel32.dll) call RtlFreeHeap (ntdll.dll)
BOOL VisualLeakDetector::_HeapFree (HANDLE heap, DWORD flags, LPVOID mem)
{
#ifdef PRINTHOOKCALLS2
	DbgReport(_T(__FUNCTION__ "\n"));
#endif
    BOOL status;

    if (!g_symbolLock.IsLockedByCurrentThread()) // skip dbghelp.dll calls
    {
        context_t context;
        // Record the current frame pointer.
        CAPTURE_CONTEXT(context, m_HeapFree);

        // Unmap the block from the specified heap.
        g_vld.unmapBlock(heap, mem, context);
    }

    status = m_HeapFree(heap, flags, mem);

    return status;
}

// _RtlReAllocateHeap - Calls to RtlReAllocateHeap are patched through to this
//   function. This function invokes the real RtlReAllocateHeap and then calls
//   VLD's reallocation tracking function. All arguments passed to this function
//   are passed on to the real RtlReAllocateHeap without modification. Pretty
//   much all memory re-allocations will eventually result in a call to
//   RtlReAllocateHeap, so this is where we finally remap the reallocated block.
//
//  - heap (IN): Handle to the heap to reallocate memory from.
//
//  - flags (IN): Heap control flags.
//
//  - mem (IN): Pointer to the currently allocated block which is to be
//      reallocated.
//
//  - size (IN): Size, in bytes, of the block to reallocate.
//
//  Return Value:
//
//    Returns the value returned by RtlReAllocateHeap.
//
LPVOID VisualLeakDetector::_RtlReAllocateHeap (HANDLE heap, DWORD flags, LPVOID mem, SIZE_T size)
{
#ifdef PRINTHOOKCALLS
	DbgReport(_T(__FUNCTION__ "\n"));
#endif
    LPVOID               newmem;

    // Reallocate the block.
    newmem = RtlReAllocateHeap(heap, flags, mem, size);
    if ((newmem == NULL) || !g_vld.enabled())
        return newmem;

    tls_t *tls = g_vld.getTls();
    bool firstcall = (tls->context.fp == 0x0);
    context_t context;
    if (firstcall) {
        // This is the first call to enter VLD for the current allocation.
        // Record the current frame pointer.
        CAPTURE_CONTEXT(context, RtlReAllocateHeap);
    }
    else
        context = tls->context;

    if (isModuleExcluded(GET_RETURN_ADDRESS(context)))
    {
        assert(tls->blockWithoutGuard == NULL);
        return newmem;
    }

    if (!firstcall && (g_vld.m_options & VLD_OPT_TRACE_INTERNAL_FRAMES)) {
        // Begin the stack trace with the current frame. Obtain the current
        // frame pointer.
        firstcall = true;
        CAPTURE_CONTEXT(context, RtlReAllocateHeap);
    }

    tls->context = context;
    tls->heap = heap;
    tls->blockWithoutGuard = mem;
    tls->newBlockWithoutGuard = newmem;
    tls->size = size;

    if (firstcall)
    {
        firstAllocCall(tls);
        tls->blockWithoutGuard = NULL;
    }

    return newmem;
}

// for kernel32.dll
LPVOID VisualLeakDetector::_HeapReAlloc (HANDLE heap, DWORD flags, LPVOID mem, SIZE_T size)
{
#ifdef PRINTHOOKCALLS
	DbgReport(_T(__FUNCTION__ "\n"));
#endif
    LPVOID               newmem;

    // Reallocate the block.
    newmem = HeapReAlloc(heap, flags, mem, size);
    if ((newmem == NULL) || !g_vld.enabled())
        return newmem;

    tls_t *tls = g_vld.getTls();
    bool firstcall = (tls->context.fp == 0x0);
    context_t context;
    if (firstcall) {
        // This is the first call to enter VLD for the current allocation.
        // Record the current frame pointer.
        CAPTURE_CONTEXT(context, HeapReAlloc);
    }
    else
        context = tls->context;

    if (isModuleExcluded(GET_RETURN_ADDRESS(context)))
    {
        assert(tls->blockWithoutGuard == NULL);
        return newmem;
    }

    if (!firstcall && (g_vld.m_options & VLD_OPT_TRACE_INTERNAL_FRAMES)) {
        // Begin the stack trace with the current frame. Obtain the current
        // frame pointer.
        firstcall = true;
        CAPTURE_CONTEXT(context, HeapReAlloc);
    }

    tls->context = context;
    tls->heap = heap;
    tls->blockWithoutGuard = mem;
    tls->newBlockWithoutGuard = newmem;
    tls->size = size;

    if (firstcall)
    {
        firstAllocCall(tls);
        tls->blockWithoutGuard = NULL;
    }

    return newmem;
}

void VisualLeakDetector::ReAllocateHeap (tls_t *tls, blockinfo_t* &pblockInfo)
{
#ifdef PRINTHOOKCALLS
	DbgReport(_T(__FUNCTION__ "\n"));
#endif
    bool crtalloc = (tls->flags & VLD_TLS_DEBUGCRTALLOC) ? true : false;

    context_t context = tls->context;
    HANDLE heap = tls->heap;
    LPVOID mem = tls->blockWithoutGuard;
    LPVOID newmem = tls->newBlockWithoutGuard;
    SIZE_T size = tls->size;

    // Reset thread local flags and variables, in case any libraries called
    // into while remapping the block allocate some memory.
    tls->context.fp = NULL;
    tls->context.func = 0x0;
    tls->flags &= ~VLD_TLS_DEBUGCRTALLOC;

    // The module that initiated this allocation is included in leak
    // detection. Remap the block.
    g_vld.remapBlock(heap, mem, newmem, size, crtalloc, tls->threadId, pblockInfo, context);

#ifdef _DEBUG
    if(tls->context.fp != 0)
        __debugbreak();
#endif
    if (crtalloc)
        tls->flags |= VLD_TLS_DEBUGCRTALLOC;

    tls->context = context;
}

////////////////////////////////////////////////////////////////////////////////
//
// COM IAT Replacement Functions
//
////////////////////////////////////////////////////////////////////////////////

// _CoGetMalloc - Calls to CoGetMalloc are patched through to this function.
//   This function returns a pointer to Visual Leak Detector's implementation
//   of the IMalloc interface, instead of returning a pointer to the system
//   implementation. This allows VLD's implementation of the IMalloc interface
//   (which is basically a thin wrapper around the system implementation) to be
//   invoked in place of the system implementation.
//
//  - context (IN): Reserved; value must be 1.
//
//  - imalloc (IN): Address of a pointer to receive the address of VLD's
//      implementation of the IMalloc interface.
//
//  Return Value:
//
//    Always returns S_OK.
//
HRESULT VisualLeakDetector::_CoGetMalloc (DWORD context, LPMALLOC *imalloc)
{
#ifdef PRINTHOOKCALLS
	DbgReport(_T(__FUNCTION__ "\n"));
#endif
    static CoGetMalloc_t pCoGetMalloc = NULL;

    HRESULT hr = S_OK;

    HMODULE ole32;

    *imalloc = (LPMALLOC)&g_vld;

    if (pCoGetMalloc == NULL) {
        // This is the first call to this function. Link to the real
        // CoGetMalloc and get a pointer to the system implementation of the
        // IMalloc interface.
        ole32 = GetModuleHandleW(L"ole32.dll");
        pCoGetMalloc = (CoGetMalloc_t)g_vld._RGetProcAddress(ole32, "CoGetMalloc");
        hr = pCoGetMalloc(context, &g_vld.m_iMalloc);
    }
    else
    {
        // wait for different thread initialization
        int c = 0;
        while(g_vld.m_iMalloc == NULL && c < 10)
        {
            Sleep(1);
            c++;
        }
        if (g_vld.m_iMalloc == NULL)
            hr = E_INVALIDARG;
    }

    return hr;
}

// _CoTaskMemAlloc - Calls to CoTaskMemAlloc are patched through to this
//   function. This function is just a wrapper around the real CoTaskMemAlloc
//   that sets appropriate flags to be consulted when the memory is actually
//   allocated by RtlAllocateHeap.
//
//  - size (IN): Size of the memory block to allocate.
//
//  Return Value:
//
//    Returns the value returned from CoTaskMemAlloc.
//
LPVOID VisualLeakDetector::_CoTaskMemAlloc (SIZE_T size)
{
#ifdef PRINTHOOKCALLS
	DbgReport(_T(__FUNCTION__ "\n"));
#endif
    static CoTaskMemAlloc_t pCoTaskMemAlloc = NULL;

    LPVOID   block;
    context_t context;
    HMODULE  ole32;
    tls_t   *tls = g_vld.getTls();

    if (pCoTaskMemAlloc == NULL) {
        // This is the first call to this function. Link to the real
        // CoTaskMemAlloc.
        ole32 = GetModuleHandleW(L"ole32.dll");
        pCoTaskMemAlloc = (CoTaskMemAlloc_t)g_vld._RGetProcAddress(ole32, "CoTaskMemAlloc");
    }

    bool firstcall = (tls->context.fp == 0x0);
    if (firstcall) {
        // This is the first call to enter VLD for the current allocation.
        // Record the current frame pointer.
        CAPTURE_CONTEXT(context, pCoTaskMemAlloc);
        tls->context = context;
    }

    // Do the allocation. The block will be mapped by _RtlAllocateHeap.
    block = pCoTaskMemAlloc(size);

    if (firstcall)
        firstAllocCall(tls);

    return block;
}

// _CoTaskMemRealloc - Calls to CoTaskMemRealloc are patched through to this
//   function. This function is just a wrapper around the real CoTaskMemRealloc
//   that sets appropriate flags to be consulted when the memory is actually
//   allocated by RtlAllocateHeap.
//
//  - mem (IN): Pointer to the memory block to reallocate.
//
//  - size (IN): Size, in bytes, of the block to reallocate.
//
//  Return Value:
//
//    Returns the value returned from CoTaskMemRealloc.
//
LPVOID VisualLeakDetector::_CoTaskMemRealloc (LPVOID mem, SIZE_T size)
{
#ifdef PRINTHOOKCALLS
	DbgReport(_T(__FUNCTION__ "\n"));
#endif
    static CoTaskMemRealloc_t pCoTaskMemRealloc = NULL;

    LPVOID   block;
    context_t context;
    HMODULE  ole32;
    tls_t   *tls = g_vld.getTls();

    if (pCoTaskMemRealloc == NULL) {
        // This is the first call to this function. Link to the real
        // CoTaskMemRealloc.
        ole32 = GetModuleHandleW(L"ole32.dll");
        pCoTaskMemRealloc = (CoTaskMemRealloc_t)g_vld._RGetProcAddress(ole32, "CoTaskMemRealloc");
    }

    bool firstcall = (tls->context.fp == 0x0);
    if (firstcall) {
        // This is the first call to enter VLD for the current allocation.
        // Record the current frame pointer.
        CAPTURE_CONTEXT(context, pCoTaskMemRealloc);
        tls->context = context;
    }

    // Do the allocation. The block will be mapped by _RtlReAllocateHeap.
    block = pCoTaskMemRealloc(mem, size);

    if (firstcall)
        firstAllocCall(tls);

    return block;
}

////////////////////////////////////////////////////////////////////////////////
//
// Public COM IMalloc Implementation Functions
//
////////////////////////////////////////////////////////////////////////////////

// AddRef - Calls to IMalloc::AddRef end up here. This function is just a
//   wrapper around the real IMalloc::AddRef implementation.
//
//  Return Value:
//
//    Returns the value returned by the system implementation of
//    IMalloc::AddRef.
//
ULONG VisualLeakDetector::AddRef ()
{
#ifdef PRINTHOOKCALLS
	DbgReport(_T(__FUNCTION__ "\n"));
#endif
    assert(m_iMalloc != NULL);
    return (m_iMalloc) ? m_iMalloc->AddRef() : 0;
}

// Alloc - Calls to IMalloc::Alloc end up here. This function is just a wrapper
//   around the real IMalloc::Alloc implementation that sets appropriate flags
//   to be consulted when the memory is actually allocated by RtlAllocateHeap.
//
//  - size (IN): The size of the memory block to allocate.
//
//  Return Value:
//
//    Returns the value returned by the system's IMalloc::Alloc implementation.
//
LPVOID VisualLeakDetector::Alloc (_In_ SIZE_T size)
{
#ifdef PRINTHOOKCALLS
	DbgReport(_T(__FUNCTION__ "\n"));
#endif
    LPVOID  block;
    context_t context;
    tls_t  *tls = getTls();

    bool firstcall = (tls->context.fp == 0x0);
    if (firstcall) {
        // This is the first call to enter VLD for the current allocation.
        // Record the current frame pointer.
        UINT_PTR* cVtablePtr = (UINT_PTR*)((UINT_PTR*)m_iMalloc)[0];
        UINT_PTR allocFunc = cVtablePtr[3];
        CAPTURE_CONTEXT(context, allocFunc);
        tls->context = context;
    }

    // Do the allocation. The block will be mapped by _RtlAllocateHeap.
    assert(m_iMalloc != NULL);
    block = (m_iMalloc) ? m_iMalloc->Alloc(size) : NULL;

    if (firstcall)
        firstAllocCall(tls);

    return block;
}

// DidAlloc - Calls to IMalloc::DidAlloc will end up here. This function is just
//   a wrapper around the system implementation of IMalloc::DidAlloc.
//
//  - mem (IN): Pointer to a memory block to inquire about.
//
//  Return Value:
//
//    Returns the value returned by the system implementation of
//    IMalloc::DidAlloc.
//
INT VisualLeakDetector::DidAlloc (_In_opt_ LPVOID mem)
{
#ifdef PRINTHOOKCALLS
	DbgReport(_T(__FUNCTION__ "\n"));
#endif
    assert(m_iMalloc != NULL);
    return (m_iMalloc) ? m_iMalloc->DidAlloc(mem) : 0;
}

// Free - Calls to IMalloc::Free will end up here. This function is just a
//   wrapper around the real IMalloc::Free implementation.
//
//  - mem (IN): Pointer to the memory block to be freed.
//
//  Return Value:
//
//    None.
//
VOID VisualLeakDetector::Free (_In_opt_ LPVOID mem)
{
#ifdef PRINTHOOKCALLS
	DbgReport(_T(__FUNCTION__ "\n"));
#endif
    assert(m_iMalloc != NULL);
    if (m_iMalloc) m_iMalloc->Free(mem);
}

// GetSize - Calls to IMalloc::GetSize will end up here. This function is just a
//   wrapper around the real IMalloc::GetSize implementation.
//
//  - mem (IN): Pointer to the memory block to inquire about.
//
//  Return Value:
//
//    Returns the value returned by the system implementation of
//    IMalloc::GetSize.
//
SIZE_T VisualLeakDetector::GetSize (_In_opt_ LPVOID mem)
{
#ifdef PRINTHOOKCALLS
	DbgReport(_T(__FUNCTION__ "\n"));
#endif
    assert(m_iMalloc != NULL);
    return (m_iMalloc) ? m_iMalloc->GetSize(mem) : 0;
}

// HeapMinimize - Calls to IMalloc::HeapMinimize will end up here. This function
//   is just a wrapper around the real IMalloc::HeapMinimize implementation.
//
//  Return Value:
//
//    None.
//
VOID VisualLeakDetector::HeapMinimize ()
{
#ifdef PRINTHOOKCALLS
	DbgReport(_T(__FUNCTION__ "\n"));
#endif
    assert(m_iMalloc != NULL);
    if (m_iMalloc) m_iMalloc->HeapMinimize();
}

// QueryInterface - Calls to IMalloc::QueryInterface will end up here. This
//   function is just a wrapper around the real IMalloc::QueryInterface
//   implementation.
//
//  - iid (IN): COM interface ID to query about.
//
//  - object (IN): Address of a pointer to receive the requested interface
//      pointer.
//
//  Return Value:
//
//    Returns the value returned by the system implementation of
//    IMalloc::QueryInterface.
//
HRESULT VisualLeakDetector::QueryInterface (REFIID iid, LPVOID *object)
{
#ifdef PRINTHOOKCALLS
	DbgReport(_T(__FUNCTION__ "\n"));
#endif
    assert(m_iMalloc != NULL);
    return (m_iMalloc) ? m_iMalloc->QueryInterface(iid, object) : E_UNEXPECTED;
}

// Realloc - Calls to IMalloc::Realloc will end up here. This function is just a
//   wrapper around the real IMalloc::Realloc implementation that sets
//   appropriate flags to be consulted when the memory is actually allocated by
//   RtlAllocateHeap.
//
//  - mem (IN): Pointer to the memory block to reallocate.
//
//  - size (IN): Size, in bytes, of the memory block to reallocate.
//
//  Return Value:
//
//    Returns the value returned by the system implementation of
//    IMalloc::Realloc.
//
LPVOID VisualLeakDetector::Realloc (_In_opt_ LPVOID mem, _In_ SIZE_T size)
{
#ifdef PRINTHOOKCALLS
	DbgReport(_T(__FUNCTION__ "\n"));
#endif
    LPVOID  block;
    context_t context;
    tls_t  *tls = getTls();

    bool firstcall = (tls->context.fp == 0x0);
    if (firstcall) {
        // This is the first call to enter VLD for the current allocation.
        // Record the current frame pointer.
        CAPTURE_CONTEXT(context, NULL);
        tls->context = context;
    }

    // Do the allocation. The block will be mapped by _RtlReAllocateHeap.
    assert(m_iMalloc != NULL);
    block = (m_iMalloc) ? m_iMalloc->Realloc(mem, size) : NULL;

    if (firstcall)
        firstAllocCall(tls);

    return block;
}

// Release - Calls to IMalloc::Release will end up here. This function is just
//   a wrapper around the real IMalloc::Release implementation.
//
//  Return Value:
//
//    Returns the value returned by the system implementation of
//    IMalloc::Release.
//
ULONG VisualLeakDetector::Release ()
{
#ifdef PRINTHOOKCALLS
	DbgReport(_T(__FUNCTION__ "\n"));
#endif
    assert(m_iMalloc != NULL);
    return (m_iMalloc) ? m_iMalloc->Release() : 0;
}
