////////////////////////////////////////////////////////////////////////////////
//
//  Visual Leak Detector - VisualLeakDetector Class Definition
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

#pragma once

#ifndef VLDBUILD
#error \
    "This header should only be included by Visual Leak Detector when building it from source. \
    Applications should never include this header."
#endif

#include <cstdio>
#pragma push_macro("new")
#undef new
#include <string>
#include <memory>
#pragma pop_macro("new")
#include <windows.h>
#include "vld_def.h"
#include "version.h"
#include "callstack.h"  // Provides a custom class for handling call stacks.
#include "map.h"        // Provides a custom STL-like map template.
#include "ntapi.h"      // Provides access to NT APIs.
#include "set.h"        // Provides a custom STL-like set template.
#include "utility.h"    // Provides miscellaneous utility functions.
#include "vldallocator.h"   // Provides internal allocator.

#define MAXMODULELISTLENGTH 512     // Maximum module list length, in characters.
#define SELFTESTTEXTA       "Memory Leak Self-Test"
#define SELFTESTTEXTW       L"Memory Leak Self-Test"
#define VLDREGKEYPRODUCT    L"Software\\Visual Leak Detector"
#ifndef WIN64
#define VLDDLL				"vld_x86.dll"
#else
#define VLDDLL				"vld_x64.dll"
#endif

// The Visual Leak Detector APIs.
extern "C" __declspec(dllexport) void VLDDisable ();
extern "C" __declspec(dllexport) void VLDEnable ();
extern "C" __declspec(dllexport) void VLDRestore ();

// Function pointer types for explicit dynamic linking with functions listed in
// the import patch table.
typedef HANDLE(__stdcall *GetProcessHeap_t) ();
typedef HANDLE(__stdcall *HeapCreate_t) (DWORD, SIZE_T, SIZE_T);
typedef BOOL(__stdcall *HeapFree_t) (HANDLE, DWORD, LPVOID);
typedef FARPROC(__stdcall *GetProcAddress_t) (HMODULE, LPCSTR);
typedef FARPROC(__stdcall *GetProcAddressForCaller_t) (HMODULE, LPCSTR, LPVOID);

typedef void* (__cdecl *_calloc_dbg_t) (size_t, size_t, int, const char*, int);
typedef void* (__cdecl *_malloc_dbg_t) (size_t, int, const char *, int);
typedef void* (__cdecl *_realloc_dbg_t) (void *, size_t, int, const char *, int);
typedef void* (__cdecl *_recalloc_dbg_t) (void *, size_t, size_t, int, const char *, int);
typedef void* (__cdecl *calloc_t) (size_t, size_t);
typedef HRESULT (__stdcall *CoGetMalloc_t) (DWORD, LPMALLOC *);
typedef LPVOID (__stdcall *CoTaskMemAlloc_t) (SIZE_T);
typedef LPVOID (__stdcall *CoTaskMemRealloc_t) (LPVOID, SIZE_T);
typedef void* (__cdecl *malloc_t) (size_t);
typedef void* (__cdecl *new_t) (size_t);
typedef void* (__cdecl *new_dbg_crt_t) (size_t, int, const char *, int);
typedef void* (__cdecl *new_dbg_mfc_t) (size_t, const char *, int);
typedef void* (__cdecl *realloc_t) (void *, size_t);
typedef void* (__cdecl *_recalloc_t) (void *, size_t, size_t);
typedef char* (__cdecl *_strdup_t) (const char*);
typedef char* (__cdecl *_strdup_dbg_t) (const char*, int, const char* ,int);
typedef wchar_t* (__cdecl *_wcsdup_t) (const wchar_t*);
typedef wchar_t* (__cdecl *_wcsdup_dbg_t) (const wchar_t*, int, const char* ,int);
typedef void* (__cdecl *_aligned_malloc_t) (size_t, size_t);
typedef void* (__cdecl *_aligned_offset_malloc_t) (size_t, size_t, size_t);
typedef void* (__cdecl *_aligned_realloc_t) (void *, size_t, size_t);
typedef void* (__cdecl *_aligned_offset_realloc_t) (void *, size_t, size_t, size_t);
typedef void* (__cdecl *_aligned_recalloc_t) (void *, size_t, size_t, size_t);
typedef void* (__cdecl *_aligned_offset_recalloc_t) (void *, size_t, size_t, size_t, size_t);
typedef void* (__cdecl *_aligned_malloc_dbg_t) (size_t, size_t, int, const char *, int);
typedef void* (__cdecl *_aligned_offset_malloc_dbg_t) (size_t, size_t, size_t, int, const char *, int);
typedef void* (__cdecl *_aligned_realloc_dbg_t) (void *, size_t, size_t, int, const char *, int);
typedef void* (__cdecl *_aligned_offset_realloc_dbg_t) (void *, size_t, size_t, size_t, int, const char *, int);
typedef void* (__cdecl *_aligned_recalloc_dbg_t) (void *, size_t, size_t, size_t, int, const char *, int);
typedef void* (__cdecl *_aligned_offset_recalloc_dbg_t) (void *, size_t, size_t, size_t, size_t, int, const char *, int);

// Data is collected for every block allocated from any heap in the process.
// The data is stored in this structure and these structures are stored in
// a BlockMap which maps each of these structures to its corresponding memory
// block.
struct blockinfo_t {
    std::unique_ptr<CallStack> callStack;
    DWORD      threadId;
    SIZE_T     serialNumber;
    SIZE_T     size;
    bool       reported;
    bool       debugCrtAlloc;
};

// BlockMaps map memory blocks (via their addresses) to blockinfo_t structures.
typedef Map<LPCVOID, blockinfo_t*> BlockMap;

// Information about each heap in the process is kept in this map. Primarily
// this is used for mapping heaps to all of the blocks allocated from those
// heaps.
struct heapinfo_t {
    BlockMap blockMap;   // Map of all blocks allocated from this heap.
    UINT32   flags;      // Heap status flags
};

// HeapMaps map heaps (via their handles) to BlockMaps.
typedef Map<HANDLE, heapinfo_t*> HeapMap;
typedef std::basic_string<wchar_t, std::char_traits<wchar_t>, vldallocator<wchar_t> > vldstring;

// This structure stores information, primarily the virtual address range, about
// a given module and can be used with the Set template because it supports the
// '<' operator (sorts by virtual address range).
struct moduleinfo_t {
    BOOL operator < (const struct moduleinfo_t& other) const
    {
        if (addrHigh < other.addrLow) {
            return TRUE;
        }
        else {
            return FALSE;
        }
    }

    SIZE_T addrLow;                  // Lowest address within the module's virtual address space (i.e. base address).
    SIZE_T addrHigh;                 // Highest address within the module's virtual address space (i.e. base + size).
    UINT32 flags;                    // Module flags:
#define VLD_MODULE_EXCLUDED      0x1 //   If set, this module is excluded from leak detection.
#define VLD_MODULE_SYMBOLSLOADED 0x2 //   If set, this module's debug symbols have been loaded.
    vldstring name;                  // The module's name (e.g. "kernel32.dll").
    vldstring path;                  // The fully qualified path from where the module was loaded.
};

// ModuleSets store information about modules loaded in the process.
typedef Set<moduleinfo_t> ModuleSet;

typedef Set<VLD_REPORT_HOOK> ReportHookSet;

// Thread local storage structure. Every thread in the process gets its own copy
// of this structure. Thread specific information, such as the current leak
// detection status (enabled or disabled) and the address that initiated the
// current allocation is stored here.
struct tls_t {
    context_t	context;       	  // Address of return address at the first call that entered VLD's code for the current allocation.
    UINT32	    flags;            // Thread-local status flags:
#define VLD_TLS_DEBUGCRTALLOC 0x1 	  //   If set, the current allocation is a CRT allocation.
#define VLD_TLS_DISABLED 0x2 	  //   If set, memory leak detection is disabled for the current thread.
#define VLD_TLS_ENABLED  0x4 	  //   If set, memory leak detection is enabled for the current thread.
    UINT32	    oldFlags;         // Thread-local status old flags
    DWORD 	    threadId;         // Thread ID of the thread that owns this TLS structure.
    HANDLE      heap;
    LPVOID      blockWithoutGuard; // Store pointer to block.
    LPVOID      newBlockWithoutGuard;
    SIZE_T      size;
};

// Allocation state:
// 1. Allocation function set tls->context and tls->blockWithoutGuard = NULL
// 2. HeapAlloc set tls->heap, tls->blockWithoutGuard, tls->newBlockWithoutGuard and tls->size
// 3. Allocation function reset tls data, map block and capture callstack to tls->blockWithoutGuard

// The TlsSet allows VLD to keep track of all thread local storage structures
// allocated in the process.
typedef Map<DWORD,tls_t*> TlsMap;

class CallStack;

////////////////////////////////////////////////////////////////////////////////
//
// The VisualLeakDetector Class
//
//   One global instance of this class is instantiated. Upon construction it
//   patches the import address table (IAT) of every other module loaded in the
//   process (see the "patchimport" utility function) to allow key Windows heap
//   APIs to be patched through to, or redirected to, functions provided by VLD.
//   Patching the IATs in this manner allows VLD to be made aware of all
//   relevant heap activity, making it possible for VLD to detect and trace
//   memory leaks.
//
//   The one global instance of this class is constructed within the context of
//   the process' main thread during process initialization and is destroyed in
//   the same context during process termination.
//
//   When the VisualLeakDetector object is destroyed, it consults its internal
//   data structures, looking for any memory that has not been freed. A memory
//   leak report is then generated, indicating any memory leaks that may have
//   been identified.
//
//   This class is derived from IMalloc so that it can provide an implementation
//   of the IMalloc COM interface in order to support detection of COM-based
//   memory leaks. However, this implementation of IMalloc is actually just a
//   thin wrapper around the system's implementation of IMalloc.
//
class VisualLeakDetector : public IMalloc
{
public:
    VisualLeakDetector();
    ~VisualLeakDetector();

    ////////////////////////////////////////////////////////////////////////////////
    // Public CRT and MFC Common Handlers
    //
    // Many heap functions are indirectly rerouted to these handlers. One common
    // function exists for each heap function with a given signature. These
    // handlers are not direct IAT replacements, but are called by the individual
    // IAT replacement functions.
    ////////////////////////////////////////////////////////////////////////////////
    // Standard CRT and MFC common handlers
    void* _calloc (calloc_t pcalloc, context_t& context, bool debugRuntime, size_t num, size_t size);
    void* _malloc (malloc_t pmalloc, context_t& context, bool debugRuntime, size_t size);
    void* _new (new_t pnew, context_t& context, bool debugRuntime, size_t size);
    void* _realloc (realloc_t prealloc, context_t& context, bool debugRuntime, void *mem, size_t size);
    void* __recalloc (_recalloc_t precalloc, context_t& context, bool debugRuntime, void *mem, size_t num, size_t size);
    char* __strdup(_strdup_t pstrdup, context_t& context, bool debugRuntime, const char* src);
    wchar_t* __wcsdup(_wcsdup_t pwcsdup, context_t& context, bool debugRuntime, const wchar_t* src);

    // Debug CRT and MFC common handlers
    void* __calloc_dbg (_calloc_dbg_t p_calloc_dbg, context_t& context, bool debugRuntime, size_t num, size_t size, int type, char const *file, int line);
    void* __malloc_dbg (_malloc_dbg_t p_malloc_dbg, context_t& context, bool debugRuntime, size_t size, int type, char const *file, int line);
    void* __new_dbg_crt (new_dbg_crt_t pnew_dbg_crt, context_t& context, bool debugRuntime, size_t size, int type, char const *file, int line);
    void* __new_dbg_mfc (new_dbg_crt_t pnew_dbg, context_t& context, size_t size, int type, char const *file, int line);
    void* __new_dbg_mfc (new_dbg_mfc_t pnew_dbg_mfc, context_t& context, size_t size, char const *file, int line);
    void* __realloc_dbg (_realloc_dbg_t p_realloc_dbg, context_t& context, bool debugRuntime, void *mem, size_t size, int type, char const *file, int line);
    void* __recalloc_dbg (_recalloc_dbg_t p_recalloc_dbg, context_t& context, bool debugRuntime, void *mem, size_t num, size_t size, int type, char const *file, int line);
    char* __strdup_dbg(_strdup_dbg_t pstrdup, context_t& context, bool debugRuntime, const char* src, int type, char const *file, int line);
    wchar_t* __wcsdup_dbg(_wcsdup_dbg_t pwcsdup, context_t& context, bool debugRuntime, const wchar_t* src, int type, char const *file, int line);

    void *__aligned_malloc (_aligned_malloc_t p_aligned_malloc, context_t& context, bool debugRuntime, size_t size, size_t alignment);
    void *__aligned_offset_malloc (_aligned_offset_malloc_t p_aligned_offset_malloc, context_t& context, bool debugRuntime, size_t size, size_t alignment, size_t offset);
    void *__aligned_realloc (_aligned_realloc_t p_aligned_realloc, context_t& context, bool debugRuntime, void *mem, size_t size, size_t alignment);
    void *__aligned_offset_realloc (_aligned_offset_realloc_t p_aligned_offset_realloc, context_t& context, bool debugRuntime, void *mem, size_t size, size_t alignment, size_t offset);
    void *__aligned_recalloc (_aligned_recalloc_t p_aligned_recalloc, context_t& context, bool debugRuntime, void *mem, size_t num, size_t size, size_t alignment);
    void *__aligned_offset_recalloc (_aligned_offset_recalloc_t p_aligned_offset_recalloc, context_t& context, bool debugRuntime, void *mem, size_t num, size_t size, size_t alignment, size_t offset);
    void* __aligned_malloc_dbg (_aligned_malloc_dbg_t p_aligned_malloc_dbg, context_t& context, bool debugRuntime, size_t size, size_t alignment, int type, char const *file, int line);
    void* __aligned_offset_malloc_dbg (_aligned_offset_malloc_dbg_t p_aligned_offset_malloc_dbg, context_t& context, bool debugRuntime, size_t size, size_t alignment, size_t offset, int type, char const *file, int line);
    void* __aligned_realloc_dbg (_aligned_realloc_dbg_t p_aligned_realloc_dbg, context_t& context, bool debugRuntime, void *mem, size_t size, size_t alignment, int type, char const *file, int line);
    void* __aligned_offset_realloc_dbg (_aligned_offset_realloc_dbg_t p_aligned_offset_realloc_dbg, context_t& context, bool debugRuntime, void *mem, size_t size, size_t alignment, size_t offset, int type, char const *file, int line);
    void* __aligned_recalloc_dbg (_aligned_recalloc_dbg_t p_aligned_recalloc_dbg, context_t& context, bool debugRuntime, void *mem, size_t num, size_t size, size_t alignment, int type, char const *file, int line);
    void* __aligned_offset_recalloc_dbg (_aligned_offset_recalloc_dbg_t p_aligned_offset_recalloc_dbg, context_t& context, bool debugRuntime, void *mem, size_t num, size_t size, size_t alignment, size_t offset, int type, char const *file, int line);

    ////////////////////////////////////////////////////////////////////////////////
    // Public IMalloc methods - for support of COM-based memory leak detection.
    ////////////////////////////////////////////////////////////////////////////////
    ULONG   __stdcall AddRef ();
    LPVOID  __stdcall Alloc (_In_ SIZE_T size);
    INT     __stdcall DidAlloc (_In_opt_ LPVOID mem);
    VOID    __stdcall Free (_In_opt_ LPVOID mem);
    SIZE_T  __stdcall GetSize (_In_opt_ LPVOID mem);
    VOID    __stdcall HeapMinimize ();
    HRESULT __stdcall QueryInterface (REFIID iid, LPVOID *object);
    LPVOID  __stdcall Realloc (_In_opt_ LPVOID mem, _In_ SIZE_T size);
    ULONG   __stdcall Release ();

    void DisableLeakDetection ();
    void EnableLeakDetection ();
    void RestoreLeakDetectionState ();
    void GlobalDisableLeakDetection ();
    void GlobalEnableLeakDetection ();

    VOID RefreshModules();
    SIZE_T GetLeaksCount();
    SIZE_T GetThreadLeaksCount(DWORD threadId);
    SIZE_T ReportLeaks();
    SIZE_T ReportThreadLeaks(DWORD threadId);
    VOID MarkAllLeaksAsReported();
    VOID MarkThreadLeaksAsReported(DWORD threadId);
    VOID EnableModule(HMODULE module);
    VOID DisableModule(HMODULE module);
    UINT32 GetOptions();
    VOID GetReportFilename(WCHAR *filename);
    VOID SetOptions(UINT32 option_mask, SIZE_T maxDataDump, UINT32 maxTraceFrames);
    VOID SetReportOptions(UINT32 option_mask, CONST WCHAR *filename);
    int  SetReportHook(int mode, VLD_REPORT_HOOK pfnNewHook);
    VOID SetModulesList(CONST WCHAR *modules, BOOL includeModules);
    bool GetModulesList(WCHAR *modules, UINT size);
    int ResolveCallstacks();

    static NTSTATUS __stdcall _LdrLoadDll (LPWSTR searchpath, ULONG flags, unicodestring_t *modulename,
        PHANDLE modulehandle);
    static NTSTATUS __stdcall _LdrLoadDllWin8 (DWORD_PTR reserved, PULONG flags, unicodestring_t *modulename,
        PHANDLE modulehandle);
    static FARPROC __stdcall _RGetProcAddress(HMODULE module, LPCSTR procname);
    static FARPROC __stdcall _RGetProcAddressForCaller(HMODULE module, LPCSTR procname, LPVOID caller);

private:
    ////////////////////////////////////////////////////////////////////////////////
    // Private leak detection functions - see each function definition for details.
    ////////////////////////////////////////////////////////////////////////////////
    VOID   attachToLoadedModules (ModuleSet *newmodules);
    UINT32 getModuleState(ModuleSet::Iterator& it, UINT32 &moduleFlags);
    LPWSTR buildSymbolSearchPath();
    VOID   configure ();
    BOOL   enabled ();
    SIZE_T eraseDuplicates (const BlockMap::Iterator &element, Set<blockinfo_t*> &aggregatedLeak);
    tls_t* getTls ();
    VOID   mapBlock (HANDLE heap, LPCVOID mem, SIZE_T size, bool crtalloc, DWORD threadId, blockinfo_t* &pblockInfo);
    VOID   mapHeap (HANDLE heap);
    VOID   remapBlock (HANDLE heap, LPCVOID mem, LPCVOID newmem, SIZE_T size,
        bool crtalloc, DWORD threadId, blockinfo_t* &pblockInfo, const context_t &context);
    VOID   reportConfig ();
    SIZE_T reportHeapLeaks (HANDLE heap);
    SIZE_T getLeaksCount (heapinfo_t* heapinfo, DWORD threadId = (DWORD)-1);
    SIZE_T reportLeaks(heapinfo_t* heapinfo, bool &firstLeak, Set<blockinfo_t*> &aggregatedLeaks, DWORD threadId = (DWORD)-1);
    VOID   markAllLeaksAsReported (heapinfo_t* heapinfo, DWORD threadId = (DWORD)-1);
    VOID   unmapBlock (HANDLE heap, LPCVOID mem, const context_t &context);
    VOID   unmapHeap (HANDLE heap);
    int    resolveStacks(heapinfo_t* heapinfo);

    // Static functions (callbacks)
    static BOOL __stdcall addLoadedModule (PCWSTR modulepath, DWORD64 modulebase, ULONG modulesize, PVOID context);
    static BOOL __stdcall detachFromModule (PCWSTR modulepath, DWORD64 modulebase, ULONG modulesize, PVOID context);

    // Utils
    static bool isModuleExcluded (UINT_PTR returnaddress);
    blockinfo_t* findAllocedBlock(LPCVOID, __out HANDLE& heap);
    static void getCallStack( CallStack *&pcallstack, context_t &context );
    static void firstAllocCall(tls_t * tls);
    void setupReporting();
    void checkInternalMemoryLeaks();
    bool waitForAllVLDThreads();

    ////////////////////////////////////////////////////////////////////////////////
    // IAT replacement functions - see each function definition for details.
    //
    // Because there are so many virtually identical CRT and MFC replacement
    // functions, they are excluded from the class to reduce the amount of noise
    // within this class's code. See crtmfcpatch.cpp for those functions.
    ////////////////////////////////////////////////////////////////////////////////
    // Win32 IAT replacement functions
    static FARPROC  __stdcall _GetProcAddress(HMODULE module, LPCSTR procname);
    static FARPROC  __stdcall _GetProcAddressForCaller(HMODULE module, LPCSTR procname, LPVOID caller);

    static HANDLE   __stdcall _GetProcessHeap();

    static HANDLE   __stdcall _HeapCreate (DWORD options, SIZE_T initsize, SIZE_T maxsize);
    static BOOL     __stdcall _HeapDestroy (HANDLE heap);
    static LPVOID   __stdcall _HeapAlloc (HANDLE heap, DWORD flags, SIZE_T size);
    static BOOL     __stdcall _HeapFree (HANDLE heap, DWORD flags, LPVOID mem);
    static LPVOID   __stdcall _HeapReAlloc (HANDLE heap, DWORD flags, LPVOID mem, SIZE_T size);

    static LPVOID   __stdcall _RtlAllocateHeap (HANDLE heap, DWORD flags, SIZE_T size);
    static BYTE     __stdcall _RtlFreeHeap (HANDLE heap, DWORD flags, LPVOID mem);
    static LPVOID   __stdcall _RtlReAllocateHeap (HANDLE heap, DWORD flags, LPVOID mem, SIZE_T size);

    // COM IAT replacement functions
    static HRESULT __stdcall _CoGetMalloc (DWORD context, LPMALLOC *imalloc);
    static LPVOID  __stdcall _CoTaskMemAlloc (SIZE_T size);
    static LPVOID  __stdcall _CoTaskMemRealloc (LPVOID mem, SIZE_T size);

    static void AllocateHeap (tls_t* tls, blockinfo_t* &pblockInfo);
    static void ReAllocateHeap (tls_t *tls, blockinfo_t* &pblockInfo);

    ////////////////////////////////////////////////////////////////////////////////
    // Private data
    ////////////////////////////////////////////////////////////////////////////////
    WCHAR                m_forcedModuleList [MAXMODULELISTLENGTH]; // List of modules to be forcefully included in leak detection.
    HeapMap             *m_heapMap;           // Map of all active heaps in the process.
    IMalloc             *m_iMalloc;           // Pointer to the system implementation of IMalloc.

    SIZE_T               m_requestCurr;       // Current request number.
    SIZE_T               m_totalAlloc;        // Grand total - sum of all allocations.
    SIZE_T               m_curAlloc;          // Total amount currently allocated.
    SIZE_T               m_maxAlloc;          // Largest ever allocated at once.
    ModuleSet           *m_loadedModules;     // Contains information about all modules loaded in the process.
    SIZE_T               m_maxDataDump;       // Maximum number of user-data bytes to dump for each leaked block.
    UINT32               m_maxTraceFrames;    // Maximum number of frames per stack trace for each leaked block.
    CriticalSection      m_modulesLock;       // Protects accesses to the "loaded modules" ModuleSet.
    CriticalSection      m_optionsLock;       // Serializes access to the heap and block maps.
    UINT32               m_options;           // Configuration options.

    static patchentry_t  m_kernelbasePatch [];
    static patchentry_t  m_kernel32Patch [];
    static patchentry_t  m_ntdllPatch [];
    static patchentry_t  m_ole32Patch [];
    static moduleentry_t m_patchTable [58];   // Table of imports patched for attaching VLD to other modules.
    FILE                *m_reportFile;        // File where the memory leak report may be sent to.
    WCHAR                m_reportFilePath [MAX_PATH]; // Full path and name of file to send memory leak report to.
    const char          *m_selfTestFile;      // Filename where the memory leak self-test block is leaked.
    int                  m_selfTestLine;      // Line number where the memory leak self-test block is leaked.
    UINT32               m_status;            // Status flags:
#define VLD_STATUS_DBGHELPLINKED        0x1   //   If set, the explicit dynamic link to the Debug Help Library succeeded.
#define VLD_STATUS_INSTALLED            0x2   //   If set, VLD was successfully installed.
#define VLD_STATUS_NEVER_ENABLED        0x4   //   If set, VLD started disabled, and has not yet been manually enabled.
#define VLD_STATUS_FORCE_REPORT_TO_FILE 0x8   //   If set, the leak report is being forced to a file.
    DWORD                m_tlsIndex;          // Thread-local storage index.
    CriticalSection      m_tlsLock;           // Protects accesses to the Set of TLS structures.
    TlsMap              *m_tlsMap;            // Set of all thread-local storage structures for the process.
    HMODULE              m_vldBase;           // Visual Leak Detector's own module handle (base address).

    VOID __stdcall ChangeModuleState(HMODULE module, bool on);
    static GetProcAddress_t m_GetProcAddress;
    static GetProcAddressForCaller_t m_GetProcAddressForCaller;
    static GetProcessHeap_t m_GetProcessHeap;
    static HeapCreate_t m_HeapCreate;
    static HeapFree_t m_HeapFree;
};


// Configuration option default values
#define VLD_DEFAULT_MAX_DATA_DUMP    256
#define VLD_DEFAULT_MAX_TRACE_FRAMES 64
#define VLD_DEFAULT_REPORT_FILE_NAME L".\\memory_leak_report.txt"
