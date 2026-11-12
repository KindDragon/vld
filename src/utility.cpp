////////////////////////////////////////////////////////////////////////////////
//
//  Visual Leak Detector - Various Utility Functions
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
#define VLDBUILD        // Declares that we are building Visual Leak Detector.
#include "utility.h"    // Provides various utility functions and macros.
#include "vldheap.h"    // Provides internal new and delete operators.
#include "vldint.h"
#include <tchar.h>
#include <string.h>

//#define PRINTHOOKINFO

// Imported Global Variables
extern ReportHookSet*   g_pReportHooks;
extern VisualLeakDetector g_vld;
extern ImageDirectoryEntries g_Ide;
#if defined(_M_ARM64)
extern "C" bool VldArm64InTeardown(void);
#endif

// Global variables.
static BOOL         s_reportDelay = FALSE;     // If TRUE, we sleep for a bit after calling OutputDebugString to give the debugger time to catch up.
static FILE        *s_reportFile = NULL;       // Pointer to the file, if any, to send the memory leak report to.
static BOOL         s_reportToDebugger = TRUE; // If TRUE, a copy of the memory leak report will be sent to the debugger for display.
static BOOL         s_reportToStdOut = TRUE;   // If TRUE, a copy of the memory leak report will be sent to standard output.
static encoding_e   s_reportEncoding = ascii;  // Output encoding of the memory leak report.

#define IS_ORDINAL(name) (((UINT_PTR)name & 0xFFFF) == ((UINT_PTR)name))

#if defined(_M_ARM64)
// On ARM64, kernel32's heap exports (HeapCreate/HeapAlloc/HeapReAlloc/HeapFree/
// HeapDestroy) are fast-forward dispatch thunks: their target slot is resolved
// lazily and the resolving stub patches the CALLING module's IAT (not the
// kernel32 slot), so the kernel32 slot stays permanently unresolved.
// (Kernel32 on ARM64 Windows ships as an ARM64X binary; the dispatch thunks
// are the ARM64X forwarding mechanism. The terminology only matters to the
// kernel32 binary itself - VLD is built as a native ARM64 DLL.) When
// RestoreImport writes GetProcAddress(kernel32, "HeapXxx") (the dispatch
// thunk) back into a module's IAT, the first call through it at process
// detach (under the loader lock) reads the unresolved slot and spins forever.
// The real, terminal function bodies live in kernelbase.dll, so we capture
// them once at DLL attach and restore IATs to those instead. x64 has no
// fast-forward thunks and uses the original code path.
static struct { LPCSTR name; LPVOID proc; } g_arm64KernelbaseHeapProcs[] = {
    { "HeapCreate",  NULL },
    { "HeapAlloc",   NULL },
    { "HeapReAlloc", NULL },
    { "HeapFree",    NULL },
    { "HeapDestroy", NULL },
};

VOID Arm64CaptureKernelbaseHeapProcs (VOID)
{
    HMODULE kernelbase = GetModuleHandleW(L"kernelbase.dll");
    if (kernelbase == NULL)
        return;
    for (size_t i = 0; i < _countof(g_arm64KernelbaseHeapProcs); ++i)
        g_arm64KernelbaseHeapProcs[i].proc = (LPVOID)GetProcAddress(kernelbase, g_arm64KernelbaseHeapProcs[i].name);
}

LPVOID Arm64LookupKernelbaseHeapProc (LPCSTR importname)
{
    if (IS_ORDINAL(importname))
        return NULL;
    for (size_t i = 0; i < _countof(g_arm64KernelbaseHeapProcs); ++i)
    {
        if (strcmp(g_arm64KernelbaseHeapProcs[i].name, importname) == 0)
            return g_arm64KernelbaseHeapProcs[i].proc;
    }
    return NULL;
}
#endif

// DumpMemoryA - Dumps a nicely formatted rendition of a region of memory.
//   Includes both the hex value of each byte and its ASCII equivalent (if
//   printable).
//
//  - address (IN): Pointer to the beginning of the memory region to dump.
//
//  - size (IN): The size, in bytes, of the region to dump.
//
//  Return Value:
//
//    None.
//
VOID DumpMemoryA (LPCVOID address, SIZE_T size)
{
    // Each line of output is 16 bytes.
    SIZE_T dumpLen;
    if ((size % 16) == 0) {
        // No padding needed.
        dumpLen = size;
    }
    else {
        // We'll need to pad the last line out to 16 bytes.
        dumpLen = size + (16 - (size % 16));
    }

    // For each byte of data, get both the ASCII equivalent (if it is a
    // printable character) and the hex representation.
    SIZE_T bytesDone = 0;
    WCHAR  hexDump [HEXDUMPLINELENGTH] = {0};
    WCHAR  ascDump [18] = {0};
    WCHAR  formatBuf [BYTEFORMATBUFFERLENGTH];
    for (SIZE_T byteIndex = 0; byteIndex < dumpLen; byteIndex++) {
        SIZE_T wordIndex = byteIndex % 16;
        SIZE_T hexIndex = 3 * (wordIndex + (wordIndex / 4)); // 3 characters per byte, plus a 3-character space after every 4 bytes.
        SIZE_T ascIndex = wordIndex + wordIndex / 8;         // 1 character per byte, plus a 1-character space after every 8 bytes.
        if (byteIndex < size) {
            BYTE byte = ((PBYTE)address)[byteIndex];
            _snwprintf_s(formatBuf, BYTEFORMATBUFFERLENGTH, _TRUNCATE, L"%.2X ", byte);
            formatBuf[3] = '\0';
            wcsncpy_s(hexDump + hexIndex, HEXDUMPLINELENGTH - hexIndex, formatBuf, 4);
            if (isgraph(byte)) {
                ascDump[ascIndex] = (WCHAR)byte;
            }
            else {
                ascDump[ascIndex] = L'.';
            }
        }
        else {
            // Add padding to fill out the last line to 16 bytes.
            wcsncpy_s(hexDump + hexIndex, HEXDUMPLINELENGTH - hexIndex, L"   ", 4);
            ascDump[ascIndex] = L'.';
        }
        bytesDone++;
        if ((bytesDone % 16) == 0) {
            // Print one line of data for every 16 bytes. Include the
            // ASCII dump and the hex dump side-by-side.
            Report(L"    %s    %s\n", hexDump, ascDump);
        }
        else {
            if ((bytesDone % 8) == 0) {
                // Add a spacer in the ASCII dump after every 8 bytes.
                ascDump[ascIndex + 1] = L' ';
            }
            if ((bytesDone % 4) == 0) {
                // Add a spacer in the hex dump after every 4 bytes.
                wcsncpy_s(hexDump + hexIndex + 3, HEXDUMPLINELENGTH - hexIndex - 3, L"   ", 4);
            }
        }
    }
}

// DumpMemoryW - Dumps a nicely formatted rendition of a region of memory.
//   Includes both the hex value of each byte and its Unicode equivalent.
//
//  - address (IN): Pointer to the beginning of the memory region to dump.
//
//  - size (IN): The size, in bytes, of the region to dump.
//
//  Return Value:
//
//    None.
//
VOID DumpMemoryW (LPCVOID address, SIZE_T size)
{
    // Each line of output is 16 bytes.
    SIZE_T dumpLen;
    if ((size % 16) == 0) {
        // No padding needed.
        dumpLen = size;
    }
    else {
        // We'll need to pad the last line out to 16 bytes.
        dumpLen = size + (16 - (size % 16));
    }

    // For each word of data, get both the Unicode equivalent and the hex
    // representation.
    WCHAR  formatBuf [BYTEFORMATBUFFERLENGTH];
    WCHAR  hexDump [HEXDUMPLINELENGTH] = {0};
    WCHAR  unidump [18] = {0};
    SIZE_T bytesDone = 0;
    for (SIZE_T byteIndex = 0; byteIndex < dumpLen; byteIndex++) {
        SIZE_T hexIndex = 3 * ((byteIndex % 16) + ((byteIndex % 16) / 4));   // 3 characters per byte, plus a 3-character space after every 4 bytes.
        SIZE_T uniIndex = ((byteIndex / 2) % 8) + ((byteIndex / 2) % 8) / 8; // 1 character every other byte, plus a 1-character space after every 8 bytes.
        if (byteIndex < size) {
            BYTE byte = ((PBYTE)address)[byteIndex];
            _snwprintf_s(formatBuf, BYTEFORMATBUFFERLENGTH, _TRUNCATE, L"%.2X ", byte);
            formatBuf[BYTEFORMATBUFFERLENGTH - 1] = '\0';
            wcsncpy_s(hexDump + hexIndex, HEXDUMPLINELENGTH - hexIndex, formatBuf, 4);
            if (((byteIndex % 2) == 0) && ((byteIndex + 1) < dumpLen)) {
                // On every even byte, print one character.
                WORD   word = ((PWORD)address)[byteIndex / 2];
                if ((word == 0x0000) || (word == 0x0020)) {
                    unidump[uniIndex] = L'.';
                }
                else {
                    unidump[uniIndex] = word;
                }
            }
        }
        else {
            // Add padding to fill out the last line to 16 bytes.
            wcsncpy_s(hexDump + hexIndex, HEXDUMPLINELENGTH - hexIndex, L"   ", 4);
            unidump[uniIndex] = L'.';
        }
        bytesDone++;
        if ((bytesDone % 16) == 0) {
            // Print one line of data for every 16 bytes. Include the
            // ASCII dump and the hex dump side-by-side.
            Report(L"    %s    %s\n", hexDump, unidump);
        }
        else {
            if ((bytesDone % 8) == 0) {
                // Add a spacer in the ASCII dump after every 8 bytes.
                unidump[uniIndex + 1] = L' ';
            }
            if ((bytesDone % 4) == 0) {
                // Add a spacer in the hex dump after every 4 bytes.
                wcsncpy_s(hexDump + hexIndex + 3, HEXDUMPLINELENGTH - hexIndex - 3, L"   ", 4);
            }
        }
    }
}

// FilterFunction - Used in structured exception handling
DWORD FilterFunction(long)
{
    return EXCEPTION_CONTINUE_SEARCH;
}

// FindOriginalImportDescriptor - Determines if the specified module imports the named import
//   from the named exporting module.
//
//  - importmodule (IN): Handle (base address) of the module to be searched to
//      see if it imports the specified import.
//
//  - exportmodulename (IN): ANSI string containing the name of the module that
//      exports the import to be searched for.
//
//  Return Value:
//
//    Returns pointer to descriptor.
//
IMAGE_IMPORT_DESCRIPTOR* FindOriginalImportDescriptor (HMODULE importmodule, LPCSTR exportmodulename)
{
    IMAGE_IMPORT_DESCRIPTOR* idte = NULL;
    IMAGE_SECTION_HEADER*    section = NULL;
    ULONG                    size = 0;

    // Locate the importing module's Import Directory Table (IDT) entry for the
    // exporting module. The importing module actually can have several IATs --
    // one for each export module that it imports something from. The IDT entry
    // gives us the offset of the IAT for the module we are interested in.
    {
        idte = (IMAGE_IMPORT_DESCRIPTOR*)g_Ide.ImageDirectoryEntryToDataEx((PVOID)GetCallingModule((UINT_PTR)importmodule), TRUE,
            IMAGE_DIRECTORY_ENTRY_IMPORT, &size, &section);
    }

    if (idte == NULL) {
        // This module has no IDT (i.e. it imports nothing).
        return NULL;
    }
    while (idte->OriginalFirstThunk != 0x0) {
        PCHAR name = (PCHAR)R2VA(importmodule, idte->Name);
        if (_stricmp(name, exportmodulename) == 0) {
            // Found the IDT entry for the exporting module.
            break;
        }
        idte++;
    }
    if (idte->OriginalFirstThunk == 0x0) {
        // The importing module does not import anything from the exporting
        // module.
        return NULL;
    }
    return idte;
}

// FindImport - Determines if the specified module imports the named import
//   from the named exporting module.
//
//  - importmodule (IN): Handle (base address) of the module to be searched to
//      see if it imports the specified import.
//
//  - exportmodule (IN): Handle (base address) of the module that exports the
//      import to be searched for.
//
//  - exportmodulename (IN): ANSI string containing the name of the module that
//      exports the import to be searched for.
//
//  - importname (IN): ANSI string containing the name of the import to search
//      for. May be an integer cast to a string if the import is exported by
//      ordinal.
//
//  Return Value:
//
//    Returns TRUE if the module imports to the specified import. Otherwise
//    returns FALSE.
//
BOOL FindImport (HMODULE importmodule, HMODULE exportmodule, LPCSTR exportmodulename, LPCSTR importname)
{
    IMAGE_IMPORT_DESCRIPTOR *idte;
    IMAGE_THUNK_DATA        *iate;
    FARPROC                  import;

    DbgTrace(L"dbghelp32.dll %i: FindImport - ImageDirectoryEntryToDataEx\n", GetCurrentThreadId());
    idte = FindOriginalImportDescriptor(importmodule, exportmodulename);
    if (idte == NULL)
        return FALSE;

    // Get the *real* address of the import. If we find this address in the IAT,
    // then we've found that the module does import the named import.
    import = GetProcAddress(exportmodule, importname);

    // Perhaps the named export module does not actually export the named import?
    //assert(import != NULL);   - on my Windows 7 x64, VS 9 SP1, Win x32 project assertion failure will cause new DLL loading, and then infinite loop of calls to findimport() and stack overflow. Maybe it's caused by antivirus, nevertheless this solution fixes infinite loop
    if ( import == NULL )    // - instead of assert
    {
        OutputDebugStringW(__FUNCTIONW__ L"(" __FILEW__ L") : import == NULL\n" );
        if ( ::IsDebuggerPresent() )
            __debugbreak();

        return FALSE;
    }

    // Locate the import's IAT entry.
    iate = (IMAGE_THUNK_DATA*)R2VA(importmodule, idte->FirstThunk);
    while (iate->u1.Function != 0x0) {
        if (iate->u1.Function == (DWORD_PTR)import) {
            // Found the IAT entry. The module imports the named import.
            return TRUE;
        }
        iate++;
    }

    // The module does not import the named import.
    return FALSE;
}

// FindImportByExportAddress - Same as FindImport but takes a pre-resolved export
//   address instead of looking it up via GetProcAddress. Used by the LDR
//   notification path on all architectures (LdrRegisterDllNotification can
//   fire under the parallel loader where another worker holds the loader
//   lock; the hooked GetProcAddress would deadlock there).
BOOL FindImportByExportAddress (HMODULE importmodule, LPCSTR exportmodulename, LPCVOID exportAddress)
{
    IMAGE_IMPORT_DESCRIPTOR *idte;
    IMAGE_THUNK_DATA        *iate;

    if (exportAddress == NULL)
        return FALSE;

    idte = FindOriginalImportDescriptor(importmodule, exportmodulename);
    if (idte == NULL)
        return FALSE;

    iate = (IMAGE_THUNK_DATA*)R2VA(importmodule, idte->FirstThunk);
    while (iate->u1.Function != 0x0) {
        if (iate->u1.Function == (DWORD_PTR)exportAddress) {
            return TRUE;
        }
        iate++;
    }
    return FALSE;
}

// FindPatch - Determines if the specified module has been patched to use the
//   specified replacement.
//
//  - importmodule (IN): Handle (base address) of the module to be searched to
//      see if it imports the specified replacement export.
//
//  - exportmodulename (IN): ANSI string containing the name of the module that
//      normally exports that import that would have been patched to use the
//      replacement export.
//
//  - replacement (IN): Address of the replacement, or destination, function or
//      variable to search for.
//
//  Return Value:
//
//    Returns TRUE if the module has been patched to use the specified
//    replacement export.
//
BOOL FindPatch (HMODULE importmodule, moduleentry_t *module)
{
    IMAGE_IMPORT_DESCRIPTOR *idte;

    idte = FindOriginalImportDescriptor(importmodule, module->exportModuleName);
    if (idte == NULL)
        return FALSE;

    int i = 0;
    patchentry_t *entry = module->patchTable;
    while(entry->importName)
    {
        LPCVOID replacement = entry->replacement;

        IMAGE_THUNK_DATA        *iate;

        // Locate the replacement's IAT entry.
        iate = (IMAGE_THUNK_DATA*)R2VA(importmodule, idte->FirstThunk);
        while (iate->u1.Function != 0x0) {
            if (iate->u1.Function == (DWORD_PTR)replacement) {
                // Found the IAT entry for the replacement. This patch has been
                // installed.
                return TRUE;
            }
            iate++;
        }
        entry++; i++;
    }

    // The module does not import the replacement. The patch has not been
    // installed.
    return FALSE;
}

// InsertReportDelay - Sets the report function to sleep for a bit after each
//   call to OutputDebugString, in order to allow the debugger to catch up.
//
//  Return Value:
//
//    None.
//
VOID InsertReportDelay ()
{
    s_reportDelay = TRUE;
}

// ConvertModulePathToAscii - Convert module path to ascii encoding.
void ConvertModulePathToAscii( LPCWSTR modulename, LPSTR * modulenamea )
{
	size_t length = ::WideCharToMultiByte(CP_ACP, 0, modulename, -1, 0, 0, 0, 0);
	*modulenamea = new CHAR [length];

	// wcstombs_s requires locale to be already set up correctly, but it might not be correct on vld init step. So use WideCharToMultiByte instead
	CHAR defaultChar     = '?';
	BOOL defaultCharUsed = FALSE;

	int count = ::WideCharToMultiByte(CP_ACP, 0/*flags*/, modulename, (int)-1, *modulenamea, (int)length, &defaultChar, &defaultCharUsed);
	assert(count != 0);
	(void)count; // Used only in debug assert
	if ( defaultCharUsed )
	{
		::OutputDebugStringW(__FILEW__ L": " __FUNCTIONW__ L" - defaultChar was used while conversion from \"");
		::OutputDebugStringW(modulename);
		::OutputDebugStringW(L"\" to ANSI \"");
		::OutputDebugStringA(*modulenamea);
		::OutputDebugStringW(L"\". Result can be wrong.\n");
	}
}

// IsModulePatched - Checks to see if any of the imports listed in the specified
//   patch table have been patched into the specified importmodule.
//
//  - importmodule (IN): Handle (base address) of the module to be queried to
//      determine if it has been patched.
//
//  - patchtable (IN): An array of patchentry_t structures specifying all of the
//      import patches to search for.
//
//  - tablesize (IN): Size, in entries, of the specified patch table.
//
//  Return Value:
//
//    Returns TRUE if at least one of the patches listed in the patch table is
//    installed in the importmodule. Otherwise returns FALSE.
//
BOOL IsModulePatched (HMODULE importmodule, moduleentry_t patchtable [], UINT tablesize)
{
    // Loop through the import patch table, individually checking each patch
    // entry to see if it is installed in the import module. If any patch entry
    // is installed in the import module, then the module has been patched.
    BOOL found = FALSE;
    for (UINT index = 0; index < tablesize; index++) {
        moduleentry_t *entry = &patchtable[index];
        found = FindPatch(importmodule, entry);
        if (found) {
            // Found one of the listed patches installed in the import module.
            return TRUE;
        }
    }

    // No patches listed in the patch table were found in the import module.
    return FALSE;
}

// Returns TRUE if [address, address + size) is committed, readable and not a
// guard page. Never changes page protection: doing so on ARM64X system DLL data
// pages faults inside the loader under x64 emulation on ARM64.
static BOOL IsReadableMemory(LPCVOID address, SIZE_T size)
{
    const BYTE* current = (const BYTE*)address;
    const BYTE* end = current + size;
    while (current < end)
    {
        MEMORY_BASIC_INFORMATION mbi;
        if (VirtualQuery(current, &mbi, sizeof(mbi)) != sizeof(mbi))
        {
            return FALSE;
        }
        if (mbi.State != MEM_COMMIT || (mbi.Protect & (PAGE_GUARD | PAGE_NOACCESS)) != 0)
        {
            return FALSE;
        }
        switch (mbi.Protect & 0xFF)
        {
        case PAGE_READONLY:
        case PAGE_READWRITE:
        case PAGE_WRITECOPY:
        case PAGE_EXECUTE_READ:
        case PAGE_EXECUTE_READWRITE:
        case PAGE_EXECUTE_WRITECOPY:
            break;
        default:
            return FALSE;
        }
        current = (const BYTE*)mbi.BaseAddress + mbi.RegionSize;
    }
    return TRUE;
}

// Copies size bytes from address into buffer without changing page protection.
static BOOL ReadMemory(LPCVOID address, LPVOID buffer, SIZE_T size)
{
    if (!IsReadableMemory(address, size))
    {
        return FALSE;
    }
    __try
    {
        memcpy(buffer, address, size);
    }
    __except (GetExceptionCode() == EXCEPTION_ACCESS_VIOLATION ? EXCEPTION_EXECUTE_HANDLER : EXCEPTION_CONTINUE_SEARCH)
    {
        return FALSE;
    }
    return TRUE;
}

LPVOID FindRealCode(LPVOID pCode)
{
    LPVOID result;
    if (pCode != NULL)
    {
#if defined(_M_ARM64)
        // ARM64: follow linker thunks/stubs to the real function body so that the
        // IAT comparison in PatchImport (func == import) succeeds even when one
        // side points at a thunk. This mirrors the x86/x64 logic below (which
        // follows the E9 jmp rel32 incremental-linking thunk and the FF25 import
        // jump stub). Without this, imports such as operator new fail to get
        // patched on ARM64, causing CRT allocations to be attributed to ucrtbase
        // instead of the user module.
        //
        // ARM64 has no single fixed jump opcode, so we recognize the two thunk
        // shapes the MSVC linker emits that are the direct analogs of the x64
        // E9/FF25 thunks: the incremental-linking branch (B imm26) and the IAT
        // import stub (ADRP Xn; LDR Xn,[Xn,#imm12]; BR Xn). We deliberately do
        // not decode broader ADRP+ADD or LDR-literal shapes, which collide with
        // ordinary function prologues and would over-resolve real imports. The
        // scratch register is x16 or x17 (both are used in practice), so the
        // register field is decoded rather than hard-coded. Resolution is
        // iterative with a depth bound and a self-loop guard to avoid runaway
        // recursion on malformed chains. On any failure to read or decode we
        // return the current address (safe for normalization) rather than NULL.
        LPVOID cur = pCode;
        for (int depth = 0; depth < 16; depth++)
        {
            // Up to 3 instructions (12 bytes); the longest sequence we decode
            // is ADRP+LDR+BR.
            ULONG p[3];
            if (!ReadMemory(cur, p, sizeof(p)))
            {
                break;
            }

            ULONG i0 = p[0];
            LPVOID next = NULL;

            if ((i0 & 0xFC000000u) == 0x14000000u)
            {
                // B <imm26> (incremental-linking thunk; analog of x64 E9 jmp rel32)
                INT64 imm26 = (INT64)(i0 & 0x03FFFFFFu);
                if (imm26 & 0x02000000)
                    imm26 -= 0x04000000; // sign-extend 26-bit
                next = (LPVOID)((BYTE*)cur + imm26 * 4);
            }
            else if ((i0 & 0x9F000000u) == 0x90000000u &&
                     (((i0 & 0x1Fu) == 16u) || ((i0 & 0x1Fu) == 17u)))
            {
                // ADRP Xn, <page> with Xn in {x16, x17}
                ULONG    xn = i0 & 0x1Fu;
                INT64    immlo = (i0 >> 29) & 0x3u;
                INT64    immhi = (i0 >> 5) & 0x7FFFFu;
                INT64    imm21 = (immhi << 2) | immlo;
                if (imm21 & 0x100000)
                    imm21 -= 0x200000; // sign-extend 21-bit
                ULONG_PTR page = ((ULONG_PTR)cur & ~(ULONG_PTR)0xFFF) + (ULONG_PTR)(imm21 * 4096);
                ULONG i1 = p[1];
                ULONG br = 0xD61F0000u | (xn << 5); // BR Xn

                if (((i1 & 0xFFC00000u) == 0xF9400000u) &&        // LDR Xn,[Xn,#imm12]
                    (((i1 >> 5) & 0x1Fu) == xn) && ((i1 & 0x1Fu) == xn) &&
                    (p[2] == br))
                {
                    // ADRP+LDR+BR: load the function pointer from the IAT slot
                    // (analog of x64 FF25 jmp [rip+disp]).
                    ULONG_PTR imm12 = (i1 >> 10) & 0xFFFu;
                    ULONG_PTR slot = page + (imm12 << 3);
                    LPVOID target;
                    if (ReadMemory((LPCVOID)slot, &target, sizeof(target)))
                    {
                        next = target;
                    }
                }
            }

            if (next == NULL || next == cur)
                break; // not a recognized thunk, or a self-loop: stop here
            cur = next;
        }
        result = cur;
#else
        // JMP r/m32 (FF 25 disp32/addr32) and JMP rel32 (E9 rel32) are at most 6 bytes.
        BYTE code[6];
        if (ReadMemory(pCode, code, sizeof(code)))
        {
            if (*(WORD*)code == 0x25ff) // JMP r/m32
            {
#ifdef _WIN64
                // RIP relative addressing
                LONG offset = *(LONG*)(code + 2);
                PBYTE slot = (PBYTE)pCode + 6 + offset;
#else
                PBYTE slot = (PBYTE)(ULONG_PTR)*(DWORD*)(code + 2);
#endif
                LPVOID target;
                if (ReadMemory(slot, &target, sizeof(target)))
                {
                    result = FindRealCode(target);
                }
                else
                {
                    result = NULL;
                }
            }
            else if (code[0] == 0xE9) // JMP rel32
            {
                LONG offset = *(LONG*)(code + 1);
                result = FindRealCode((PBYTE)pCode + 5 + offset);
            }
            else
            {
                result = pCode;
            }
        }
        else
        {
            result = NULL;
        }
#endif // !_M_ARM64
    }
    else
    {
        result = NULL;
    }
    return result;
}

#if defined(_M_X64)
// IMAGE_ARM64EC_METADATA, which the SDK does not declare. The load config
// CHPEMetadataPointer of an ARM64X image (seen from an x64 process) points here.
typedef struct ARM64EC_METADATA_TAG
{
    ULONG Version;
    ULONG CodeMap;
    ULONG CodeMapCount;
    ULONG CodeRangesToEntryPoints;
    ULONG RedirectionMetadata;
    ULONG DispatchCallNoRedirect;
    ULONG DispatchRet;
    ULONG DispatchCall;
    ULONG DispatchICall;
    ULONG DispatchICallCfg;
    ULONG AlternateEntryPoint;
    ULONG AuxiliaryIAT;
    ULONG CodeRangesToEntryPointsCount;
    ULONG RedirectionMetadataCount;
    ULONG GetX64InformationFunctionPointer;
    ULONG SetX64InformationFunctionPointer;
    ULONG ExtraRFETable;     // ARM64 RUNTIME_FUNCTIONs of the ARM64/ARM64EC code
    ULONG ExtraRFETableSize;
} ARM64EC_METADATA;

#define ARM64EC_CODE_RANGE_ARM64EC 1

typedef struct ARM64EC_CODE_RANGE_TAG
{
    ULONG StartOffset;  // low 2 bits: range type
    ULONG Length;
} ARM64EC_CODE_RANGE;

// x64 export thunk of an ARM64X image: mov rax,rsp; mov [rax+20h],rbx;
// push rbp; pop rbp; jmp rel32 <ARM64EC body>.
static const BYTE g_arm64EcExportThunk[] = { 0x48, 0x8B, 0xC4, 0x48, 0x89, 0x58, 0x20, 0x55, 0x5D, 0xE9 };

static BOOL GetArm64EcExportNameUnsafe(UINT_PTR programCounter, LPWSTR name, SIZE_T nameChars, DWORD64* displacement)
{
    BYTE* base = (BYTE*)GetCallingModule(programCounter);
    if (base == NULL)
    {
        return FALSE;
    }
    IMAGE_NT_HEADERS64* nt = (IMAGE_NT_HEADERS64*)(base + ((IMAGE_DOS_HEADER*)base)->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE || nt->OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR64_MAGIC)
    {
        return FALSE;
    }
    DWORD imageSize = nt->OptionalHeader.SizeOfImage;
    DWORD pcRva = (DWORD)(programCounter - (UINT_PTR)base);

    IMAGE_DATA_DIRECTORY loadConfigDir = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG];
    if (loadConfigDir.VirtualAddress == 0)
    {
        return FALSE;
    }
    IMAGE_LOAD_CONFIG_DIRECTORY64* loadConfig = (IMAGE_LOAD_CONFIG_DIRECTORY64*)(base + loadConfigDir.VirtualAddress);
    if (loadConfig->Size < offsetof(IMAGE_LOAD_CONFIG_DIRECTORY64, CHPEMetadataPointer) + sizeof(ULONGLONG) ||
        loadConfig->CHPEMetadataPointer == 0)
    {
        return FALSE;
    }
    const ARM64EC_METADATA* metadata = (const ARM64EC_METADATA*)loadConfig->CHPEMetadataPointer;
    if ((BYTE*)metadata < base || (BYTE*)(metadata + 1) > base + imageSize)
    {
        return FALSE;
    }

    // The program counter must be in ARM64EC code.
    const ARM64EC_CODE_RANGE* codeMap = (const ARM64EC_CODE_RANGE*)(base + metadata->CodeMap);
    BOOL inEcCode = FALSE;
    for (ULONG i = 0; i < metadata->CodeMapCount; i++)
    {
        DWORD start = codeMap[i].StartOffset & ~3u;
        if ((codeMap[i].StartOffset & 3u) == ARM64EC_CODE_RANGE_ARM64EC &&
            pcRva >= start && pcRva - start < codeMap[i].Length)
        {
            inEcCode = TRUE;
            break;
        }
    }
    if (!inEcCode)
    {
        return FALSE;
    }

    // Find the ARM64 function containing the program counter (sorted by BeginAddress).
    const IMAGE_ARM64_RUNTIME_FUNCTION_ENTRY* functions =
        (const IMAGE_ARM64_RUNTIME_FUNCTION_ENTRY*)(base + metadata->ExtraRFETable);
    ULONG low = 0;
    ULONG high = metadata->ExtraRFETableSize / sizeof(IMAGE_ARM64_RUNTIME_FUNCTION_ENTRY);
    while (low < high)
    {
        ULONG mid = low + (high - low) / 2;
        if (functions[mid].BeginAddress <= pcRva)
        {
            low = mid + 1;
        }
        else
        {
            high = mid;
        }
    }
    if (low == 0)
    {
        return FALSE;
    }
    const IMAGE_ARM64_RUNTIME_FUNCTION_ENTRY* function = &functions[low - 1];
    DWORD functionLength;
    if (function->Flag != 0)
    {
        functionLength = function->FunctionLength * 4;
    }
    else
    {
        functionLength = (*(const DWORD*)(base + function->UnwindData) & 0x3FFFF) * 4;
    }
    if (pcRva - function->BeginAddress >= functionLength)
    {
        return FALSE;
    }

    // Find the export whose x64 thunk jumps to that function.
    IMAGE_DATA_DIRECTORY exportDir = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
    if (exportDir.VirtualAddress == 0)
    {
        return FALSE;
    }
    const IMAGE_EXPORT_DIRECTORY* exports = (const IMAGE_EXPORT_DIRECTORY*)(base + exportDir.VirtualAddress);
    const DWORD* functionRvas = (const DWORD*)(base + exports->AddressOfFunctions);
    const DWORD* nameRvas = (const DWORD*)(base + exports->AddressOfNames);
    const WORD* nameOrdinals = (const WORD*)(base + exports->AddressOfNameOrdinals);
    for (DWORD i = 0; i < exports->NumberOfNames; i++)
    {
        WORD ordinal = nameOrdinals[i];
        if (ordinal >= exports->NumberOfFunctions)
        {
            continue;
        }
        DWORD thunkRva = functionRvas[ordinal];
        // Skip forwarders (RVA inside the export directory) and anything that
        // does not leave room for a complete thunk.
        if ((thunkRva >= exportDir.VirtualAddress && thunkRva - exportDir.VirtualAddress < exportDir.Size) ||
            thunkRva == 0 || thunkRva > imageSize - (sizeof(g_arm64EcExportThunk) + sizeof(LONG)))
        {
            continue;
        }
        const BYTE* thunk = base + thunkRva;
        if (memcmp(thunk, g_arm64EcExportThunk, sizeof(g_arm64EcExportThunk)) != 0)
        {
            continue;
        }
        LONG rel = *(const LONG*)(thunk + sizeof(g_arm64EcExportThunk));
        DWORD targetRva = thunkRva + (DWORD)(sizeof(g_arm64EcExportThunk) + sizeof(LONG)) + (DWORD)rel;
        if (targetRva != function->BeginAddress)
        {
            continue;
        }

        if (nameRvas[i] >= imageSize)
        {
            continue;
        }
        const char* exportName = (const char*)(base + nameRvas[i]);
        SIZE_T maxLength = imageSize - nameRvas[i];
        SIZE_T length = 0;
        while (length + 1 < nameChars && length < maxLength && exportName[length] != '\0')
        {
            name[length] = (WCHAR)(BYTE)exportName[length];
            length++;
        }
        name[length] = L'\0';
        *displacement = pcRva - function->BeginAddress;
        return TRUE;
    }
    return FALSE;
}

static BOOL s_isArm64Host = FALSE;

static BOOL CALLBACK QueryArm64Host(PINIT_ONCE, PVOID, PVOID*)
{
    typedef BOOL (WINAPI *IsWow64Process2_t)(HANDLE, USHORT*, USHORT*);
    // IsWow64Process2 tells the real host machine even to an emulated x64
    // process (GetNativeSystemInfo reports AMD64 there). It exists since
    // Windows 10 1709, the first release that runs on ARM64.
    IsWow64Process2_t isWow64Process2 = (IsWow64Process2_t)GetProcAddress(
        GetModuleHandleW(L"kernel32.dll"), "IsWow64Process2");
    USHORT processMachine = IMAGE_FILE_MACHINE_UNKNOWN;
    USHORT nativeMachine = IMAGE_FILE_MACHINE_UNKNOWN;
    s_isArm64Host = isWow64Process2 != NULL &&
        isWow64Process2(GetCurrentProcess(), &processMachine, &nativeMachine) &&
        nativeMachine == IMAGE_FILE_MACHINE_ARM64;
    return TRUE;
}

// Only ARM64 hosts load ARM64X images into x64 processes.
BOOL IsArm64Host()
{
    static INIT_ONCE s_arm64HostOnce = INIT_ONCE_STATIC_INIT;
    if (!InitOnceExecuteOnce(&s_arm64HostOnce, QueryArm64Host, NULL, NULL))
    {
        return FALSE;
    }
    return s_isArm64Host;
}

BOOL GetArm64EcExportName(UINT_PTR programCounter, LPWSTR name, SIZE_T nameChars, DWORD64* displacement)
{
    if (name == NULL || nameChars == 0 || displacement == NULL || !IsArm64Host())
    {
        return FALSE;
    }
    // Built aside so that a fault halfway leaves the caller's name intact.
    WCHAR candidate[256];
    DWORD64 candidateDisplacement = 0;
    BOOL found;
    // The module can be unloaded concurrently; treat any fault as "does not apply".
    __try
    {
        found = GetArm64EcExportNameUnsafe(programCounter, candidate,
            nameChars < _countof(candidate) ? nameChars : _countof(candidate), &candidateDisplacement);
    }
    __except (GetExceptionCode() == EXCEPTION_ACCESS_VIOLATION ? EXCEPTION_EXECUTE_HANDLER : EXCEPTION_CONTINUE_SEARCH)
    {
        found = FALSE;
    }
    if (found)
    {
        wcsncpy_s(name, nameChars, candidate, _TRUNCATE);
        *displacement = candidateDisplacement;
    }
    return found;
}
#endif // _M_X64

#define MAX_PATCH_ENTRY_COUNT 128

// PatchImport - Patches all future calls to an imported function, or references
//   to an imported variable, through to a replacement function or variable.
//   Patching is done by replacing the import's address in the specified target
//   module's Import Address Table (IAT) with the address of the replacement
//   function or variable.
//
//  - importmodule (IN): Handle (base address) of the target module for which
//      calls or references to the import should be patched.
//
//  - exportmodule (IN): Handle (base address) of the module that exports the
//      the function or variable to be patched.
//
//  - exportmodulename (IN): ANSI string containing the name of the module that
//      exports the function or variable to be patched.
//
//  - importname (IN): ANSI string containing the name of the imported function
//      or variable to be patched. May be an integer cast to a string if the
//      import is exported by ordinal.
//
//  - replacement (IN): Address of the function or variable to which future
//      calls or references should be patched through to. This function or
//      variable can be thought of as effectively replacing the original import
//      from the point of view of the module specified by "importmodule".
//
//  Return Value:
//
//    Returns TRUE if the patch was installed into the import module. If the
//    import module does not import the specified export, so nothing changed,
//    then FALSE will be returned.
//
BOOL PatchImport (HMODULE importmodule, moduleentry_t *patchModule)
{
    HMODULE exportmodule = (HMODULE)patchModule->moduleBase;
    if (exportmodule == NULL)
        return FALSE;

    IMAGE_IMPORT_DESCRIPTOR *idte = NULL;
    IMAGE_SECTION_HEADER    *section = NULL;
    ULONG                    size = 0;

    // Locate the importing module's Import Directory Table (IDT) entry for the
    // exporting module. The importing module actually can have several IATs --
    // one for each export module that it imports something from. The IDT entry
    // gives us the offset of the IAT for the module we are interested in.
    {
        idte = (IMAGE_IMPORT_DESCRIPTOR*)g_Ide.ImageDirectoryEntryToDataEx((PVOID)GetCallingModule((UINT_PTR)importmodule), TRUE,
            IMAGE_DIRECTORY_ENTRY_IMPORT, &size, &section);
    }

    if (idte == NULL) {
        // This module has no IDT (i.e. it imports nothing).
        return FALSE;
    }
#ifdef PRINTHOOKINFO
	bool dllNamePrinted = false;
	CHAR  cwBuffer[2048] = { 0 };
	LPSTR pszBuffer = cwBuffer;
	DWORD dwMaxChars = _countof(cwBuffer);
	DWORD dwLength = ::GetModuleFileNameA(importmodule, pszBuffer, dwMaxChars);
#endif

    // VLD's own module base. utility.cpp is compiled into the VLD module, so the
    // address of any function here resolves to VLD's own image. Used below to
    // ensure we never record VLD's own hook as the call-through original.
#if defined(_M_ARM64)
    HMODULE vldModule = GetCallingModule((UINT_PTR)&PatchImport);
#endif

    // have a stack local array of the addresses, don't want to use malloc for this
    // The reason to precompute and cache these is because VirtualProtect is expensive
    // Thus first we compute *only* once the real addresses for the export module
    LPVOID realAddresses[MAX_PATCH_ENTRY_COUNT];
    patchentry_t* patchEntry = patchModule->patchTable;
    int i = 0;
    while (patchEntry->importName)
    {
        LPCSTR importname = patchEntry->importName;

        // Get the *real* address of the import. If we find this address in the IAT,
        // then we've found the entry that needs to be patched. We use the saved
        // pointer to the real GetProcAddress (_RGetProcAddress); never the public
        // GetProcAddress, because PatchImport is called from the LDR LOADED
        // notification path and the public GetProcAddress is hooked - calling it
        // here could re-enter the loader lock and deadlock the parallel loader.
        LPVOID import = VisualLeakDetector::_RGetProcAddress(exportmodule, importname);
        import = FindRealCode(import);

        realAddresses[i] = import;

        patchEntry++;
        i++;

        if (i >= MAX_PATCH_ENTRY_COUNT)
        {
            // we only process MAX_PATCH_ENTRY_COUNT, if we exceed it crash
            // if this abort is ever hit, it means that MAX_PATCH_ENTRY_COUNT should be bumped up
            Report(L"MAX_PATCH_ENTRY_COUNT is set to %zu, but has been exceeded, MAX_PATCH_ENTRY_COUNT needs to be increased.\n", MAX_PATCH_ENTRY_COUNT);
            abort();
            break;
        }
    }

    int result = 0;
    while (idte->FirstThunk != 0x0) {
        PCHAR importdllname = (PCHAR)R2VA(importmodule, idte->Name);
        UNREFERENCED_PARAMETER(importdllname);
        // (No GetModuleHandleA here: it was previously called only to feed an
        // unused diagnostic, and like GetProcAddress it is hooked - calling it
        // from the LDR notification path would re-enter the loader lock.)

        // Locate the import's IAT entry.
        IMAGE_THUNK_DATA *thunk = (IMAGE_THUNK_DATA*)R2VA(importmodule, idte->FirstThunk);
        IMAGE_THUNK_DATA *origThunk = (IMAGE_THUNK_DATA*)R2VA(importmodule, idte->OriginalFirstThunk);
        for (; origThunk->u1.Function != NULL;
            origThunk++, thunk++)
        {
            LPVOID func = FindRealCode((LPVOID)thunk->u1.Function);

            patchEntry = patchModule->patchTable;
            i = 0;
            while (patchEntry->importName)
            {
                LPVOID import = realAddresses[i];
                if (import != NULL)
                {
                    LPCVOID replacement = patchEntry->replacement;

                    if (((DWORD_PTR)func == (DWORD_PTR)import))
                    {
                        // Found the IAT entry. Overwrite the address stored in the IAT
                        // entry with the address of the replacement. Note that the IAT
                        // entry may be write-protected, so we must first ensure that it is
                        // writable.
                        if (import != replacement)
                        {
                            // Never record VLD's own code as the call-through
                            // original. On ARM64 the kernel32 fast-forward
                            // dispatch can route a module's import through
                            // kernel32's internal IAT slot, which VLD has
                            // already patched, so FindRealCode may resolve
                            // "func" into VLD's own hook; storing that would
                            // make the hook call itself (infinite recursion).
                            // The real address is captured when VLD patches
                            // the exporting module's own import, before that
                            // slot is redirected. x64 has no fast-forward
                            // thunk chain that can route through VLD, so the
                            // unconditional store from upstream is preserved.
#if defined(_M_ARM64)
                            if (patchEntry->original != NULL &&
                                GetCallingModule((UINT_PTR)func) != vldModule)
                                *patchEntry->original = func;
#else
                            if (patchEntry->original != NULL)
                                *patchEntry->original = func;
#endif

                            DWORD protect;
                            if (VirtualProtect(&thunk->u1.Function, sizeof(thunk->u1.Function), PAGE_EXECUTE_READWRITE, &protect)) {
                                thunk->u1.Function = (DWORD_PTR)replacement;
                                if (VirtualProtect(&thunk->u1.Function, sizeof(thunk->u1.Function), protect, &protect)) {
#ifdef PRINTHOOKINFO
                                    if (!IS_ORDINAL(importname)) {
                                        DbgReport(L"Hook dll \"%S\" import %S!%S()\n",
                                            strrchr(pszBuffer, '\\') + 1, patchModule->exportModuleName, importname);
                                    }
                                    else {
                                        DbgReport(L"Hook dll \"%S\" import %S!%zu()\n",
                                            strrchr(pszBuffer, '\\') + 1, patchModule->exportModuleName, importname);
                                    }
#endif
                                }
                            }
                        }
                        // The patch has been installed in the import module.
                        result++;
                        break;
                    }
#ifdef PRINTHOOKINFO
                    PIMAGE_IMPORT_BY_NAME funcEntry = (PIMAGE_IMPORT_BY_NAME)
                        R2VA(importmodule, origThunk->u1.AddressOfData);
                    if (stricmp(importdllname, patchModule->exportModuleName) == 0)
                    {
                        if (!(origThunk->u1.Ordinal & IMAGE_ORDINAL_FLAG) && !IS_ORDINAL(importname) &&
                            strcmp(reinterpret_cast<const char*>(funcEntry->Name), importname) == 0)
                        {
                            if (!dllNamePrinted)
                            {
                                dllNamePrinted = true;
                                DbgReport(L"Hook dll \"%S\":\n",
                                    strrchr(pszBuffer, '\\') + 1);
                            }
                            DbgReport(L"Import found %S(\"%S\") for dll \"%S\".\n",
                                importname, patchModule->exportModuleName, importdllname);
                            break;
                        }
                        if ((origThunk->u1.Ordinal & IMAGE_ORDINAL_FLAG) && IS_ORDINAL(importname) &&
                            (IMAGE_ORDINAL(origThunk->u1.Ordinal) == (UINT_PTR)importname))
                        {
                            if (!dllNamePrinted)
                            {
                                dllNamePrinted = true;
                                DbgReport(L"Hook dll \"%S\":\n",
                                    strrchr(pszBuffer, '\\') + 1);
                            }
                            DbgReport(L"Import found %zu(\"%S\") for dll \"%S\".\n",
                                importname, patchModule->exportModuleName, importdllname);
                            break;
                        }
                    }
#endif
                }

                patchEntry++; i++;
            }
        }

        idte++;
    }

    // The import's IAT entry was not found. The importing module does not
    // import the specified import.
    return result > 0;
}

// PatchModule - Patches all imports listed in the supplied patch table, and
//   which are imported by the specified module, through to their respective
//   replacement functions.
//
//   Note: If the specified module does not import any of the functions listed
//     in the patch table, then nothing is changed for the specified module.
//
//  - importmodule (IN): Handle (base address) of the target module which is to
//      have its imports patched.
//
//  - patchtable (IN): An array of patchentry_t structures specifying all of the
//      imports to patch for the specified module.
//
//  - tablesize (IN): Size, in entries, of the specified patch table.
//
//  Return Value:
//
//    Returns TRUE if at least one of the patches listed in the patch table was
//    installed in the importmodule. Otherwise returns FALSE.
//
BOOL PatchModule (HMODULE importmodule, moduleentry_t patchtable [], UINT tablesize)
{
    moduleentry_t *entry;
    UINT          index;
    BOOL          patched = FALSE;

#ifdef PRINTHOOKINFO
    CHAR  cwBuffer[2048] = { 0 };
    LPSTR pszBuffer = cwBuffer;
    DWORD dwMaxChars = _countof(cwBuffer);
    DWORD dwLength = ::GetModuleFileNameA(importmodule, pszBuffer, dwMaxChars);
#endif

    // Loop through the import patch table, individually patching each import
    // listed in the table.
    DbgTrace(L"dbghelp32.dll %i: PatchModule - ImageDirectoryEntryToDataEx\n", GetCurrentThreadId());
    for (index = 0; index < tablesize; index++) {
        entry = &patchtable[index];
        if (PatchImport(importmodule, entry)) {
            patched = TRUE;
        }
    }

    return patched;
}

int CallReportHook(int reportType, LPWSTR message, int* hook_retval)
{
    if (g_pReportHooks == NULL)
        return 0;
    for (ReportHookSet::Iterator it = g_pReportHooks->begin(); it != g_pReportHooks->end(); ++it)
    {
        int result = (*it)(reportType, message, hook_retval);
        if (result) // handled
            return result;
    }
    return 0;
}

// Print - Sends a message to the debugger for display
//   and/or to a file.
//
//   Note: A message longer than MAXREPORTLENGTH characters will be truncated
//     to MAXREPORTLENGTH.
//
//  - ... (IN): Arguments to be formatted using the specified format string.
//
//  Return Value:
//
//    None.
//
VOID Print (LPWSTR messagew)
{
    if (NULL == messagew)
        return;

    int hook_retval=0;
    if (!CallReportHook(0, messagew, &hook_retval))
    {
        if (s_reportEncoding == unicode) {
            if (s_reportFile != NULL) {
                // Send the report to the previously specified file.
                fwrite(messagew, sizeof(WCHAR), wcslen(messagew), s_reportFile);
            }

            if ( s_reportToStdOut )
                fputws(messagew, stdout);
        }
        else {
            const size_t MAXMESSAGELENGTH = 5119;
            size_t  count = 0;
            CHAR    messagea [MAXMESSAGELENGTH + 1];
            errno_t err = wcstombs_s(&count, messagea, MAXMESSAGELENGTH + 1, messagew, _TRUNCATE);
            if (err != 0 && err != STRUNCATE) {
                // Failed to convert the Unicode message to ASCII.
                assert(FALSE);
                return;
            }
            messagea[MAXMESSAGELENGTH] = '\0';

            if (s_reportFile != NULL) {
                // Send the report to the previously specified file.
                fwrite(messagea, sizeof(CHAR), strlen(messagea), s_reportFile);
            }

            if ( s_reportToStdOut )
                fputs(messagea, stdout);
		}

		if (s_reportToDebugger)
			OutputDebugStringW(messagew);
    }
    else if (hook_retval == 1)
        __debugbreak();

    if (s_reportToDebugger && (s_reportDelay)) {
        Sleep(10); // Workaround the Visual Studio 6 bug where debug strings are sometimes lost if they're sent too fast.
    }
}

// Report - Sends a printf-style formatted message to the debugger for display
//   and/or to a file.
//
//   Note: A message longer than MAXREPORTLENGTH characters will be truncated
//     to MAXREPORTLENGTH.
//
//  - format (IN): Specifies a printf-compliant format string containing the
//      message to be sent to the debugger.
//
//  - ... (IN): Arguments to be formatted using the specified format string.
//
//  Return Value:
//
//    None.
//
VOID Report (LPCWSTR format, ...)
{
    va_list args;
    WCHAR   messagew [MAXREPORTLENGTH + 1];

    va_start(args, format);
    int result = _vsnwprintf_s(messagew, MAXREPORTLENGTH + 1, _TRUNCATE, format, args);
    va_end(args);
    messagew[MAXREPORTLENGTH] = L'\0';

    if (result >= 0)
        Print(messagew);
}

// RestoreImport - Restores the IAT entry for an import previously patched via
//   a call to "PatchImport" to the original address of the import.
//
//  - importmodule (IN): Handle (base address) of the target module for which
//      calls or references to the import should be restored.
//
//  - exportmodule (IN): Handle (base address) of the module that exports the
//      function or variable to be patched.
//
//  - exportmodulename (IN): ANSI string containing the name of the module that
//      exports the function or variable to be patched.
//
//  - importname (IN): ANSI string containing the name of the imported function
//      or variable to be restored. May be an integer cast to a string if the
//      import is exported by ordinal.
//
//  - replacement (IN): Address of the function or variable which the import was
//      previously patched through to via a call to "PatchImport".
//
//  Return Value:
//
//    None.
//
VOID RestoreImport (HMODULE importmodule, moduleentry_t* module)
{
    HMODULE exportmodule = (HMODULE)module->moduleBase;
    LPCSTR exportmodulename = module->exportModuleName;
    UNREFERENCED_PARAMETER(exportmodulename);
    if (exportmodule == NULL)
        return;

    IMAGE_IMPORT_DESCRIPTOR *idte = NULL;
    IMAGE_SECTION_HEADER    *section = NULL;
    ULONG                    size = 0;

    // Locate the importing module's Import Directory Table (IDT) entry for the
    // exporting module. The importing module actually can have several IATs --
    // one for each export module that it imports something from. The IDT entry
    // gives us the offset of the IAT for the module we are interested in.
    {
        idte = (IMAGE_IMPORT_DESCRIPTOR*)g_Ide.ImageDirectoryEntryToDataEx((PVOID)GetCallingModule((UINT_PTR)importmodule), TRUE,
            IMAGE_DIRECTORY_ENTRY_IMPORT, &size, &section);
    }

    if (idte == NULL) {
        // This module has no IDT (i.e. it imports nothing).
        return;
    }

#ifdef PRINTHOOKINFO
    bool dllNamePrinted = false;
    CHAR  cwBuffer[2048] = { 0 };
    LPSTR pszBuffer = cwBuffer;
    DWORD dwMaxChars = _countof(cwBuffer);
    DWORD dwLength = ::GetModuleFileNameA(importmodule, pszBuffer, dwMaxChars);
#endif

    int result = 0;
    while (idte->OriginalFirstThunk != 0x0)
    {
        PCHAR name = (PCHAR)R2VA(importmodule, idte->Name);
        UNREFERENCED_PARAMETER(name);

        int i = 0;
        patchentry_t *entry = module->patchTable;
        while(entry->importName)
        {
            LPCSTR importname   = entry->importName;
            LPCVOID replacement = entry->replacement;
            UNREFERENCED_PARAMETER(importname);

            // Get the *real* address of the import.
            //LPCVOID original = entry->original;
#if defined(_M_ARM64)
            // On ARM64, resolve heap APIs to the real kernelbase body captured at
            // attach rather than the kernel32 fast-forward dispatch thunk, whose
            // slot never resolves and spins at teardown (see Arm64Capture...).
            LPCVOID original = Arm64LookupKernelbaseHeapProc(importname);
            if (original == NULL)
                original = g_vld._RGetProcAddress(exportmodule, importname);
#else
            LPCVOID original = g_vld._RGetProcAddress(exportmodule, importname);
#endif
            if (original == NULL) // Perhaps the named export module does not actually export the named import?
            {
                entry++; i++;
                continue;
            }

            // Locate the import's original IAT entry (it currently has the replacement
            // address in it).
            IMAGE_THUNK_DATA* iate = (IMAGE_THUNK_DATA*)R2VA(importmodule, idte->FirstThunk);
            while (iate->u1.Function != 0x0)
            {
                if (iate->u1.Function != (DWORD_PTR)replacement)
                {
                    iate++;
                    continue;
                }

                if (iate->u1.Function != (DWORD_PTR)original)
                {
                    // Found the IAT entry. Overwrite the address stored in the IAT
                    // entry with the import's real address. Note that the IAT entry may
                    // be write-protected, so we must first ensure that it is writable.
                    DWORD protect;
                    if (VirtualProtect(&iate->u1.Function, sizeof(iate->u1.Function), PAGE_EXECUTE_READWRITE, &protect)) {
                        iate->u1.Function = (DWORD_PTR)original;
                        if (VirtualProtect(&iate->u1.Function, sizeof(iate->u1.Function), protect, &protect)) {
#ifdef PRINTHOOKINFO
                            if (!IS_ORDINAL(importname)) {
                                DbgReport(L"UnHook dll \"%S\" import %S!%S()\n",
                                    strrchr(pszBuffer, '\\') + 1, module->exportModuleName, importname);
                            } else {
                                DbgReport(L"UnHook dll \"%S\" import %S!%zu()\n",
                                    strrchr(pszBuffer, '\\') + 1, module->exportModuleName, importname);
                            }
#endif
                        }
                    }
                }
                result++;
                iate++;
            }
            entry++; i++;
        }
        idte++;
    }
}

// RestoreModule - Restores all imports listed in the supplied patch table, and
//   which are imported by the specified module, to their original functions.
//
//   Note: If the specified module does not import any of the functions listed
//     in the patch table, then nothing is changed for the specified module.
//
//  - importmodule (IN): Handle (base address) of the target module which is to
//      have its imports restored.
//
//  - patchtable (IN): Array of patchentry_t structures specifying all of the
//      imports to restore for the specified module.
//
//  - tablesize (IN): Size, in entries, of the specified patch table.
//
//  Return Value:
//
//    None.
//
VOID RestoreModule (HMODULE importmodule, moduleentry_t patchtable [], UINT tablesize)
{
    moduleentry_t *entry;
    UINT          index;

    // Loop through the import patch table, individually restoring each import
    // listed in the table.
    DbgTrace(L"dbghelp32.dll %i: RestoreModule - ImageDirectoryEntryToDataEx\n", GetCurrentThreadId());
    for (index = 0; index < tablesize; index++) {
        entry = &patchtable[index];
        RestoreImport(importmodule, entry);
    }
}

// SetReportEncoding - Sets the output encoding of report messages to either
//   ASCII (the default) or Unicode.
//
//  - encoding (IN): Specifies either "ascii" or "unicode".
//
//  Return Value:
//
//    None.
//
VOID SetReportEncoding (encoding_e encoding)
{
    switch (encoding) {
    case ascii:
    case unicode:
        s_reportEncoding = encoding;
        break;

    default:
        assert(FALSE);
    }
}

// SetReportFile - Sets a destination file to which all report messages should
//   be sent. If this function is not called to set a destination file, then
//   report messages will be sent to the debugger instead of to a file.
//
//  - file (IN): Pointer to an open file, to which future report messages should
//      be sent.
//
//  - copydebugger (IN): If true, in addition to sending report messages to
//      the specified file, a copy of each message will also be sent to the
//      debugger.
//
//  Return Value:
//
//    None.
//
VOID SetReportFile (FILE *file, BOOL copydebugger, BOOL tostdout)
{
    s_reportFile = file;
    s_reportToDebugger = copydebugger;
    s_reportToStdOut = tostdout;
}

// AppendString - Appends the specified source string to the specified destination
//   string. Allocates additional space so that the destination string "grows"
//   as new strings are appended to it. This is accomplished by deleting the
//   destination string after the new longer string is gets the copied contents
//   of the destination and additional text. This function is fairly infrequently
//   used so efficiency is not a major concern.
//
//  - dest (IN): Address of the destination string. Receives the resulting
//      combined string after the append operation.
//
//  - source (IN): Source string to be appended to the destination string.
//
//  Return Value:
//
//    The new concatenated string.
//
LPWSTR AppendString (LPWSTR dest, LPCWSTR source)
{
    if ((source == NULL) || (source[0] == '\0'))
    {
        return dest;
    }
    SIZE_T length = wcslen(dest) + wcslen(source);
    LPWSTR new_str = new WCHAR [length + 1];
    wcsncpy_s(new_str, length + 1, dest, _TRUNCATE);
    wcsncat_s(new_str, length + 1, source, _TRUNCATE);
    delete [] dest;
    return new_str;
}

// StrToBool - Converts string values (e.g. "yes", "no", "on", "off") to boolean
//   values.
//
//  - s (IN): String value to convert.
//
//  Return Value:
//
//    Returns TRUE if the string is recognized as a "true" string. Otherwise
//    returns FALSE.
//
BOOL StrToBool (LPCWSTR s) {
    WCHAR *end;

    if ((_wcsicmp(s, L"true") == 0) ||
        (_wcsicmp(s, L"yes") == 0) ||
        (_wcsicmp(s, L"on") == 0) ||
        (wcstol(s, &end, 10) == 1)) {
        return TRUE;
    }
    else {
        return FALSE;
    }
}

static const DWORD crctab[256] = {
    0x00000000, 0x77073096, 0xee0e612c, 0x990951ba, 0x076dc419, 0x706af48f,
    0xe963a535, 0x9e6495a3, 0x0edb8832, 0x79dcb8a4, 0xe0d5e91e, 0x97d2d988,
    0x09b64c2b, 0x7eb17cbd, 0xe7b82d07, 0x90bf1d91, 0x1db71064, 0x6ab020f2,
    0xf3b97148, 0x84be41de, 0x1adad47d, 0x6ddde4eb, 0xf4d4b551, 0x83d385c7,
    0x136c9856, 0x646ba8c0, 0xfd62f97a, 0x8a65c9ec, 0x14015c4f, 0x63066cd9,
    0xfa0f3d63, 0x8d080df5, 0x3b6e20c8, 0x4c69105e, 0xd56041e4, 0xa2677172,
    0x3c03e4d1, 0x4b04d447, 0xd20d85fd, 0xa50ab56b, 0x35b5a8fa, 0x42b2986c,
    0xdbbbc9d6, 0xacbcf940, 0x32d86ce3, 0x45df5c75, 0xdcd60dcf, 0xabd13d59,
    0x26d930ac, 0x51de003a, 0xc8d75180, 0xbfd06116, 0x21b4f4b5, 0x56b3c423,
    0xcfba9599, 0xb8bda50f, 0x2802b89e, 0x5f058808, 0xc60cd9b2, 0xb10be924,
    0x2f6f7c87, 0x58684c11, 0xc1611dab, 0xb6662d3d, 0x76dc4190, 0x01db7106,
    0x98d220bc, 0xefd5102a, 0x71b18589, 0x06b6b51f, 0x9fbfe4a5, 0xe8b8d433,
    0x7807c9a2, 0x0f00f934, 0x9609a88e, 0xe10e9818, 0x7f6a0dbb, 0x086d3d2d,
    0x91646c97, 0xe6635c01, 0x6b6b51f4, 0x1c6c6162, 0x856530d8, 0xf262004e,
    0x6c0695ed, 0x1b01a57b, 0x8208f4c1, 0xf50fc457, 0x65b0d9c6, 0x12b7e950,
    0x8bbeb8ea, 0xfcb9887c, 0x62dd1ddf, 0x15da2d49, 0x8cd37cf3, 0xfbd44c65,
    0x4db26158, 0x3ab551ce, 0xa3bc0074, 0xd4bb30e2, 0x4adfa541, 0x3dd895d7,
    0xa4d1c46d, 0xd3d6f4fb, 0x4369e96a, 0x346ed9fc, 0xad678846, 0xda60b8d0,
    0x44042d73, 0x33031de5, 0xaa0a4c5f, 0xdd0d7cc9, 0x5005713c, 0x270241aa,
    0xbe0b1010, 0xc90c2086, 0x5768b525, 0x206f85b3, 0xb966d409, 0xce61e49f,
    0x5edef90e, 0x29d9c998, 0xb0d09822, 0xc7d7a8b4, 0x59b33d17, 0x2eb40d81,
    0xb7bd5c3b, 0xc0ba6cad, 0xedb88320, 0x9abfb3b6, 0x03b6e20c, 0x74b1d29a,
    0xead54739, 0x9dd277af, 0x04db2615, 0x73dc1683, 0xe3630b12, 0x94643b84,
    0x0d6d6a3e, 0x7a6a5aa8, 0xe40ecf0b, 0x9309ff9d, 0x0a00ae27, 0x7d079eb1,
    0xf00f9344, 0x8708a3d2, 0x1e01f268, 0x6906c2fe, 0xf762575d, 0x806567cb,
    0x196c3671, 0x6e6b06e7, 0xfed41b76, 0x89d32be0, 0x10da7a5a, 0x67dd4acc,
    0xf9b9df6f, 0x8ebeeff9, 0x17b7be43, 0x60b08ed5, 0xd6d6a3e8, 0xa1d1937e,
    0x38d8c2c4, 0x4fdff252, 0xd1bb67f1, 0xa6bc5767, 0x3fb506dd, 0x48b2364b,
    0xd80d2bda, 0xaf0a1b4c, 0x36034af6, 0x41047a60, 0xdf60efc3, 0xa867df55,
    0x316e8eef, 0x4669be79, 0xcb61b38c, 0xbc66831a, 0x256fd2a0, 0x5268e236,
    0xcc0c7795, 0xbb0b4703, 0x220216b9, 0x5505262f, 0xc5ba3bbe, 0xb2bd0b28,
    0x2bb45a92, 0x5cb36a04, 0xc2d7ffa7, 0xb5d0cf31, 0x2cd99e8b, 0x5bdeae1d,
    0x9b64c2b0, 0xec63f226, 0x756aa39c, 0x026d930a, 0x9c0906a9, 0xeb0e363f,
    0x72076785, 0x05005713, 0x95bf4a82, 0xe2b87a14, 0x7bb12bae, 0x0cb61b38,
    0x92d28e9b, 0xe5d5be0d, 0x7cdcefb7, 0x0bdbdf21, 0x86d3d2d4, 0xf1d4e242,
    0x68ddb3f8, 0x1fda836e, 0x81be16cd, 0xf6b9265b, 0x6fb077e1, 0x18b74777,
    0x88085ae6, 0xff0f6a70, 0x66063bca, 0x11010b5c, 0x8f659eff, 0xf862ae69,
    0x616bffd3, 0x166ccf45, 0xa00ae278, 0xd70dd2ee, 0x4e048354, 0x3903b3c2,
    0xa7672661, 0xd06016f7, 0x4969474d, 0x3e6e77db, 0xaed16a4a, 0xd9d65adc,
    0x40df0b66, 0x37d83bf0, 0xa9bcae53, 0xdebb9ec5, 0x47b2cf7f, 0x30b5ffe9,
    0xbdbdf21c, 0xcabac28a, 0x53b39330, 0x24b4a3a6, 0xbad03605, 0xcdd70693,
    0x54de5729, 0x23d967bf, 0xb3667a2e, 0xc4614ab8, 0x5d681b02, 0x2a6f2b94,
    0xb40bbe37, 0xc30c8ea1, 0x5a05df1b, 0x2d02ef8d,
};

DWORD CalculateCRC32(UINT_PTR p, UINT startValue)
{
    DWORD hash = startValue;
    hash = (hash >> 8) ^ crctab[(hash & 0xff) ^ ((p >>  0) & 0xff)];
    hash = (hash >> 8) ^ crctab[(hash & 0xff) ^ ((p >>  8) & 0xff)];
    hash = (hash >> 8) ^ crctab[(hash & 0xff) ^ ((p >> 16) & 0xff)];
    hash = (hash >> 8) ^ crctab[(hash & 0xff) ^ ((p >> 24) & 0xff)];
#ifdef WIN64
    hash = (hash >> 8) ^ crctab[(hash & 0xff) ^ ((p >> 32) & 0xff)];
    hash = (hash >> 8) ^ crctab[(hash & 0xff) ^ ((p >> 40) & 0xff)];
    hash = (hash >> 8) ^ crctab[(hash & 0xff) ^ ((p >> 48) & 0xff)];
    hash = (hash >> 8) ^ crctab[(hash & 0xff) ^ ((p >> 56) & 0xff)];
#endif
    return hash;
}

// Formats a message string using the specified message and variable
// list of arguments.
void GetFormattedMessage(DWORD last_error)
{
    // Retrieve the system error message for the last-error code
    WCHAR lpMsgBuf[MAX_PATH] = {0};

    FormatMessage(
        FORMAT_MESSAGE_FROM_SYSTEM |
        FORMAT_MESSAGE_IGNORE_INSERTS,
        NULL,
        last_error,
        MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
        lpMsgBuf,
        MAX_PATH,
        NULL );

    // Display the error message.
    Report(L"%s", lpMsgBuf);
}

// GetCallingModule - Return calling module by address.
//
//  Return Value:
//
//    Module handle.
//
HMODULE GetCallingModule(UINT_PTR pCaller )
{
    HMODULE hModule = NULL;

#if defined(_M_ARM64)
    if (VldArm64InTeardown())
    {
        // During ARM64 process-exit teardown the loader lock is held and the
        // QueryVirtualMemoryInformation / VirtualQuery calls below reach
        // NtQueryVirtualMemory, which intermittently livelocks (aka.ms/AA10dvw4).
        // Use a loader-based lookup that walks the loaded-module list instead and
        // cannot wedge. For a code address (every call-stack frame) this returns
        // the same module base; for a non-module address it returns NULL, which
        // all callers already treat as "not a tracked module".
        HMODULE hMod = NULL;
        if (GetModuleHandleExW(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS | GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
                               reinterpret_cast<LPCWSTR>(pCaller), &hMod))
        {
            return hMod;
        }
        return NULL;
    }
#endif

    // Try QueryVirtualMemoryInformation first (Windows 10 1607+)
    WIN32_MEMORY_REGION_INFORMATION memoryRegionInfo;
    if ( QueryVirtualMemoryInformation(GetCurrentProcess(), (LPCVOID)pCaller, MemoryRegionInfo, &memoryRegionInfo, sizeof(memoryRegionInfo), NULL) )
    {
        // the allocation base is the beginning of a PE file
        hModule = (HMODULE)memoryRegionInfo.AllocationBase;
    }
    else {
        // Fall back to VirtualQuery for older systems or when QueryVirtualMemoryInformation fails
        MEMORY_BASIC_INFORMATION mbi;
        if (VirtualQuery((LPCVOID)pCaller, &mbi, sizeof(MEMORY_BASIC_INFORMATION)) == sizeof(MEMORY_BASIC_INFORMATION))
        {
            // the allocation base is the beginning of a PE file
            hModule = (HMODULE)mbi.AllocationBase;
        }
    }
    return hModule;
}

// LoadBoolOption - Loads specified option from environment variables or from specified ini file,
//   if env var is unavailable and converts string values (e.g. "yes", "no", "on", "off") to boolean values.
//
//  - optionname (IN): Option to load.
//
//  - defaultvalue (IN): Default value if optionname in unavailable.
//
//  - inipath (IN): Path to configuration ini file.
//
//  Return Value:
//
//    Returns TRUE if the string is recognized as a "true" string. Otherwise
//    returns FALSE.
//
BOOL LoadBoolOption(LPCWSTR optionname, LPCWSTR defaultvalue, LPCWSTR inipath)
{
    const UINT buffersize = 64;
    WCHAR buffer[buffersize] = { 0 };

    WCHAR envirinmentoptionname[buffersize] = L"Vld";
    wcscat_s(envirinmentoptionname, buffersize, optionname);

    if (!GetEnvironmentVariable(envirinmentoptionname, buffer, buffersize)) {
        GetPrivateProfileString(L"Options", optionname, defaultvalue, buffer, buffersize, inipath);
    }

    return StrToBool(buffer);
}

// LoadIntOption - Loads specified option from environment variables or from specified ini file,
//   if env var is unavailable.
//
//  - optionname (IN): Option to load
//
//  - defaultvalue (IN): Default value if optionname in unavailable.
//
//  - inipath (IN): Path to configuration ini file.
//
//  Return Value:
//
//    Returns integer representation of optionname's value.
//
UINT LoadIntOption(LPCWSTR optionname, UINT defaultvalue, LPCWSTR inipath)
{
    const UINT buffersize = 64;
    WCHAR buffer[buffersize] = { 0 };

    WCHAR envirinmentoptionname[buffersize] = L"Vld";
    wcscat_s(envirinmentoptionname, buffersize, optionname);

    if (!GetEnvironmentVariable(envirinmentoptionname, buffer, buffersize)) {
        return GetPrivateProfileInt(L"Options", optionname, defaultvalue, inipath);
    }

    return _tstoi(buffer);
}

// LoadStringOption - Loads specified option from environment variables or from specified ini file,
//   if env var is unavailable.
//
//  - optionname (IN): Option to load.
//
//  - outputbuffer (OUT): A buffer to store the string.
//
//  - buffersize (IN): Size of a buffer in characters.
//
//  - inipath (IN): Path to configuration ini file.
//
//  Return Value:
//
//    None.
//
VOID LoadStringOption(LPCWSTR optionname, LPWSTR outputbuffer, UINT buffersize, LPCWSTR inipath)
{
    const UINT namebuffersize = 64;
    WCHAR envirinmentoptionname[namebuffersize] = L"Vld";
    wcscat_s(envirinmentoptionname, namebuffersize, optionname);

    if (!GetEnvironmentVariable(envirinmentoptionname, outputbuffer, buffersize)) {
        GetPrivateProfileString(L"Options", optionname, L"", outputbuffer, buffersize, inipath);
    }
}