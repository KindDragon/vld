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

// Imported Global Variables
extern CriticalSection  g_imageLock;
extern ReportHookSet*   g_pReportHooks;

// Global variables.
static BOOL         s_reportDelay = FALSE;     // If TRUE, we sleep for a bit after calling OutputDebugString to give the debugger time to catch up.
static FILE        *s_reportFile = NULL;       // Pointer to the file, if any, to send the memory leak report to.
static BOOL         s_reportToDebugger = TRUE; // If TRUE, a copy of the memory leak report will be sent to the debugger for display.
static BOOL         s_reportToStdOut = TRUE;   // If TRUE, a copy of the memory leak report will be sent to standard output.
static encoding_e   s_reportEncoding = ascii;  // Output encoding of the memory leak report.

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
    g_imageLock.Enter();
    __try
    {
        idte = (IMAGE_IMPORT_DESCRIPTOR*)ImageDirectoryEntryToDataEx((PVOID)importmodule, TRUE,
            IMAGE_DIRECTORY_ENTRY_IMPORT, &size, &section);
    }
    __except(FilterFunction(GetExceptionCode()))
    {
        idte = NULL;
    }
    g_imageLock.Leave();
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
        if (found == TRUE) {
            // Found one of the listed patches installed in the import module.
            return TRUE;
        }
    }

    // No patches listed in the patch table were found in the import module.
    return FALSE;
}

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
BOOL PatchImport (HMODULE importmodule, moduleentry_t *module)
{
    HMODULE exportmodule = (HMODULE)module->moduleBase;
    if (exportmodule == NULL)
        return FALSE;

    IMAGE_IMPORT_DESCRIPTOR *idte;
    IMAGE_SECTION_HEADER    *section;
    ULONG                    size;

    // Locate the importing module's Import Directory Table (IDT) entry for the
    // exporting module. The importing module actually can have several IATs --
    // one for each export module that it imports something from. The IDT entry
    // gives us the offset of the IAT for the module we are interested in.
    g_imageLock.Enter();
    __try
    {
        idte = (IMAGE_IMPORT_DESCRIPTOR*)ImageDirectoryEntryToDataEx((PVOID)importmodule, TRUE,
            IMAGE_DIRECTORY_ENTRY_IMPORT, &size, &section);
    }
    __except(FilterFunction(GetExceptionCode()))
    {
        idte = NULL;
    }
    g_imageLock.Leave();
    if (idte == NULL) {
        // This module has no IDT (i.e. it imports nothing).
        return FALSE;
    }

    int result = 0;
    while (idte->FirstThunk != 0x0) {
        PCHAR name = (PCHAR)R2VA(importmodule, idte->Name);
        UNREFERENCED_PARAMETER(name);

        patchentry_t *entry = module->patchTable;
        int i = 0;
        while(entry->importName)
        {
            LPCSTR importname   = entry->importName;
            LPCVOID replacement = entry->replacement;

            // Get the *real* address of the import. If we find this address in the IAT,
            // then we've found the entry that needs to be patched.
            FARPROC import2 = VisualLeakDetector::_RGetProcAddress(exportmodule, importname);
            FARPROC import = GetProcAddress(exportmodule, importname);
            if ( import2 )
                import = import2;

            if (import == NULL) // Perhaps the named export module does not actually export the named import?
            {
                entry++; i++;
                continue;
            }

            // Locate the import's IAT entry.
            IMAGE_THUNK_DATA *iate = (IMAGE_THUNK_DATA*)R2VA(importmodule, idte->FirstThunk);
            while (iate->u1.Function != 0x0)
            {
                if (iate->u1.Function != (DWORD_PTR)import) 
                {
                    iate++;
                    continue;
                }

                // Found the IAT entry. Overwrite the address stored in the IAT
                // entry with the address of the replacement. Note that the IAT
                // entry may be write-protected, so we must first ensure that it is
                // writable.
                if ( import != replacement )
                {
                    if (entry->original != NULL)
                        *entry->original = (LPVOID)iate->u1.Function;

                    DWORD protect;
                    VirtualProtect(&iate->u1.Function, sizeof(iate->u1.Function), PAGE_EXECUTE_READWRITE, &protect);
                    iate->u1.Function = (DWORD_PTR)replacement;
                    VirtualProtect(&iate->u1.Function, sizeof(iate->u1.Function), protect, &protect);
                }
                // The patch has been installed in the import module.
                result++;
                iate++;
            }
            entry++; i++;
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

    // Loop through the import patch table, individually patching each import
    // listed in the table.
    DbgTrace(L"dbghelp32.dll %i: PatchModule - ImageDirectoryEntryToDataEx\n", GetCurrentThreadId());
    for (index = 0; index < tablesize; index++) {
        entry = &patchtable[index];
        if (PatchImport(importmodule, entry) == TRUE) {
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
            size_t  count = 0;
            CHAR    messagea [MAXREPORTLENGTH + 1];
            if (wcstombs_s(&count, messagea, MAXREPORTLENGTH + 1, messagew, _TRUNCATE) != 0) {
                // Failed to convert the Unicode message to ASCII.
                assert(FALSE);
                return;
            }
            messagea[MAXREPORTLENGTH] = '\0';

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

    if (s_reportToDebugger && (s_reportDelay == TRUE)) {
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

    IMAGE_IMPORT_DESCRIPTOR *idte;
    IMAGE_SECTION_HEADER    *section;
    ULONG                    size;

    // Locate the importing module's Import Directory Table (IDT) entry for the
    // exporting module. The importing module actually can have several IATs --
    // one for each export module that it imports something from. The IDT entry
    // gives us the offset of the IAT for the module we are interested in.
    g_imageLock.Enter();
    __try
    {
        idte = (IMAGE_IMPORT_DESCRIPTOR*)ImageDirectoryEntryToDataEx((PVOID)importmodule, TRUE,
            IMAGE_DIRECTORY_ENTRY_IMPORT, &size, &section);
    }
    __except(FilterFunction(GetExceptionCode()))
    {
        idte = NULL;
    }
    g_imageLock.Leave();
    if (idte == NULL) {
        // This module has no IDT (i.e. it imports nothing).
        return;
    }

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
            LPCVOID original = GetProcAddress(exportmodule, importname);
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
                    VirtualProtect(&iate->u1.Function, sizeof(iate->u1.Function), PAGE_EXECUTE_READWRITE, &protect);
                    iate->u1.Function = (DWORD_PTR)original;
                    VirtualProtect(&iate->u1.Function, sizeof(iate->u1.Function), protect, &protect);
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

// _GetProcessIdOfThread - Returns the ID of the process owns the thread.
//
//  - thread (IN): The handle to the thread.
//
//  Return Value:
//
//    Returns the ID of the process that owns the thread. Otherwise returns 0.
//
DWORD _GetProcessIdOfThread (HANDLE thread)
{
    typedef struct _CLIENT_ID {
        HANDLE UniqueProcess;
        HANDLE UniqueThread;
    } CLIENT_ID, *PCLIENT_ID;

    typedef LONG NTSTATUS;
    typedef LONG KPRIORITY;

    typedef struct _THREAD_BASIC_INFORMATION {
        NTSTATUS  ExitStatus;
        PVOID     TebBaseAddress;
        CLIENT_ID ClientId;
        KAFFINITY AffinityMask;
        KPRIORITY Priority;
        KPRIORITY BasePriority;
    } THREAD_BASIC_INFORMATION, *PTHREAD_BASIC_INFORMATION;

    const static THREADINFOCLASS ThreadBasicInformation = (THREADINFOCLASS)0;

    typedef NTSTATUS (WINAPI *PNtQueryInformationThread) (HANDLE thread,
        THREADINFOCLASS infoclass, PVOID buffer, ULONG buffersize,
        PULONG used);

    static PNtQueryInformationThread NtQueryInformationThread = NULL;

    THREAD_BASIC_INFORMATION tbi;
    NTSTATUS status;
    if (NtQueryInformationThread == NULL) {
        HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");
        if (ntdll)
        {
            NtQueryInformationThread = (PNtQueryInformationThread)GetProcAddress(ntdll, "NtQueryInformationThread");
        }

        if (NtQueryInformationThread == NULL) {
            return 0;
        }
    }

    status = NtQueryInformationThread(thread, ThreadBasicInformation, &tbi, sizeof(tbi), NULL);
    if(status < 0) {
        // Shall we go through all the trouble of setting last error?
        return 0;
    }

    return (DWORD)tbi.ClientId.UniqueProcess;
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
    register DWORD hash = startValue;
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
HMODULE GetCallingModule( UINT_PTR pCaller )
{
    HMODULE hModule = NULL;
    MEMORY_BASIC_INFORMATION mbi;
    if ( VirtualQuery((LPCVOID)pCaller, &mbi, sizeof(MEMORY_BASIC_INFORMATION)) == sizeof(MEMORY_BASIC_INFORMATION) )
    {
        // the allocation base is the beginning of a PE file 
        hModule = (HMODULE) mbi.AllocationBase;
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