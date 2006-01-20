////////////////////////////////////////////////////////////////////////////////
//  $Id: utility.cpp,v 1.4 2006/01/20 01:14:40 dmouldin Exp $
//
//  Visual Leak Detector (Version 1.0)
//  Copyright (c) 2005 Dan Moulding
//
//  This program is free software; you can redistribute it and/or modify
//  it under the terms of the GNU Lesser General Public License as published by
//  the Free Software Foundation; either version 2.1 of the License, or
//  (at your option) any later version.
//
//  This program is distributed in the hope that it will be useful,
//  but WITHOUT ANY WARRANTY; without even the implied warranty of
//  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
//  GNU Lesser General Public License for more details.
//
//  You should have received a copy of the GNU Lesser General Public License
//  along with this program; if not, write to the Free Software
//  Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
//
//  See COPYING.txt for the full terms of the GNU Lesser General Public License.
//
////////////////////////////////////////////////////////////////////////////////

#include <cassert>
#include <cstdio>
#include <windows.h>
#define __out_xcount(x) // Workaround for the specstrings.h bug in the Platform SDK.
#include <dbghelp.h>    // Provides PE executable image access functions.
#include <tchar.h>
#define VLDBUILD        // Declares that we are building Visual Leak Detector.
#include "utility.h"    // Provides various utility functions.
#include "vldheap.h"    // Provides internal new and delete operators.

// Imported global variables.
extern HANDLE currentprocess;
extern HANDLE currentthread;
extern SIZE_T serialnumber;

// Global variables.
static FILE *reportfile = NULL;
static BOOL  reporttodebugger = TRUE;

// booltostr - Converts boolean values to string values ("true" or "false").
//
//  - b (IN): Boolean value to convert.
//
//  Return Value:
//
//  - String containing "true" if the input is true.
//  - String containing "false" if the input is false.
//
LPCTSTR booltostr (BOOL b)
{
    if (b == TRUE) {
        return _T("true");
    }
    else {
        return _T("false");
    }
}

// dumpmemory - Dumps a nicely formatted rendition of a region of memory to the
//   debugger's output window. Includes both the hex value of each byte and its
//   ASCII equivalent (if printable).
//
//  - address (IN): Pointer to the beginning of the memory region to dump.
//
//  - size (IN): The size of the region to dump.
//
//  Return Value:
//
//    None.
//
VOID dumpmemory (LPCVOID address, SIZE_T size)
{
    char          ascdump [18] = {0};
    size_t        ascindex;
    unsigned long byte;
    unsigned long bytesdone;
    unsigned char datum;
    unsigned long dumplen;
    char          formatbuf [4];
    char          hexdump [58] = {0};
    size_t        hexindex;

    // Each line of output is 16 bytes.
    if ((size % 16) == 0) {
        // No padding needed.
        dumplen = size;
    }
    else {
        // We'll need to pad the last line out to 16 bytes.
        dumplen = size + (16 - (size % 16));
    }

    // For each byte of data, get both the ASCII equivalent (if it is a
    // printable character) and the hex representation.
    bytesdone = 0;
    for (byte = 0; byte < dumplen; byte++) {
        hexindex = 3 * ((byte % 16) + ((byte % 16) / 4)); // 3 characters per byte, plus a 3-character space after every 4 bytes.
        ascindex = (byte % 16) + (byte % 16) / 8; // 1 character per byte, plus a 1-character space after every 8 bytes.
        if (byte < size) {
            datum = ((unsigned char*)address)[byte];
            sprintf(formatbuf, "%.2X ", datum);
            strncpy(hexdump + hexindex, formatbuf, 4);
            if (isprint(datum) && (datum != ' ')) {
                ascdump[ascindex] = datum;
            }
            else {
                ascdump[ascindex] = '.';
            }
        }
        else {
            // Add padding to fill out the last line to 16 bytes.
            strncpy(hexdump + hexindex, "   ", 4);
            ascdump[ascindex] = '.';
        }
        bytesdone++;
        if ((bytesdone % 16) == 0) {
            // Print one line of data for every 16 bytes. Include the
            // ASCII dump and the hex dump side-by-side.
            report(_T("    %s    %s\n"), hexdump, ascdump);
        }
        else {
            if ((bytesdone % 8) == 0) {
                // Add a spacer in the ASCII dump after every two words.
                ascdump[ascindex + 1] = ' ';
            }
            if ((bytesdone % 4) == 0) {
                // Add a spacer in the hex dump after every word.
                strncpy(hexdump + hexindex + 3, "   ", 4);
            }
        }
    }
}

// getprogramcounterx86x64 - Helper function that retrieves the program counter
//   (aka the EIP (x86) or RIP (x64) register) for CallStack::getstacktrace() on
//   Intel x86 or x64 architectures (x64 supports both AMD64 and Intel EM64T).
//
//   There is no way for software to directly read the EIP/RIP register. But
//   it's value can be obtained by calling into a function (in our case, this
//   function) and then retrieving the return address, which will be the program
//   counter from where the function was called.
//
//   Note: Inlining of this function must be disabled. The whole purpose of this
//     function's existence depends upon it being a *called* function.
//
//  Return Value:
//
//    Returns the caller's program address.
//
#if defined(_M_IX86) || defined(_M_X64)
#pragma auto_inline(off)
SIZE_T getprogramcounterx86x64 ()
{
    SIZE_T programcounter;

    __asm mov AXREG, [BPREG + SIZEOFPTR] // Get the return address out of the current stack frame
    __asm mov [programcounter], AXREG    // Put the return address into the variable we'll return

    return programcounter;
}
#pragma auto_inline(on)
#endif // defined(_M_IX86) || defined(_M_X64)

// patchimport - Patches all future calls to an imported function, or references
//   to an imported variable, through to a replacement function or variable.
//   Patching is done by replacing the import's address in the specified target
//   module's Import Address Table (IAT) with the address of the replacement
//   function or variable.
//
//  - importmodule (IN): Handle (base address) of the target module for which
//      calls or references to the import should be patched.
//
//  - exportmodulename (IN): ANSI string containing the name of the module that
//      exports the function or variable to be patched.
//
//  - importname (IN): ANSI string containing the name of the imported function
//      or variable to be patched.
//
//  - replacement (IN): Address of the function or variable to which future
//      calls or references should be patched through to. This function or
//      variable can be thought of as effectively replacing the original import
//      from the point of view of the module specified by "importmodule".
//
//  Return Value:
//
//    None.
//   
VOID patchimport (HMODULE importmodule, LPCSTR exportmodulename, LPCSTR importname, LPCVOID replacement)
{
    HMODULE                  exportmodule;
    IMAGE_THUNK_DATA        *iate;
    IMAGE_IMPORT_DESCRIPTOR *idte;
    FARPROC                  import;
    DWORD                    protect;
    IMAGE_SECTION_HEADER    *section;
    ULONG                    size;
            
    // Locate the importing module's Import Directory Table (IDT) entry for the
    // exporting module. The importing module actually can have several IATs --
    // one for each export module that it imports something from. The IDT entry
    // gives us the offset of the IAT for the module we are interested in.
    idte = (IMAGE_IMPORT_DESCRIPTOR*)ImageDirectoryEntryToDataEx((PVOID)importmodule, TRUE, IMAGE_DIRECTORY_ENTRY_IMPORT, &size, &section);
    if (idte == NULL) {
        // This module has no IDT (i.e. it imports nothing).
        return;
    }
    while (idte->OriginalFirstThunk != 0x0) {
        if (_stricmp((PCHAR)R2VA(importmodule, idte->Name), exportmodulename) == 0) {
            // Found the IDT entry for the exporting module.
            break;
        }
        idte++;
    }
    if (idte->OriginalFirstThunk == 0x0) {
        // The importing module does not import anything from the exporting
        // module.
        return;
    }
    
    // Get the *real* address of the import. If we find this address in the IAT,
    // then we've found the entry that needs to be patched.
    exportmodule = GetModuleHandleA(exportmodulename);
    assert(exportmodule != NULL);
    import = GetProcAddress(exportmodule, importname);
    assert(import != NULL); // Perhaps the named export module does not actually export the named import?

    // Locate the import's IAT entry.
    iate = (IMAGE_THUNK_DATA*)R2VA(importmodule, idte->FirstThunk);
    while (iate->u1.Function != 0x0) {
        if (iate->u1.Function == (DWORD_PTR)import) {
            // Found the IAT entry. Overwrite the address stored in the IAT
            // entry with the address of the replacement. Note that the IAT
            // entry may be write-protected, so we must first ensure that it is
            // writable.
            VirtualProtect(&iate->u1.Function, sizeof(iate->u1.Function), PAGE_READWRITE, &protect);
            iate->u1.Function = (DWORD_PTR)replacement;
            VirtualProtect(&iate->u1.Function, sizeof(iate->u1.Function), protect, &protect);
            break;
        }
        iate++;
    }
}

// report - Sends a printf-style formatted message to the debugger for display.
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
VOID report (LPCTSTR format, ...)
{
    va_list args;
    TCHAR   message [MAXREPORTLENGTH + 1];

    va_start(args, format);
    _vsntprintf(message, MAXREPORTLENGTH, format, args);
    va_end(args);
    message[MAXREPORTLENGTH] = '\0';

    if (reportfile != NULL) {
        // Send the report to the previously specified file.
        fwrite(message, sizeof(TCHAR), _tcslen(message), reportfile);
    }
    if (reporttodebugger) {
        OutputDebugString(message);
        Sleep(10); // Workaround the Visual Studio 6 bug where debug strings are sometimes lost.
    }
}

// restoreimport - Restores the IAT entry for an import previously patched via
//   a call to "patchimport" to the original address of the import.
//
//  - importmodule (IN): Handle (base address) of the target module for which
//      calls or references to the import should be restored.
//
//  - exportmodulename (IN): ANSI string containing the name of the module that
//      exports the function or variable to be restored.
//
//  - importname (IN): ANSI string containing the name of the imported function
//      or variable to be restored.
//
//  - replacement (IN): Address of the function or variable which the import was
//      previously patched through to via a call to "patchimport".
//
//  Return Value:
//
//    None.
//   
VOID restoreimport (HMODULE importmodule, LPCSTR exportmodulename, LPCSTR importname, LPCVOID replacement)
{
    HMODULE                  exportmodule;
    IMAGE_THUNK_DATA        *iate;
    IMAGE_IMPORT_DESCRIPTOR *idte;
    FARPROC                  import;
    DWORD                    protect;
    IMAGE_SECTION_HEADER    *section;
    ULONG                    size;
            
    // Locate the importing module's Import Directory Table (IDT) entry for the
    // exporting module. The importing module actually can have several IATs --
    // one for each export module that it imports something from. The IDT entry
    // gives us the offset of the IAT for the module we are interested in.
    idte = (IMAGE_IMPORT_DESCRIPTOR*)ImageDirectoryEntryToDataEx((PVOID)importmodule, TRUE, IMAGE_DIRECTORY_ENTRY_IMPORT, &size, &section);
    if (idte == NULL) {
        // This module has no IDT (i.e. it imports nothing)..
        return;
    }
    while (idte->OriginalFirstThunk != 0x0) {
        if (_stricmp((PCHAR)R2VA(importmodule, idte->Name), exportmodulename) == 0) {
            // Found the IDT entry for the exporting module.
            break;
        }
        idte++;
    }
    if (idte->OriginalFirstThunk == 0x0) {
        // The importing module does not import anything from the exporting
        // module.
        return;
    }
    
    // Get the *real* address of the import.
    exportmodule = GetModuleHandleA(exportmodulename);
    assert(exportmodule != NULL);
    import = GetProcAddress(exportmodule, importname);
    assert(import != NULL); // Perhaps the named export module does not actually export the named import?

    // Locate the import's original IAT entry (it currently has the replacement
    // address in it).
    iate = (IMAGE_THUNK_DATA*)R2VA(importmodule, idte->FirstThunk);
    while (iate->u1.Function != 0x0) {
        if (iate->u1.Function == (DWORD_PTR)replacement) {
            // Found the IAT entry. Overwrite the address stored in the IAT
            // entry with the import's real address. Note that the IAT entry may
            // be write-protected, so we must first ensure that it is writable.
            VirtualProtect(&iate->u1.Function, sizeof(iate->u1.Function), PAGE_READWRITE, &protect);
            iate->u1.Function = (DWORD_PTR)import;
            VirtualProtect(&iate->u1.Function, sizeof(iate->u1.Function), protect, &protect);
            break;
        }
        iate++;
    }
}

// setreportfile - Sets a destination file to which all report messages should
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
VOID setreportfile (FILE *file, BOOL copydebugger)
{
    reportfile = file;
    reporttodebugger = copydebugger;
}

// strapp - Appends the specified source string to the specified destination
//   string. Allocates additional space so that the destination string "grows"
//   as new strings are appended to it. This function is fairly infrequently
//   used so efficiency is not a major concern.
//
//  - dest (IN/OUT): Address of the destination string. Receives the resulting
//      combined string after the append operation.
//
//  - source (IN): Source string to be appended to the destination string.
//
//  Return Value:
//
//    None.
//
VOID strapp (LPTSTR *dest, LPCTSTR source)
{
    size_t length;
    LPTSTR temp;

    temp = *dest;
    length = _tcslen(*dest) + _tcslen(source);
    *dest = new TCHAR [length + 1];
    _tcsncpy(*dest, temp, length);
    _tcsncat(*dest, source, length);
    delete [] temp;
}

// strtobool - Converts string values (e.g. "yes", "no", "on", "off") to boolean
//   values.
//
//  - s (IN): String value to convert.
//
//  Return Value:
//
//    Returns true if the string is recognized as a "true" string. Otherwise
//    returns false.
//
BOOL strtobool (LPCTSTR s) {
    TCHAR *end;

    if ((_tcsicmp(s, _T("true")) == 0) ||
        (_tcsicmp(s, _T("yes")) == 0) ||
        (_tcsicmp(s, _T("on")) == 0) ||
        (_tcstol(s, &end, 10) == 1)) {
        return true;
    }
    else {
        return false;
    }
}
