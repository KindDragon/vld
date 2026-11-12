////////////////////////////////////////////////////////////////////////////////
//
//  Visual Leak Detector - Various Utility Definitions
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
#include <windows.h>
#include <intrin.h>

#ifdef _WIN64
#define ADDRESSFORMAT       L"0x%.16X"   // Format string for 64-bit addresses
#define ADDRESSCPPFORMAT    L"0x{:016X}" // Format string for 64-bit addresses
#else
#define ADDRESSFORMAT       L"0x%.8X"    // Format string for 32-bit addresses
#define ADDRESSCPPFORMAT    L"0x{:08X}"  // Format string for 32-bit addresses
#endif // _WIN64
#define BOM             0xFEFF     // Unicode byte-order mark.
#define MAXREPORTLENGTH 511        // Maximum length, in characters, of "report" messages.

// Architecture-specific definitions for x86, x64, and ARM64
#if defined(_M_IX86)
#define X86X64ARCHITECTURE IMAGE_FILE_MACHINE_I386
#define BPREG Ebp
#define IPREG Eip
#define SPREG Esp
#elif defined(_M_X64)
#define X86X64ARCHITECTURE IMAGE_FILE_MACHINE_AMD64
#define BPREG Rbp
#define IPREG Rip
#define SPREG Rsp
#elif defined(_M_ARM64)
#ifndef IMAGE_FILE_MACHINE_ARM64
#define IMAGE_FILE_MACHINE_ARM64 0xAA64  // ARM64 Little-Endian
#endif
#define X86X64ARCHITECTURE IMAGE_FILE_MACHINE_ARM64
// ARM64 uses Fp (x29), Sp, Pc instead of Rbp, Rsp, Rip
#define BPREG Fp
#define IPREG Pc
#define SPREG Sp
#endif // _M_IX86

struct context_t
{
    UINT_PTR fp;
    UINT_PTR func;
#if defined(_M_IX86)
    DWORD Ebp;
    DWORD Esp;
    DWORD Eip;
#elif defined(_M_X64)
    DWORD64 Rbp;
    DWORD64 Rsp;
    DWORD64 Rip;
#elif defined(_M_ARM64)
    DWORD64 Fp;  // Frame pointer (x29)
    DWORD64 Sp;  // Stack pointer
    DWORD64 Pc;  // Program counter
#endif // _M_IX86
};

// Abstraction macros for accessing context registers across architectures
#if defined(_M_IX86)
#define CONTEXT_BPREG(ctx) ((ctx).Ebp)
#define CONTEXT_SPREG(ctx) ((ctx).Esp)
#define CONTEXT_IPREG(ctx) ((ctx).Eip)
#elif defined(_M_X64)
#define CONTEXT_BPREG(ctx) ((ctx).Rbp)
#define CONTEXT_SPREG(ctx) ((ctx).Rsp)
#define CONTEXT_IPREG(ctx) ((ctx).Rip)
#elif defined(_M_ARM64)
#define CONTEXT_BPREG(ctx) ((ctx).Fp)
#define CONTEXT_SPREG(ctx) ((ctx).Sp)
#define CONTEXT_IPREG(ctx) ((ctx).Pc)
#endif

// Capture current context
#if defined(_M_IX86)
#define CAPTURE_CONTEXT()                                                       \
    context_t context_;                                                         \
    {CONTEXT _ctx;                                                              \
    RtlCaptureContext(&_ctx);                                                   \
    context_.Ebp = _ctx.Ebp; context_.Esp = _ctx.Esp; context_.Eip = _ctx.Eip;  \
    context_.fp = (UINT_PTR)_ReturnAddress();}
#define GET_RETURN_ADDRESS(context)  (context.fp)
#elif defined(_M_X64)
#define CAPTURE_CONTEXT()                                                       \
    context_t context_;                                                         \
    {CONTEXT _ctx;                                                              \
    RtlCaptureContext(&_ctx);                                                   \
    context_.Rbp = _ctx.Rbp; context_.Rsp = _ctx.Rsp; context_.Rip = _ctx.Rip;  \
    context_.fp = (UINT_PTR)_ReturnAddress();}
#define GET_RETURN_ADDRESS(context)  (context.fp)
#elif defined(_M_ARM64)
#define CAPTURE_CONTEXT()                                                       \
    context_t context_;                                                         \
    {CONTEXT _ctx;                                                              \
    RtlCaptureContext(&_ctx);                                                   \
    context_.Fp = _ctx.Fp; context_.Sp = _ctx.Sp; context_.Pc = _ctx.Pc;        \
    context_.fp = (UINT_PTR)_ReturnAddress();}
#define GET_RETURN_ADDRESS(context)  (context.fp)
#else
// If you want to retarget Visual Leak Detector to another processor
// architecture then you'll need to provide an architecture-specific macro to
// obtain the frame pointer (or other address) which can be used to obtain the
// return address and stack pointer of the calling frame.
#error "Visual Leak Detector is not supported on this architecture."
#endif // _M_IX86 || _M_X64

// Miscellaneous definitions
#define R2VA(moduleBase, rva)  (((PBYTE)moduleBase) + rva) // Relative Virtual Address to Virtual Address conversion.
#define BYTEFORMATBUFFERLENGTH 4
#define HEXDUMPLINELENGTH      58

// Reports can be encoded as either ASCII or Unicode (UTF-16).
enum encoding_e {
    ascii,
    unicode
};

// This structure allows us to build a table of APIs which should be patched
// through to replacement functions provided by VLD.
struct patchentry_t
{
    LPCSTR  importName;       // The name (or ordinal) of the imported API being patched.
    LPVOID* original;         // Pointer to the original function.
    LPCVOID replacement;      // Pointer to the function to which the imported API should be patched through to.
};

struct moduleentry_t
{
    LPCSTR          exportModuleName; // The name of the module exporting the patched API.
    BOOL            reportLeaks;      // Patch module to report leaks from it
    UINT_PTR        moduleBase;       // The base address of the exporting module (filled in at runtime when the modules are loaded).
    patchentry_t*   patchTable;
};

// Utility functions. See function definitions for details.
#if defined(_M_ARM64)
VOID Arm64CaptureKernelbaseHeapProcs (VOID);
// Returns the captured terminal kernelbase/ntdll body for a kernel32 heap export
// name (HeapCreate/HeapAlloc/HeapReAlloc/HeapFree/HeapDestroy), or NULL if not
// captured. Used by the heap hooks so VLD's own pass-through call goes to the real
// body instead of kernel32's patchable fast-forward dispatch thunk (which would recurse).
LPVOID Arm64LookupKernelbaseHeapProc (LPCSTR importname);
#endif
VOID DumpMemoryA (LPCVOID address, SIZE_T length);
VOID DumpMemoryW (LPCVOID address, SIZE_T length);
BOOL FindImport (HMODULE importmodule, HMODULE exportmodule, LPCSTR exportmodulename, LPCSTR importname);
BOOL FindImportByExportAddress (HMODULE importmodule, LPCSTR exportmodulename, LPCVOID exportAddress);
BOOL FindPatch (HMODULE importmodule, moduleentry_t* module);
VOID InsertReportDelay ();
BOOL IsModulePatched (HMODULE importmodule, moduleentry_t patchtable [], UINT tablesize);
BOOL PatchImport (HMODULE importmodule, moduleentry_t *module);
BOOL PatchModule (HMODULE importmodule, moduleentry_t patchtable [], UINT tablesize);
VOID Print (LPWSTR message);
VOID Report (LPCWSTR format, ...);
#ifndef NDEBUG
#define DbgPrint(x)     Print(x)
#define DbgReport(...)  Report(__VA_ARGS__)
#define DbgTrace(...)
#else
#define DbgPrint(x)
#define DbgReport(...)
#define DbgTrace(...)
#endif
VOID RestoreImport (HMODULE importmodule, moduleentry_t* module);
VOID RestoreModule (HMODULE importmodule, moduleentry_t patchtable [], UINT tablesize);
VOID SetReportEncoding (encoding_e encoding);
VOID SetReportFile (FILE *file, BOOL copydebugger, BOOL copytostdout);
LPWSTR AppendString (LPWSTR dest, LPCWSTR source);
BOOL StrToBool (LPCWSTR s);
void ConvertModulePathToAscii( LPCWSTR modulename, LPSTR * modulenamea );
DWORD CalculateCRC32(UINT_PTR p, UINT startValue = 0xD202EF8D);
// Formats a message string using the specified message and variable
// list of arguments.
void GetFormattedMessage(DWORD last_error);
HMODULE GetCallingModule(UINT_PTR pCaller);
#if defined(_M_X64)
// Names a program counter inside the ARM64EC code of an ARM64X module (an x64
// process running on ARM64) after the export whose x64 thunk enters that exact
// function. Returns FALSE when that does not apply.
BOOL GetArm64EcExportName(UINT_PTR programCounter, LPWSTR name, SIZE_T nameChars, DWORD64* displacement);
// TRUE when the host is ARM64. The first call resolves IsWow64Process2, which
// may need the loader; make it before VLD holds any of its own locks.
BOOL IsArm64Host();
#endif
DWORD FilterFunction(long);
BOOL LoadBoolOption(LPCWSTR optionname, LPCWSTR defaultvalue, LPCWSTR inipath);
UINT LoadIntOption(LPCWSTR optionname, UINT defaultvalue, LPCWSTR inipath);
VOID LoadStringOption(LPCWSTR optionname, LPWSTR outputbuffer, UINT buffersize, LPCWSTR inipath);