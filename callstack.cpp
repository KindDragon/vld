////////////////////////////////////////////////////////////////////////////////
//
//  Visual Leak Detector - CallStack Class Implementations
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
#define VLDBUILD
#include "callstack.h"  // This class' header.
#include "utility.h"    // Provides various utility functions.
#include "vldheap.h"    // Provides internal new and delete operators.
#include "vldint.h"     // Provides access to VLD internals.

// Imported global variables.
extern HANDLE             g_currentProcess;
extern HANDLE             g_currentThread;
extern CriticalSection    g_stackWalkLock;
extern CriticalSection    g_symbolLock;
extern VisualLeakDetector g_vld;

// Constructor - Initializes the CallStack with an initial size of zero and one
//   Chunk of capacity.
//
CallStack::CallStack ()
{
    m_capacity   = CALLSTACK_CHUNK_SIZE;
    m_size       = 0;
    m_status     = 0x0;
    m_store.next = NULL;
    m_topChunk   = &m_store;
    m_topIndex   = 0;
    m_resolved   = NULL;
    m_resolvedCapacity   = 0;
    m_resolvedLength = 0;
}

// Destructor - Frees all memory allocated to the CallStack.
//
CallStack::~CallStack ()
{
    CallStack::chunk_t *chunk = m_store.next;
    CallStack::chunk_t *temp;

    while (chunk) {
        temp = chunk;
        chunk = temp->next;
        delete temp;
    }

    if (m_resolved)
    {
        delete [] m_resolved;
    }

    m_resolved = NULL;
    m_resolvedCapacity = 0;
    m_resolvedLength = 0;
}

CallStack* CallStack::Create()
{
    CallStack* result = NULL;
    if (g_vld.GetOptions() & VLD_OPT_SAFE_STACK_WALK) {
        result = new SafeCallStack();
    }
    else {
        result = new FastCallStack();
    }
    return result;
}

// operator == - Equality operator. Compares the CallStack to another CallStack
//   for equality. Two CallStacks are equal if they are the same size and if
//   every frame in each is identical to the corresponding frame in the other.
//
//  other (IN) - Reference to the CallStack to compare the current CallStack
//    against for equality.
//
//  Return Value:
//
//    Returns true if the two CallStacks are equal. Otherwise returns false.
//
BOOL CallStack::operator == (const CallStack &other) const
{
    if (m_size != other.m_size) {
        // They can't be equal if the sizes are different.
        return FALSE;
    }

    // Walk the chunk list and within each chunk walk the frames array until we
    // either find a mismatch, or until we reach the end of the call stacks.
    const CallStack::chunk_t *prevChunk = NULL;
    const CallStack::chunk_t *chunk = &m_store;
    const CallStack::chunk_t *otherChunk = &other.m_store;
    while (prevChunk != m_topChunk) {
        UINT32 size = (chunk == m_topChunk) ? m_topIndex : CALLSTACK_CHUNK_SIZE;
        for (UINT32 index = 0; index < size; index++) {
            if (chunk->frames[index] != otherChunk->frames[index]) {
                // Found a mismatch. They are not equal.
                return FALSE;
            }
        }
        prevChunk = chunk;
        chunk = chunk->next;
        otherChunk = otherChunk->next;
    }

    // Reached the end of the call stacks. They are equal.
    return TRUE;
}

// operator [] - Random access operator. Retrieves the frame at the specified
//   index.
//
//   Note: We give up a bit of efficiency here, in favor of efficiency of push
//     operations. This is because walking of a CallStack is done infrequently
//     (only if a leak is found), whereas pushing is done very frequently (for
//     each frame in the program's call stack when the program allocates some
//     memory).
//
//  - index (IN): Specifies the index of the frame to retrieve.
//
//  Return Value:
//
//    Returns the program counter for the frame at the specified index. If the
//    specified index is out of range for the CallStack, the return value is
//    undefined.
//
UINT_PTR CallStack::operator [] (UINT32 index) const
{
    UINT32                    chunknumber = index / CALLSTACK_CHUNK_SIZE;
    const CallStack::chunk_t *chunk = &m_store;

    for (UINT32 count = 0; count < chunknumber; count++) {
        chunk = chunk->next;
    }

    return chunk->frames[index % CALLSTACK_CHUNK_SIZE];
}

// clear - Resets the CallStack, returning it to a state where no frames have
//   been pushed onto it, readying it for reuse.
//
//   Note: Calling this function does not release any memory allocated to the
//     CallStack. We give up a bit of memory-usage efficiency here in favor of
//     performance of push operations.
//
//  Return Value:
//
//    None.
//
VOID CallStack::clear ()
{
    m_size     = 0;
    m_topChunk = &m_store;
    m_topIndex = 0;
    if (m_resolved)
    {
        delete [] m_resolved;
        m_resolved = NULL;
    }
    m_resolvedCapacity = 0;
    m_resolvedLength = 0;
}


// dump - Dumps a nicely formatted rendition of the CallStack, including
//   symbolic information (function names and line numbers) if available.
//
//   Note: The symbol handler must be initialized prior to calling this
//     function.
//
//  - showinternalframes (IN): If true, then all frames in the CallStack will be
//      dumped. Otherwise, frames internal to the heap will not be dumped.
//
//  Return Value:
//
//    None.
//
void CallStack::dump(BOOL showInternalFrames, UINT start_frame) const
{
    // The stack was dumped already
    if (m_resolved)
    {
        dumpResolved();
        return;
    }

    if (m_status & CALLSTACK_STATUS_INCOMPLETE) {
        // This call stack appears to be incomplete. Using StackWalk64 may be
        // more reliable.
        Report(L"    HINT: The following call stack may be incomplete. Setting \"StackWalkMethod\"\n"
            L"      in the vld.ini file to \"safe\" instead of \"fast\" may result in a more\n"
            L"      complete stack trace.\n");
    }

    IMAGEHLP_LINE64  sourceInfo = { 0 };
    sourceInfo.SizeOfStruct = sizeof(IMAGEHLP_LINE64);

    BYTE symbolBuffer [sizeof(SYMBOL_INFO) + MAX_SYMBOL_NAME_SIZE] = { 0 };

    WCHAR lowerCaseName [MAX_PATH];
    WCHAR callingModuleName [MAX_PATH];

    const size_t max_size = MAXREPORTLENGTH + 1;

    // Use static here to increase performance, and avoid heap allocs. Hopefully this won't
    // prove to be an issue in thread safety. If it does, it will have to be simply non-static.
    static WCHAR stack_line[MAXREPORTLENGTH + 1] = L"";
    bool isPrevFrameInternal = false;

    // Iterate through each frame in the call stack.
    for (UINT32 frame = start_frame; frame < m_size; frame++)
    {
        // Try to get the source file and line number associated with
        // this program counter address.
        SIZE_T programCounter = (*this)[frame];
        g_symbolLock.Enter();
        BOOL             foundline = FALSE;
        DWORD            displacement = 0;
        DbgTrace(L"dbghelp32.dll %i: SymGetLineFromAddrW64\n", GetCurrentThreadId());
        foundline = SymGetLineFromAddrW64(g_currentProcess, programCounter, &displacement, &sourceInfo);
        bool isFrameInternal = false;
        if (foundline && !showInternalFrames) {
            wcscpy_s(lowerCaseName, sourceInfo.FileName);
            _wcslwr_s(lowerCaseName, wcslen(lowerCaseName) + 1);
            if (isInternalModule(lowerCaseName))
            {
                isFrameInternal = true;
                // Don't show frames in files internal to the heap.
                //g_symbolLock.Leave();
            }
        }

        // Initialize structures passed to the symbol handler.
        SYMBOL_INFO* functionInfo = (SYMBOL_INFO*)&symbolBuffer;
        functionInfo->SizeOfStruct = sizeof(SYMBOL_INFO);
        functionInfo->MaxNameLen = MAX_SYMBOL_NAME_LENGTH;

        // Try to get the name of the function containing this program
        // counter address.
        DWORD64          displacement64 = 0;
        LPWSTR           functionName;
        DbgTrace(L"dbghelp32.dll %i: SymFromAddrW\n", GetCurrentThreadId());
        if (SymFromAddrW(g_currentProcess, programCounter, &displacement64, functionInfo)) {
            functionName = functionInfo->Name;
        }
        else {
            // GetFormattedMessage( GetLastError() );
            functionName = L"(Function name unavailable)";
            displacement64 = 0;
        }
        g_symbolLock.Leave();

        HMODULE hCallingModule = GetCallingModule(programCounter);
        LPWSTR moduleName = L"(Module name unavailable)";
        if (hCallingModule && 
            GetModuleFileName(hCallingModule, callingModuleName, _countof(callingModuleName)) > 0)
        {
            moduleName = wcsrchr(callingModuleName, L'\\');
            if (moduleName == NULL)
                moduleName = wcsrchr(callingModuleName, L'/');
            if (moduleName != NULL)
                moduleName++;
            else
                moduleName = callingModuleName;
        }

        if (!isFrameInternal && isPrevFrameInternal)
            Print(stack_line);
        isPrevFrameInternal = isFrameInternal;

        int NumChars = -1;
        // Display the current stack frame's information.
        if (foundline) {
            if (displacement == 0)
                NumChars = _snwprintf_s(stack_line, max_size, _TRUNCATE, L"    %s (%d): %s!%s\n", 
                sourceInfo.FileName, sourceInfo.LineNumber, moduleName, functionName);
            else
                NumChars = _snwprintf_s(stack_line, max_size, _TRUNCATE, L"    %s (%d): %s!%s + 0x%X bytes\n", 
                sourceInfo.FileName, sourceInfo.LineNumber, moduleName, functionName, displacement);
        }
        else {
            if (displacement64 == 0)
                NumChars = _snwprintf_s(stack_line, max_size, _TRUNCATE, L"    " ADDRESSFORMAT L" (File and line number not available): %s!%s\n", 
                programCounter, moduleName, functionName);
            else
                NumChars = _snwprintf_s(stack_line, max_size, _TRUNCATE, L"    " ADDRESSFORMAT L" (File and line number not available): %s!%s + 0x%X bytes\n", 
                programCounter, moduleName, functionName, (DWORD)displacement64);	
        }

        if (!isFrameInternal)
            Print(stack_line);
    }
}

// Resolve - Creates a nicely formatted rendition of the CallStack, including
//   symbolic information (function names and line numbers) if available. and 
//   saves it for later retrieval. This is almost identical to Callstack::dump above.
//
//   Note: The symbol handler must be initialized prior to calling this
//     function.
//
//  - showInternalFrames (IN): If true, then all frames in the CallStack will be
//      dumped. Otherwise, frames internal to the heap will not be dumped.
//
//  Return Value:
//
//    None.
//
void CallStack::resolve(BOOL showInternalFrames)
{
    if (m_resolved)
    {
        // already resolved, no need to do it again
        // resolving twice may report an incorrect module for the stack frames
        // if the memory was leaked in a dynamic library that was already unloaded.
        return;
    }
    if (m_status & CALLSTACK_STATUS_INCOMPLETE) {
        // This call stack appears to be incomplete. Using StackWalk64 may be
        // more reliable.
        Report(L"    HINT: The following call stack may be incomplete. Setting \"StackWalkMethod\"\n"
            L"      in the vld.ini file to \"safe\" instead of \"fast\" may result in a more\n"
            L"      complete stack trace.\n");
    }

    IMAGEHLP_LINE64  sourceInfo = { 0 };
    sourceInfo.SizeOfStruct = sizeof(IMAGEHLP_LINE64);

    BYTE symbolBuffer [sizeof(SYMBOL_INFO) + MAX_SYMBOL_NAME_SIZE] = { 0 };
    
    WCHAR callingModuleName [MAX_PATH] = L"";
    WCHAR lowerCaseName [MAX_PATH];

    const size_t max_line_length = MAXREPORTLENGTH + 1;
    m_resolvedCapacity = m_size * max_line_length;
    m_resolved = new WCHAR[m_resolvedCapacity];
    const size_t allocedBytes = m_resolvedCapacity * sizeof(WCHAR);
    ZeroMemory(m_resolved, allocedBytes);
    
    // Iterate through each frame in the call stack.
    for (UINT32 frame = 0; frame < m_size; frame++)
    {
        // Try to get the source file and line number associated with
        // this program counter address.
        SIZE_T programCounter = (*this)[frame];
        g_symbolLock.Enter();
        BOOL             foundline = FALSE;
        DWORD            displacement = 0;

        // It turns out that calls to SymGetLineFromAddrW64 may free the very memory we are scrutinizing here
        // in this method. If this is the case, m_Resolved will be null after SymGetLineFromAddrW64 returns. 
        // When that happens there is nothing we can do except crash.
        DbgTrace(L"dbghelp32.dll %i: SymGetLineFromAddrW64\n", GetCurrentThreadId());
        foundline = SymGetLineFromAddrW64(g_currentProcess, programCounter, &displacement, &sourceInfo);
        assert(m_resolved != NULL);

        if (foundline && !showInternalFrames) {
            wcscpy_s(lowerCaseName, sourceInfo.FileName);
            _wcslwr_s(lowerCaseName, wcslen(lowerCaseName) + 1);
            if (isInternalModule(lowerCaseName)) {
                // Don't show frames in files internal to the heap.
                g_symbolLock.Leave();
                continue;
            }
        }

        // Initialize structures passed to the symbol handler.
        SYMBOL_INFO* functionInfo = (SYMBOL_INFO*)&symbolBuffer;
        functionInfo->SizeOfStruct = sizeof(SYMBOL_INFO);
        functionInfo->MaxNameLen = MAX_SYMBOL_NAME_LENGTH;

        // Try to get the name of the function containing this program
        // counter address.
        DWORD64          displacement64 = 0;
        LPWSTR           functionName;
        DbgTrace(L"dbghelp32.dll %i: SymFromAddrW\n", GetCurrentThreadId());
        if (SymFromAddrW(g_currentProcess, programCounter, &displacement64, functionInfo)) {
            functionName = functionInfo->Name;
        }
        else {
            // GetFormattedMessage( GetLastError() );
            functionName = L"(Function name unavailable)";
            displacement64 = 0;
        }
        g_symbolLock.Leave();

        HMODULE hCallingModule = GetCallingModule(programCounter);
        LPWSTR moduleName = L"(Module name unavailable)";
        if (hCallingModule && 
            GetModuleFileName(hCallingModule, callingModuleName, _countof(callingModuleName)) > 0)
        {
            moduleName = wcsrchr(callingModuleName, L'\\');
            if (moduleName == NULL)
                moduleName = wcsrchr(callingModuleName, L'/');
            if (moduleName != NULL)
                moduleName++;
            else
                moduleName = callingModuleName;
        }

        // Use static here to increase performance, and avoid heap allocs. Hopefully this won't
        // prove to be an issue in thread safety. If it does, it will have to be simply non-static.
        static WCHAR stack_line[max_line_length] = L"";
        int NumChars = -1;
        // Display the current stack frame's information.
        if (foundline) {
            // Just truncate anything that is too long.
            if (displacement == 0)
                NumChars = _snwprintf_s(stack_line, max_line_length, _TRUNCATE, L"    %s (%d): %s!%s\n", 
                sourceInfo.FileName, sourceInfo.LineNumber, moduleName, functionName);
            else
                NumChars = _snwprintf_s(stack_line, max_line_length, _TRUNCATE, L"    %s (%d): %s!%s + 0x%X bytes\n", 
                sourceInfo.FileName, sourceInfo.LineNumber, moduleName, functionName, displacement);
        }
        else {
            if (displacement64 == 0)
                NumChars = _snwprintf_s(stack_line, max_line_length, _TRUNCATE, L"    " ADDRESSFORMAT L" (File and line number not available): %s!%s\n", 
                programCounter, moduleName, functionName);
            else
                NumChars = _snwprintf_s(stack_line, max_line_length, _TRUNCATE, L"    " ADDRESSFORMAT L" (File and line number not available): %s!%s + 0x%X bytes\n", 
                programCounter, moduleName, functionName, (DWORD)displacement64);
        }

        if (NumChars >= 0) {
            assert(m_resolved != NULL);
            m_resolvedLength += NumChars;
            wcsncat_s(m_resolved, m_resolvedCapacity, stack_line, NumChars);
        }
    } // end for loop
}

// DumpResolve
void CallStack::dumpResolved() const
{
    if (m_resolved)
        Print(m_resolved);
}



// getHashValue - Generate callstack hash value.
//
//  Return Value:
//
//    None.
//
DWORD CallStack::getHashValue () const
{
    DWORD       hashcode = 0xD202EF8D;

    // Iterate through each frame in the call stack.
    for (UINT32 frame = 0; frame < m_size; frame++) {
        UINT_PTR programcounter = (*this)[frame];
        hashcode = CalculateCRC32(programcounter, hashcode);
    }
    return hashcode;
}

// push_back - Pushes a frame's program counter onto the CallStack. Pushes are
//   always appended to the back of the chunk list (aka the "top" chunk).
//
//   Note: This function will allocate additional memory as necessary to make
//     room for new program counter addresses.
//
//  - programcounter (IN): The program counter address of the frame to be pushed
//      onto the CallStack.
//
//  Return Value:
//
//    None.
//
VOID CallStack::push_back (const UINT_PTR programcounter)
{
    if (m_size == m_capacity) {
        // At current capacity. Allocate additional storage.
        CallStack::chunk_t *chunk = new CallStack::chunk_t;
        chunk->next = NULL;
        m_topChunk->next = chunk;
        m_topChunk = chunk;
        m_topIndex = 0;
        m_capacity += CALLSTACK_CHUNK_SIZE;
    }
    else if (m_topIndex >= CALLSTACK_CHUNK_SIZE) {
        // There is more capacity, but not in this chunk. Go to the next chunk.
        // Note that this only happens if this CallStack has previously been
        // cleared (clearing resets the data, but doesn't give up any allocated
        // space).
        m_topChunk = m_topChunk->next;
        m_topIndex = 0;
    }

    m_topChunk->frames[m_topIndex++] = programcounter;
    m_size++;
}

bool CallStack::isInternalModule( const PWSTR filename ) const
{
    return wcsstr(filename, L"\\crt\\src\\afxmem.cpp") ||
        wcsstr(filename, L"\\crt\\src\\dbgheap.c") ||
        wcsstr(filename, L"\\crt\\src\\malloc.c") ||
        wcsstr(filename, L"\\crt\\src\\dbgmalloc.c") ||
        wcsstr(filename, L"\\crt\\src\\new.cpp") ||
        wcsstr(filename, L"\\crt\\src\\newaop.cpp") ||
        wcsstr(filename, L"\\crt\\src\\dbgnew.cpp") ||
        wcsstr(filename, L"\\crt\\src\\dbgcalloc.c") ||
        wcsstr(filename, L"\\crt\\src\\realloc.c") ||
        wcsstr(filename, L"\\crt\\src\\dbgrealloc.c") ||
        wcsstr(filename, L"\\crt\\src\\dbgdel.cp") ||
        wcsstr(filename, L"\\crt\\src\\free.c") ||
        wcsstr(filename, L"\\crt\\src\\strdup.c") ||
        wcsstr(filename, L"\\crt\\src\\wcsdup.c") ||
        wcsstr(filename, L"\\vc\\include\\xmemory0");
}

// getStackTrace - Traces the stack as far back as possible, or until 'maxdepth'
//   frames have been traced. Populates the CallStack with one entry for each
//   stack frame traced.
//
//   Note: This function uses a very efficient method to walk the stack from
//     frame to frame, so it is quite fast. However, unconventional stack frames
//     (such as those created when frame pointer omission optimization is used)
//     will not be successfully walked by this function and will cause the
//     stack trace to terminate prematurely.
//
//  - maxdepth (IN): Maximum number of frames to trace back.
//
//  - framepointer (IN): Frame (base) pointer at which to begin the stack trace.
//      If NULL, then the stack trace will begin at this function.
//
//  Return Value:
//
//    None.
//
VOID FastCallStack::getStackTrace (UINT32 maxdepth, const context_t& context)
{
    UINT32  count = 0;
    UINT_PTR function = context.func;
    if (function != NULL)
    {
        count++;
        push_back(function);
    }
    UINT_PTR* framePointer = context.fp;

#if defined(_M_IX86)
    while (count < maxdepth) {
        if (*framePointer < (UINT_PTR)framePointer) {
            if (*framePointer == NULL) {
                // Looks like we reached the end of the stack.
                break;
            }
            else {
                // Invalid frame pointer. Frame pointer addresses should always
                // increase as we move up the stack.
                m_status |= CALLSTACK_STATUS_INCOMPLETE;
                break;
            }
        }
        if (*framePointer & (sizeof(UINT_PTR*) - 1)) {
            // Invalid frame pointer. Frame pointer addresses should always
            // be aligned to the size of a pointer. This probably means that
            // we've encountered a frame that was created by a module built with
            // frame pointer omission (FPO) optimization turned on.
            m_status |= CALLSTACK_STATUS_INCOMPLETE;
            break;
        }
        if (IsBadReadPtr((UINT*)*framePointer, sizeof(UINT_PTR*))) {
            // Bogus frame pointer. Again, this probably means that we've
            // encountered a frame built with FPO optimization.
            m_status |= CALLSTACK_STATUS_INCOMPLETE;
            break;
        }
        count++;
        push_back(*(framePointer + 1));
        framePointer = (UINT_PTR*)*framePointer;
    }
#elif defined(_M_X64)
    UINT32 maxframes = min(62, maxdepth + 10);
    static USHORT (WINAPI *s_pfnCaptureStackBackTrace)(ULONG FramesToSkip, ULONG FramesToCapture, PVOID* BackTrace, PULONG BackTraceHash) = 0;  
    if (s_pfnCaptureStackBackTrace == 0)  
    {  
        const HMODULE hNtDll = GetModuleHandleW(L"ntdll.dll");  
        reinterpret_cast<void*&>(s_pfnCaptureStackBackTrace)
            = ::GetProcAddress(hNtDll, "RtlCaptureStackBackTrace");
        if (s_pfnCaptureStackBackTrace == 0)  
            return;
    }
    UINT_PTR* myFrames = new UINT_PTR[maxframes];
    ZeroMemory(myFrames, sizeof(UINT_PTR) * maxframes);
    s_pfnCaptureStackBackTrace(0, maxframes, (PVOID*)myFrames, NULL);
    UINT32  startIndex = 0;
    while (count < maxframes) {
        if (myFrames[count] == 0)
            break;
        if (myFrames[count] == *(framePointer + 1))
            startIndex = count;
        count++;
    }
    count = startIndex;
    while (count < maxframes) {
        if (myFrames[count] == 0)
            break;
        push_back(myFrames[count]);
        count++;
    }
    delete [] myFrames;
#endif
}

// getStackTrace - Traces the stack as far back as possible, or until 'maxdepth'
//   frames have been traced. Populates the CallStack with one entry for each
//   stack frame traced.
//
//   Note: This function uses a documented Windows API to walk the stack. This
//     API is supposed to be the most reliable way to walk the stack. It claims
//     to be able to walk stack frames that do not follow the conventional stack
//     frame layout. However, this robustness comes at a cost: it is *extremely*
//     slow compared to walking frames by following frame (base) pointers.
//
//  - maxdepth (IN): Maximum number of frames to trace back.
//
//  - framepointer (IN): Frame (base) pointer at which to begin the stack trace.
//      If NULL, then the stack trace will begin at this function.
//
//  Return Value:
//
//    None.
//
VOID SafeCallStack::getStackTrace (UINT32 maxdepth, const context_t& context)
{
    UINT32 count = 0;
    UINT_PTR function = context.func;
    if (function != NULL)
    {
        count++;
        push_back(function);
    }

    UINT_PTR* framePointer = context.fp;
    DWORD   architecture   = X86X64ARCHITECTURE;
    CONTEXT currentContext;
    memset(&currentContext, 0, sizeof(currentContext));

    // Get the required values for initialization of the STACKFRAME64 structure
    // to be passed to StackWalk64(). Required fields are AddrPC and AddrFrame.
#if defined(_M_IX86)
    UINT_PTR programcounter = *(framePointer + 1);
    UINT_PTR stackpointer   = (*framePointer) - maxdepth * 10 * sizeof(void*);  // An approximation.
    currentContext.SPREG  = stackpointer;
    currentContext.BPREG  = (DWORD64)framePointer;
    currentContext.IPREG  = programcounter;
#elif defined(_M_X64)
    currentContext.SPREG  = context.Rsp;
    currentContext.BPREG  = (DWORD64)framePointer;
    currentContext.IPREG  = context.Rip;
#else
    // If you want to retarget Visual Leak Detector to another processor
    // architecture then you'll need to provide architecture-specific code to
    // obtain the program counter and stack pointer from the given frame pointer.
#error "Visual Leak Detector is not supported on this architecture."
#endif // _M_IX86 || _M_X64

    // Initialize the STACKFRAME64 structure.
    STACKFRAME64 frame;
    memset(&frame, 0x0, sizeof(frame));
    frame.AddrPC.Offset       = currentContext.IPREG;
    frame.AddrPC.Mode         = AddrModeFlat;
    frame.AddrStack.Offset    = currentContext.SPREG;
    frame.AddrStack.Mode      = AddrModeFlat;
    frame.AddrFrame.Offset    = currentContext.BPREG;
    frame.AddrFrame.Mode      = AddrModeFlat;
    frame.Virtual             = TRUE;

    // Walk the stack.
    CriticalSectionLocker cs(g_stackWalkLock);
	g_symbolLock.Enter();
	while (count < maxdepth) {
        count++;
        DbgTrace(L"dbghelp32.dll %i: StackWalk64\n", GetCurrentThreadId());
        if (!StackWalk64(architecture, g_currentProcess, g_currentThread, &frame, &currentContext, NULL,
            SymFunctionTableAccess64, SymGetModuleBase64, NULL)) {
                // Couldn't trace back through any more frames.
                break;
        }
        if (frame.AddrFrame.Offset == 0) {
            // End of stack.
            break;
        }

        // Push this frame's program counter onto the CallStack.
        push_back((UINT_PTR)frame.AddrPC.Offset);
    }
	g_symbolLock.Leave();
}
