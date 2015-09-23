////////////////////////////////////////////////////////////////////////////////
//
//  Visual Leak Detector - CallStack Class Definitions
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

#include <windows.h>
#include "utility.h"

#define CALLSTACK_CHUNK_SIZE    32	// Number of frame slots in each CallStack chunk.
#define MAX_SYMBOL_NAME_LENGTH  256 // Maximum symbol name length that we will allow. Longer names will be truncated.
#define MAX_SYMBOL_NAME_SIZE    ((MAX_SYMBOL_NAME_LENGTH * sizeof(WCHAR)) - 1)

////////////////////////////////////////////////////////////////////////////////
//
//  The CallStack Class
//
//    CallStack objects can be used for obtaining, storing, and displaying the
//    call stack at a given point during program execution.
//
//    The primary data structure used by the CallStack is similar in concept to
//    a STL vector, but is specifically tailored for use by VLD, making it more
//    efficient than a standard STL vector.
//
//    Inside the CallStack are a number of "chunks" which are arranged in a
//    linked list. Each chunk contains an array of frames (each frame is
//    represented by a program counter address). If we run out of space when
//    pushing new frames onto an existing chunk in the CallStack chunk list,
//    then a new chunk is allocated and appended to the end of the list. In this
//    way, the CallStack can grow dynamically as needed. New frames are always
//    pushed onto the chunk at the end of the list known as the "top" chunk.
//
//    IMPORTANT NOTE: This class as originally written makes two fatal assumptions:
//    First: That the application will never load modules (call LoadLibrary) during the
//           lifetime of the app.
//    Second: That modules will never get unloaded (call to FreeLibrary)
//            during the lifetime of the app.
//    The result of this assumption is that
//    memory allocations whose call stacks goes through dynamically loaded modules
//    will be incomplete. This is manifested by stack frames that cannot be resolved
//    when the stack is 'dumped' because the binaries have been unloaded from the
//    process.
//    To rectify this situation, it is up to the caller to resolve or format the call stacks
//    into human readable form, BEFORE the callers process unloads any modules. That is
//    done by calling VisualLeakDetector::ResolveCallstacks, which can be called from
//    external code by the exported VLDResolveCallstacks function.
//    When this happens, the call stacks are formatted, and then cached for later dumping.
//    This has performance penalties, as the current implementation saves all info to heap memory,
//    and it is wasteful, as some of the 'converted' memory is not a true leak, but will get
//    properly de-allocated at a later time. However there is no other way to work around the
//    fact that the call stacks can only get formatted when the binary is loaded in the process.
//
class CallStack
{
public:
	CallStack ();
	virtual ~CallStack ();
	static CallStack* Create();
	// Public APIs - see each function definition for details.
	VOID clear ();
	// Prints the call stack to one of either / or the debug output window and or
	// a log file.
	VOID dump (BOOL showinternalframes, UINT start_frame = 0) const;
    // Formats the stack frame into a human readable format, and saves it for later retrieval.
	int resolve(BOOL showinternalframes);
    virtual DWORD getHashValue() const = 0;
	virtual VOID getStackTrace (UINT32 maxdepth, const context_t& context) = 0;

	BOOL operator == (const CallStack &other) const;
	UINT_PTR operator [] (UINT32 index) const;
	VOID push_back (const UINT_PTR programcounter);

protected:
	// Protected data.
	UINT32 m_status;                    // Status flags:
#define CALLSTACK_STATUS_INCOMPLETE 0x1 //   If set, the stack trace stored in this CallStack appears to be incomplete.

	// The chunk list is made of a linked list of Chunks.
	struct chunk_t {
		chunk_t*    next;					    // Pointer to the next chunk in the chunk list.
		UINT_PTR    frames[CALLSTACK_CHUNK_SIZE]; // Pushed frames (program counter addresses) are stored in this array.
	};

	// Private data.
	UINT32              m_capacity; // Current capacity limit (in frames)
	UINT32              m_size;     // Current size (in frames)
	CallStack::chunk_t  m_store;    // Pointer to the underlying data store (i.e. head of the chunk list)
	CallStack::chunk_t* m_topChunk; // Pointer to the chunk at the top of the stack
	UINT32              m_topIndex; // Index, within the top chunk, of the top of the stack

	// The string that contains the stack converted into a human readable format.
	// This is always NULL if the callstack has not been 'converted'.
	WCHAR*              m_resolved;
	int                 m_resolvedCapacity;
	int                 m_resolvedLength;
	// Prints out the strings in m_Resolved when the time comes to report the callstack in
	// human readable form. Currently this is only called by the dump method.
	void dumpResolved() const;
	bool isInternalModule( const PWSTR filename ) const;
    LPCWSTR getFunctionName(SIZE_T programCounter, DWORD64& displacement64,
        SYMBOL_INFO* functionInfo) const;
    DWORD resolveFunction(SIZE_T programCounter, IMAGEHLP_LINEW64* sourceInfo, DWORD displacement,
        LPCWSTR functionName, LPWSTR stack_line, DWORD stackLineSize) const;

private:
    // Don't allow this!!
    CallStack(const CallStack &other);
    // Don't allow this!!
    CallStack& operator = (const CallStack &other);
};


////////////////////////////////////////////////////////////////////////////////
//
//  The FastCallStack Class
//
//    This class is a specialization of the CallStack class which provides a
//    very fast stack tracing function.
//
class FastCallStack : public CallStack
{
public:
    FastCallStack()
        : m_hashValue(0)
    {
    }
    virtual VOID getStackTrace (UINT32 maxdepth, const context_t& context);
    virtual DWORD getHashValue() const
    {
        return m_hashValue;
    }

private:
    UINT32 m_hashValue;
};

////////////////////////////////////////////////////////////////////////////////
//
//  The SafeCallStack Class
//
//    This class is a specialization of the CallStack class which provides a
//    more robust, but quite slow, stack tracing function.
//
class SafeCallStack : public CallStack
{
public:
    virtual VOID getStackTrace (UINT32 maxdepth, const context_t& context);
    virtual DWORD getHashValue() const;
};
