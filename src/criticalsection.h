#pragma once

#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <windows.h>

// you should consider CriticalSectionLocker whenever possible instead of
// directly working with CriticalSection class - it is safer
class CriticalSection
{
public:
	void Initialize()
	{
		m_critRegion.OwningThread = 0;
		__try {
			InitializeCriticalSection(&m_critRegion);
		} __except (GetExceptionCode() == STATUS_NO_MEMORY ? EXCEPTION_EXECUTE_HANDLER : EXCEPTION_CONTINUE_SEARCH) {
			assert(FALSE);
		}
	}
	void Delete()		{ DeleteCriticalSection(&m_critRegion); }

	// enter the section
	void Enter()
	{
		ULONG_PTR ownerThreadId = (ULONG_PTR)m_critRegion.OwningThread;
		UNREFERENCED_PARAMETER(ownerThreadId);
		EnterCriticalSection(&m_critRegion);
	}

	bool IsLocked()
	{
		return (m_critRegion.OwningThread != NULL);
	}

	bool IsLockedByCurrentThread()
	{
		if (m_critRegion.OwningThread == NULL)
			return false;
		HANDLE ownerThreadId = (HANDLE)GetCurrentThreadId();
		return m_critRegion.OwningThread == ownerThreadId;
	}

	// try enter the section
	bool TryEnter()		{ return (TryEnterCriticalSection(&m_critRegion) != 0); }

	// leave the critical section
	void Leave()		{ LeaveCriticalSection(&m_critRegion); }

private:
	CRITICAL_SECTION m_critRegion;
};

class CriticalSectionLocker
{
public:
	CriticalSectionLocker(CriticalSection& cs)
		: m_leave(false)
		, m_critSect(cs)
	{
		m_critSect.Enter();
	}

	~CriticalSectionLocker()
	{
		LeaveLock();
	}

	void Leave()
	{
		LeaveLock();
	}

private:
	void LeaveLock()
	{
		if (!m_leave)
		{
			m_critSect.Leave();
			m_leave = true;
		}
	}
	CriticalSectionLocker(); // not allowed
	CriticalSectionLocker( const CriticalSectionLocker & ); // not allowed
	CriticalSectionLocker & operator=( const CriticalSectionLocker & ); // not allowed
	bool m_leave;
	CriticalSection& m_critSect;
};
