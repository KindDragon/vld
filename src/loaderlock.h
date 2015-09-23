#pragma once

#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <windows.h>
#include "ntapi.h"

//
// LdrLockLoaderLock Flags
//
#define LDR_LOCK_LOADER_LOCK_FLAG_DEFAULT           0x00000000
#define LDR_LOCK_LOADER_LOCK_FLAG_RAISE_ON_ERRORS   0x00000001
#define LDR_LOCK_LOADER_LOCK_FLAG_TRY_ONLY          0x00000002

//
// LdrUnlockLoaderLock Flags
//
#define LDR_UNLOCK_LOADER_LOCK_FLAG_DEFAULT         0x00000000
#define LDR_UNLOCK_LOADER_LOCK_FLAG_RAISE_ON_ERRORS 0x00000001

//
// LdrLockLoaderLock State
//
#define LDR_LOCK_LOADER_LOCK_STATE_INVALID                   0
#define LDR_LOCK_LOADER_LOCK_STATE_LOCK_ACQUIRED             1
#define LDR_LOCK_LOADER_LOCK_STATE_LOCK_NOT_ACQUIRED         2

class LoaderLock
{
public:
    LoaderLock() : m_uCookie(NULL), m_hThreadId(NULL) {
        ULONG uState = NULL;
        NTSTATUS ntStatus = LdrLockLoaderLock(LDR_LOCK_LOADER_LOCK_FLAG_DEFAULT, &uState, &m_uCookie);
        if (ntStatus == STATUS_SUCCESS) {
            m_hThreadId = GetCurrentThreadId();
        }
    }

    ~LoaderLock() {
        if (m_uCookie) {
            NTSTATUS ntStatus = LdrUnlockLoaderLock(LDR_UNLOCK_LOADER_LOCK_FLAG_DEFAULT, m_uCookie);
            if (ntStatus == STATUS_SUCCESS) {
                m_hThreadId = NULL;
                m_uCookie = NULL;
            }
        }
    }

private:
    // Disallow certain operations
    LoaderLock(const LoaderLock&) = delete;
    LoaderLock& operator=(const LoaderLock&) = delete;

private:
    DWORD m_hThreadId;
    ULONG_PTR m_uCookie;
};
