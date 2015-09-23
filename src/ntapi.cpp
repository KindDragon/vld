////////////////////////////////////////////////////////////////////////////////
//
//  Visual Leak Detector - Global NT API Function Pointers
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
#include "ntapi.h"

// Global function pointers for explicit dynamic linking with NT APIs that can't
// be load-time linked (there is no import library available for these).
LdrLoadDll_t        LdrLoadDll;
LdrLoadDllWin8_t    LdrLoadDllWin8;
RtlAllocateHeap_t   RtlAllocateHeap;
RtlFreeHeap_t       RtlFreeHeap;
RtlReAllocateHeap_t RtlReAllocateHeap;

LdrGetDllHandle_t   LdrGetDllHandle;
LdrGetProcedureAddress_t LdrGetProcedureAddress;
LdrUnloadDll_t      LdrUnloadDll;
LdrLockLoaderLock_t LdrLockLoaderLock;
LdrUnlockLoaderLock_t LdrUnlockLoaderLock;