#include <phnt_windows.h>
#include <phnt.h>
#define PHNT_VERSION PHNT_THRESHOLD // Windows 10
#include "WinApi.h"
#include "TlsFunction.h"
#include "WinFunction.h"

// https://docs.microsoft.com/en-us/windows/win32/procthread/thread-local-storage
// https://doxygen.reactos.org/d0/d85/dll_2win32_2kernel32_2client_2thread_8c.html#a57228c083124de2c7d14b1ee7a28d78a

DWORD TlsAlloc()
{
    WinApi* winApi = WinApi::Get();

    PTEB teb = winApi->GetCurrentTeb();
    PPEB peb = teb->ProcessEnvironmentBlock;

    // Lock the peb because multiple thread can access this data
    winApi->pRtlAcquirePebLock();

    // search for an entry in the simple TlsBitmap (only 64 available)
    ULONG index = winApi->pRtlFindClearBitsAndSet((PRTL_BITMAP)peb->TlsBitmap, 1, 0);

    for (;; index = winApi->pRtlFindClearBitsAndSet((PRTL_BITMAP)peb->TlsBitmap, 1, 0))
    {
        // return the index if we found one in the simple TlsBitmap
        if (index != TLS_OUT_OF_INDEXES)
        {
            winApi->pRtlReleasePebLock();
            teb->TlsSlots[index] = 0;
            return index;
        }

        // check if the expansion is already used
        if (teb->TlsExpansionSlots)
        {
            // search a index in the TlsExpansionBitmap
            ULONG expIndex = winApi->pRtlFindClearBitsAndSet((PRTL_BITMAP)peb->TlsExpansionBitmap, 1, 0);
            winApi->pRtlReleasePebLock();
            if (expIndex != TLS_OUT_OF_INDEXES)
            {
                teb->TlsExpansionSlots[expIndex] = 0;
                return expIndex + TLS_MINIMUM_AVAILABLE;
            }
            else
            {
                // no entry in simple and extension is found (limit 1088)
                SetLastError(STATUS_NO_MEMORY);
                return TLS_OUT_OF_INDEXES;
            }
        }

        winApi->pRtlReleasePebLock();

        // unknown globalVariable but should be 0
        ULONG KernelBaseGlobalData = 0;

        // allocate space for the expansion
        PVOID heapPtr = winApi->pRtlAllocateHeap(peb->ProcessHeap, HEAP_ZERO_MEMORY | KernelBaseGlobalData, 8 * TLS_EXPANSION_SLOTS);
        if (heapPtr == nullptr)
        {
            SetLastError(STATUS_NO_MEMORY);
            return TLS_OUT_OF_INDEXES;
        }
        teb->TlsExpansionSlots = (PVOID*)heapPtr;

        winApi->pRtlAcquirePebLock();
    }
}


BOOL WINAPI TlsFree(DWORD dwTlsIndex)
{
    WinApi* winApi = WinApi::Get();

    PTEB teb = winApi->GetCurrentTeb();
    PPEB peb = teb->ProcessEnvironmentBlock;

    RTL_BITMAP* tlsBitmap;

    DWORD dwTlsIndex2 = dwTlsIndex;
    if (dwTlsIndex >= TLS_MINIMUM_AVAILABLE)
    {
        dwTlsIndex2 = dwTlsIndex - TLS_MINIMUM_AVAILABLE;
        if (dwTlsIndex - TLS_MINIMUM_AVAILABLE >= TLS_EXPANSION_SLOTS)
        {
            SetLastError(STATUS_INVALID_PARAMETER);
            return FALSE;
        }

        tlsBitmap = (RTL_BITMAP*)peb->TlsExpansionBitmap;
    }
    else
    {
        tlsBitmap = (RTL_BITMAP*)peb->TlsBitmap;
    }

    winApi->pRtlAcquirePebLock();
    BOOLEAN bStatus = winApi->pRtlAreBitsSet(tlsBitmap, dwTlsIndex2, 1);
    if (bStatus == TRUE)
    {
        NTSTATUS ntStatus = winApi->pNtSetInformationThread(ZwCurrentThread(), ThreadZeroTlsCell, &dwTlsIndex2, sizeof(dwTlsIndex2));
        if (ntStatus == STATUS_SUCCESS)
        {
            winApi->pRtlClearBits(tlsBitmap, dwTlsIndex2, 1);
            winApi->pRtlReleasePebLock();
            return TRUE;
        }
    }

    winApi->pRtlReleasePebLock();
    SetLastError(STATUS_INVALID_PARAMETER);
    return FALSE;
}


BOOL WINAPI TlsSetValue(DWORD dwTlsIndex, LPVOID lpTlsValue)
{
    WinApi* winapi = WinApi::Get();
    PTEB teb = NtCurrentTeb();
    PPEB peb = teb->ProcessEnvironmentBlock;

    // check if we have a simple TlsIndex
    if (dwTlsIndex < TLS_MINIMUM_AVAILABLE)
    {
        teb->TlsSlots[dwTlsIndex] = lpTlsValue;
        return TRUE;
    }

    DWORD dwExpTlsIndex = dwTlsIndex - TLS_MINIMUM_AVAILABLE;
    if (dwExpTlsIndex < TLS_EXPANSION_SLOTS)
    {
        // check if ExpansionSlot is allocated
        LPVOID tlsExpSlot = teb->TlsExpansionSlots;
        if (tlsExpSlot)
        {
            teb->TlsExpansionSlots[dwExpTlsIndex] = lpTlsValue;
            return 1;
        }

        // unknown globalVariable but should be 0
        ULONG KernelBaseGlobalData = 0;

        // allocate space for the expansion
        PVOID heapPtr = winapi->pRtlAllocateHeap(peb->ProcessHeap, HEAP_ZERO_MEMORY | KernelBaseGlobalData, 8 * TLS_EXPANSION_SLOTS);
        if (heapPtr)
        {
            teb->TlsExpansionSlots = (PVOID*)heapPtr;
            teb->TlsExpansionSlots[dwExpTlsIndex] = lpTlsValue;
            return TRUE;
        }
    }
    // 
    SetLastError(STATUS_NO_MEMORY);
    return FALSE;
}


LPVOID TlsGetValue(DWORD dwTlsIndex)
{
    WinApi* winapi = WinApi::Get();
    PTEB teb = NtCurrentTeb();

    // check if we have a simple TlsIndex
    if (dwTlsIndex < TLS_MINIMUM_AVAILABLE)
    {
        auto result = teb->TlsSlots[dwTlsIndex];
        teb->LastErrorValue = 0;
        return result;
    }

    // check if we are out of range 
    if (dwTlsIndex >= TLS_EXPANSION_SLOTS + TLS_MINIMUM_AVAILABLE)
    {
        SetLastError(STATUS_INVALID_PARAMETER);
        return NULL;
    }

    // check if ExpansionSlot is allocated
    LPVOID result = teb->TlsExpansionSlots;
    if (result)
        result = teb->TlsExpansionSlots[dwTlsIndex - TLS_MINIMUM_AVAILABLE];

    teb->LastErrorValue = 0;
    return result;
}

LPVOID TlsGetValue(DWORD dwThreadId, DWORD dwTlsIndex)
{
    WinApi* winapi = WinApi::Get();
    PTEB teb = GetTeb(dwThreadId);

    // check if we have a simple TlsIndex
    if (dwTlsIndex < TLS_MINIMUM_AVAILABLE)
    {
        auto result = teb->TlsSlots[dwTlsIndex];
        teb->LastErrorValue = 0;
        return result;
    }

    // check if we are out of range 
    if (dwTlsIndex >= TLS_EXPANSION_SLOTS + TLS_MINIMUM_AVAILABLE)
    {
        SetLastError(STATUS_INVALID_PARAMETER);
        return NULL;
    }

    // check if ExpansionSlot is allocated
    LPVOID result = teb->TlsExpansionSlots;
    if (result)
        result = teb->TlsExpansionSlots[dwTlsIndex - TLS_MINIMUM_AVAILABLE];

    teb->LastErrorValue = 0;
    return result;
}