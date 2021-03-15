#pragma once
#include <phnt_windows.h>
#include <phnt.h>
#define PHNT_VERSION PHNT_THRESHOLD // Windows 10

// BitMaps
// https://www.osronline.com/article.cfm%5Earticle=523.htm

typedef NTSYSAPI VOID(NTAPI* fRtlAcquirePebLock)(VOID);
typedef NTSYSAPI VOID(NTAPI* fRtlReleasePebLock)(VOID);
typedef NTSYSAPI ULONG(NTAPI* fRtlFindClearBitsAndSet)(
    _In_ PRTL_BITMAP BitMapHeader, _In_ ULONG NumberToFind, _In_ ULONG HintIndex);
typedef NTSYSAPI PVOID(NTAPI* fRtlAllocateHeap)(
    _In_ PVOID HeapHandle, _In_opt_ ULONG Flags, _In_ SIZE_T Size);
typedef NTSYSAPI BOOLEAN(NTAPI* fRtlAreBitsSet)(
    _In_ PRTL_BITMAP BitMapHeader, _In_ ULONG StartingIndex, _In_ ULONG Length);
typedef NTSYSAPI VOID(NTAPI* fRtlClearBits)(
    _In_ PRTL_BITMAP BitMapHeader,
    _In_range_(0, BitMapHeader->SizeOfBitMap - NumberToClear) ULONG StartingIndex,
    _In_range_(0, BitMapHeader->SizeOfBitMap - StartingIndex) ULONG NumberToClear
    );

typedef NTSYSAPI ULONG (NTAPI* fRtlNumberOfSetBits)( _In_ PRTL_BITMAP BitMapHeader);

typedef NTSYSCALLAPI NTSTATUS(NTAPI* fNtSetInformationThread)(
    _In_ HANDLE ThreadHandle,
    _In_ THREADINFOCLASS ThreadInformationClass,
    _In_reads_bytes_(ThreadInformationLength) PVOID ThreadInformation,
    _In_ ULONG ThreadInformationLength
    );

typedef NTSYSCALLAPI NTSTATUS(NTAPI* fNtQueryInformationThread)(
    _In_ HANDLE ThreadHandle,
    _In_ THREADINFOCLASS ThreadInformationClass,
    _Out_writes_bytes_(ThreadInformationLength) PVOID ThreadInformation,
    _In_ ULONG ThreadInformationLength,
    _Out_opt_ PULONG ReturnLength
    );

typedef NTSYSCALLAPI NTSTATUS (NTAPI* fNtQueryInformationProcess)(
    _In_ HANDLE ProcessHandle,
    _In_ PROCESSINFOCLASS ProcessInformationClass,
    _Out_writes_bytes_(ProcessInformationLength) PVOID ProcessInformation,
    _In_ ULONG ProcessInformationLength,
    _Out_opt_ PULONG ReturnLength
);

class WinApi
{
private:
    inline static WinApi* instance = nullptr;
    WinApi() { }
public:
    fRtlAcquirePebLock pRtlAcquirePebLock;
    fRtlReleasePebLock pRtlReleasePebLock;
    fRtlAllocateHeap pRtlAllocateHeap;
    fRtlFindClearBitsAndSet pRtlFindClearBitsAndSet;
    fRtlAreBitsSet pRtlAreBitsSet;
    fRtlClearBits pRtlClearBits;
    fRtlNumberOfSetBits pRtlNumberOfSetBits;
    fNtSetInformationThread pNtSetInformationThread;
    fNtQueryInformationThread pNtQueryInformationThread;
    fNtQueryInformationProcess pNtQueryInformationProcess;

    inline static WinApi* Get()
    {
        if (instance == nullptr)
        {
            instance = new WinApi();
            instance->Init();
        }
        return instance;
    }

    inline void Init()
    {
        pRtlAcquirePebLock = (fRtlAcquirePebLock)GetProcAddress(GetModuleHandleA("ntdll.dll"), "RtlAcquirePebLock");
        pRtlReleasePebLock = (fRtlReleasePebLock)GetProcAddress(GetModuleHandleA("ntdll.dll"), "RtlReleasePebLock");
        pRtlAllocateHeap = (fRtlAllocateHeap)GetProcAddress(GetModuleHandleA("ntdll.dll"), "RtlAllocateHeap");
        pRtlFindClearBitsAndSet = (fRtlFindClearBitsAndSet)GetProcAddress(GetModuleHandleA("ntdll.dll"), "RtlFindClearBitsAndSet");
        pRtlAreBitsSet = (fRtlAreBitsSet)GetProcAddress(GetModuleHandleA("ntdll.dll"), "RtlAreBitsSet");
        pRtlClearBits = (fRtlClearBits)GetProcAddress(GetModuleHandleA("ntdll.dll"), "RtlClearBits");
        pRtlNumberOfSetBits = (fRtlNumberOfSetBits)GetProcAddress(GetModuleHandleA("ntdll.dll"), "RtlNumberOfSetBits");
        pNtSetInformationThread = (fNtSetInformationThread)GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtSetInformationThread");
        pNtQueryInformationThread = (fNtQueryInformationThread)GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtQueryInformationThread");
        pNtQueryInformationProcess = (fNtQueryInformationProcess)GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtQueryInformationProcess");   
    }

    inline PPEB GetCurrentPeb()
    {
        return (PPEB)__readgsqword(0x60);
    }

    inline PTEB GetCurrentTeb()
    {
        return (PTEB)__readgsqword(0x30);
    }

    inline WINBASEAPI DWORD WINAPI GetCurrentThreadId(VOID)
    {
        return (DWORD)WinApi::GetCurrentTeb()->ClientId.UniqueThread;
    }
};