#include "WinFunction.h"
#include <TlHelp32.h>

BOOL SetDebugPrivilege(bool Enable)
{
    HANDLE hToken = 0;
    TOKEN_PRIVILEGES tkp = { 0 };

    // Get a token for this process.
    BOOL bOpt = OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken);
    if (!bOpt)
    {
        return FALSE;
    }

    // Get the LUID for the privilege. 
    BOOL bLpv = LookupPrivilegeValue(NULL, L"SeDebugPrivilege", &tkp.Privileges[0].Luid);
    if (!bLpv)
    {
        CloseHandle(hToken);
        return FALSE;
    }

    tkp.PrivilegeCount = 1;  // one privilege to set
    if (Enable)
        tkp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
    else
        tkp.Privileges[0].Attributes = SE_PRIVILEGE_USED_FOR_ACCESS;


    // Set the privilege for this process. 
    BOOL bAtp = AdjustTokenPrivileges(hToken, FALSE, &tkp, sizeof(TOKEN_PRIVILEGES), (PTOKEN_PRIVILEGES)NULL, 0);
    if (!bAtp)
    {
        CloseHandle(hToken);
        return FALSE;
    }

    CloseHandle(hToken);
    return TRUE;
}

DWORD GetPidByName(const WCHAR* szProcName)
{
    HANDLE hProcessSnap;
    HANDLE hProcess;
    PROCESSENTRY32 pe32;
    DWORD dwPriorityClass;

    // Take a snapshot of all processes in the system.
    hProcessSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hProcessSnap == INVALID_HANDLE_VALUE)
        return 0;

    // Set the size of the structure before using it.
    pe32.dwSize = sizeof(PROCESSENTRY32);

    // Retrieve information about the first process,
    // and exit if unsuccessful
    if (!Process32First(hProcessSnap, &pe32))
    {
        CloseHandle(hProcessSnap);          // clean the snapshot object
        return 0;
    }

    // Now walk the snapshot of processes, and
    // display information about each process in turn
    do
    {

        if (!wcscmp(pe32.szExeFile, szProcName))
        {
            CloseHandle(hProcessSnap);
            return pe32.th32ProcessID;
        }

    } while (Process32Next(hProcessSnap, &pe32));

    CloseHandle(hProcessSnap);
    return 0;
}

// https://docs.microsoft.com/en-us/windows/win32/toolhelp/taking-a-snapshot-and-viewing-processes
BOOL GetProcessThreads(DWORD dwOwnerPID, DWORD *dwThreadList, DWORD &dwThreadListCount)
{
    HANDLE hThreadSnap = INVALID_HANDLE_VALUE;
    THREADENTRY32 te32;

    // Take a snapshot of all running threads  
    hThreadSnap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
    if (hThreadSnap == INVALID_HANDLE_VALUE)
        return(FALSE);

    // Fill in the size of the structure before using it. 
    te32.dwSize = sizeof(THREADENTRY32);

    // Retrieve information about the first thread,
    // and exit if unsuccessful
    if (!Thread32First(hThreadSnap, &te32))
    {
        CloseHandle(hThreadSnap);          // clean the snapshot object
        return(FALSE);
    }

    DWORD i = 0;
    // Now walk the thread list of the system,
    // and display information about each thread
    // associated with the specified process
    do
    {
        if (te32.th32OwnerProcessID == dwOwnerPID)
        {
            if (i <= dwThreadListCount)
            {
                dwThreadList[i] = te32.th32ThreadID;
                i++;
            }
            else
            {

                return FALSE;
            }

        }
    } while (Thread32Next(hThreadSnap, &te32));

    CloseHandle(hThreadSnap);
    dwThreadListCount = i;
    return(TRUE);
}

PTEB GetTeb(DWORD dwThreadId)
{
    WinApi* winApi = WinApi::Get();
    void* start_address;

    SYSTEM_PROCESS_INFORMATION spi = { 0 };
    //NTSTATUS ntRet = m_pNtQuerySystemInformation(SYSTEM_INFORMATION_CLASS::SystemProcessInformation, &spi, m_BufferSize, &size_out);

    HANDLE hThread = OpenThread(THREAD_QUERY_INFORMATION | THREAD_QUERY_LIMITED_INFORMATION, FALSE, dwThreadId);
    if (!hThread)
    {
        return NULL;
    }

    THREAD_BASIC_INFORMATION tbi{ 0 };
    NTSTATUS ntStatus = winApi->pNtQueryInformationThread(hThread, THREADINFOCLASS::ThreadBasicInformation, &tbi, sizeof(tbi), nullptr);
    if (NT_SUCCESS(ntStatus))
    {
        CloseHandle(hThread);
        return tbi.TebBaseAddress;
    }

    CloseHandle(hThread);
    return NULL;
}