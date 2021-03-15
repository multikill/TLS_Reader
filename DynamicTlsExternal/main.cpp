#include <stdio.h> 
#include "WinApi.h"
#include "TlsFunction.h"
#include "WinFunction.h"

#define TLS_MAX TLS_MINIMUM_AVAILABLE + TLS_EXPANSION_SLOTS

BOOL GetTlsSlots(DWORD dwProcId, DWORD dwThreadId, PVOID* TlsSlots);

int main()
{
	BOOL bDebugPriv = SetDebugPrivilege(true);
	if (bDebugPriv == FALSE)
	{
		printf("SetDebugPrivilege failed\n");
		return 1;
	}

	DWORD pid = GetPidByName(L"DynamicTls.exe");
	if (pid == 0)
	{
		printf("GetPidByName failed\n");
		return 1;
	}

	DWORD threadCount = 10;
	DWORD threadId[10] = { 0 };
	BOOL threadResult = GetProcessThreads(pid, threadId, threadCount);
	if (threadResult == FALSE)
	{
		printf("GetProcessThreads failed\n");
		return 1;
	}

	for (int i = 0; i < threadCount; i++)
	{
		PVOID tlsSlots[TLS_MAX] = { 0 };
		tlsSlots[1] = (PVOID)1;

		BOOL bTlsSlots = GetTlsSlots(pid, threadId[i], tlsSlots);
		if (bTlsSlots == 1)
		{
			printf("GetTlsSlots failed\n");
			return 1;
		}

		for (int j = 0; j < TLS_MAX; j++)
		{
			if (tlsSlots[j] != 0)
			{
				printf("Pid=%d, Thread=%d, TlsSlots[%d]=%d\n", pid, threadId[i], j, tlsSlots[j]);
			}
		}
	}
}

BOOL GetTlsSlots(DWORD dwProcId, DWORD dwThreadId, PVOID* TlsSlots)
{
	//PVOID TlsSlots[TLS_MAX] = { 0 };
	ZeroMemory(TlsSlots, TLS_MINIMUM_AVAILABLE + TLS_EXPANSION_SLOTS);

	HANDLE hThread = OpenThread(THREAD_QUERY_INFORMATION | THREAD_QUERY_LIMITED_INFORMATION, FALSE, dwThreadId);
	if (!hThread)
	{
		printf("OpenThread failed\n");
		return 1;
	}

	WinApi* winApi = WinApi::Get();
	THREAD_BASIC_INFORMATION tbi{ 0 };
	NTSTATUS ntStatus = winApi->pNtQueryInformationThread(hThread, THREADINFOCLASS::ThreadBasicInformation, &tbi, sizeof(tbi), nullptr);
	if (!NT_SUCCESS(ntStatus))
	{
		CloseHandle(hThread);
		printf("OpenThread failed\n");
		return 1;
	}

	CloseHandle(hThread);

	PTEB teb = tbi.TebBaseAddress;
	if (teb == NULL)
	{
		printf("OpenThread failed\n");
		return 1;
	}

	HANDLE hProc = OpenProcess(PROCESS_VM_READ, NULL, dwProcId);
	if (hProc == NULL)
	{
		printf("OpenProcess failed\n");
		return NULL;
	}

	TEB tebb = { 0 };
	BOOL bTeb = ReadProcessMemory(hProc, tbi.TebBaseAddress, &tebb, sizeof(tebb), NULL);
	if (!bTeb)
	{
		printf("ReadProcessMemory teb failed\n");
		return 1;
	}

	if (!tebb.TlsSlots)
	{
		printf("tebb.TlsSlots null\n");
		return 1;
	}

	// ready normal tls slots
	BOOL bReadTls = ReadProcessMemory(hProc, teb->TlsSlots, TlsSlots, TLS_MINIMUM_AVAILABLE * 8, NULL);

	// ready optional tls expansion slots
	if (tebb.TlsExpansionSlots)
	{
		BOOL bReadTlsExp = ReadProcessMemory(hProc, teb->TlsExpansionSlots, TlsSlots + TLS_MINIMUM_AVAILABLE, TLS_EXPANSION_SLOTS * 8, NULL);
	}

	CloseHandle(hProc);
	return 0;
}
