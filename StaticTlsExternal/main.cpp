#include <stdio.h> 
#include "WinApi.h"
#include "WinFunction.h"

#define TLS_MAX TLS_MINIMUM_AVAILABLE + TLS_EXPANSION_SLOTS

BOOL GetTlsValue(DWORD dwProcId, DWORD dwThreadId, DWORD* dwTlsValue, DWORD dwTlsValueSize);

DWORD GetTlsOffset(DWORD dwProcId, LPCVOID address);


int main()
{
	BOOL bDebugPriv = SetDebugPrivilege(true);
	if (bDebugPriv == FALSE)
	{
		printf("SetDebugPrivilege failed\n");
		return 1;
	}

	DWORD pid = GetPidByName(L"StaticTls.exe");
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
		DWORD tlsValue[200] = { 0 };
		tlsValue[1] = 1;

		BOOL bTlsSlots = GetTlsValue(pid, threadId[i], tlsValue, sizeof(tlsValue));
		if (bTlsSlots == 1)
		{
			printf("GetTlsSlots failed\n");
			//return 1;
		}

		auto ComFuncAddress = 0x00007FF6159A1090;
		auto offset = GetTlsOffset(pid, (LPCVOID)ComFuncAddress);
		auto dwOffset = offset / sizeof(DWORD);

		printf("Pid=%d, Thread=%d, TlsValue[%d]=%d\n", pid, threadId[i], dwOffset, tlsValue[dwOffset]);

		//for (int j = 0; j < sizeof(tlsValue) / sizeof(tlsValue[0]); j++)
		//{
		//	if (tlsValue[j] != 0)
		//	{
		//		printf("Pid=%d, Thread=%d, TlsValue[%d]=%d\n", pid, threadId[i], j, tlsValue[j]);
		//	}
		//}
	}
}

BOOL GetTlsValue(DWORD dwProcId, DWORD dwThreadId, DWORD* dwTlsValue, DWORD dwTlsValueSize)
{
	//PVOID TlsSlots[TLS_MAX] = { 0 };
	ZeroMemory(dwTlsValue, dwTlsValueSize);

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

	if (tebb.ThreadLocalStoragePointer == NULL)
	{
		printf("ThreadLocalStoragePointer null\n");
		return 1;
	}

	PVOID TlsPointer;
	BOOL bTlsPointer = ReadProcessMemory(hProc, tebb.ThreadLocalStoragePointer, &TlsPointer, sizeof(TlsPointer), NULL);
	if (!bTlsPointer)
	{
		printf("ReadProcessMemory TlsPointer failed\n");
		return 1;
	}

	if (TlsPointer == NULL)
	{
		printf("TlsPointer null\n");
		return 1;
	}

	//DWORD TlsValue[100];
	BOOL bTlsValue = ReadProcessMemory(hProc, TlsPointer, dwTlsValue, dwTlsValueSize, NULL);
	if (!bTlsValue)
	{
		printf("ReadProcessMemory TlsValue failed\n");
		return 1;
	}


	CloseHandle(hProc);
	return 0;
}


DWORD GetTlsOffset(DWORD dwProcId, LPCVOID address)
{
	HANDLE hProc = OpenProcess(PROCESS_ALL_ACCESS, NULL, dwProcId);
	if (hProc == NULL)
	{
		printf("OpenProcess failed\n");
		return 0;
	}

	char buffer[100] = { 0 };
	BOOL bAddress2 = ReadProcessMemory(hProc, address, buffer, sizeof(buffer), NULL);
	if (!bAddress2)
	{
		
		printf("ReadProcessMemory func address failed %d\n", GetLastError());
		return 0;
	}

	char pattern[] = { 
		0xB8, 0x00, 0x00, 0x00, 0x00,							// move eax, 10h  <-- We search for this
		0x8B, 0xC0,												// mov eax, eax
		0x8B, 0x00, 0x00, 0x00, 0x00, 0x00,						// mov ecx, dword ptr [_tls_index]
		0x65, 0x48, 0x8B, 0x14, 0x25, 0x58, 0x00, 0x00, 0x00	// mov rdx, qword ptr gs:[58h]
	};
	char mask[] = "x????xxx?????xxxxxxxxx";

	auto found = ScanBasic(pattern, mask, buffer, sizeof(buffer));
	if (found == nullptr)
	{
		return 0;
	}

	return (DWORD)(found[1]);
}