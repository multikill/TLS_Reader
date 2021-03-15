#include <stdio.h> 
#include "WinApi.h"
#include "WinFunction.h"

int main()
{
	BOOL bDebugPriv = SetDebugPrivilege(true);
	if (bDebugPriv == FALSE)
	{
		printf("SetDebugPrivilege failed\n");
		return 1;
	}

	DWORD dwPid = GetPidByName(L"CallbackTls.exe");
	if (dwPid == 0)
	{
		printf("GetPidByName failed\n");
		return 1;
	}

	HANDLE hProc = OpenProcess(PROCESS_ALL_ACCESS, NULL, dwPid);
	if (hProc == NULL)
	{
		printf("OpenProcess failed\n");
		return 1;
	}

	WinApi* winapi = WinApi::Get();

	PROCESS_BASIC_INFORMATION pbi = { 0 };
	NTSTATUS status = winapi->pNtQueryInformationProcess(hProc, ProcessBasicInformation, &pbi, sizeof(pbi), 0);
	if (!NT_SUCCESS(status))
	{
		printf("pNtQueryInformationProcess failed\n");
		return 1;
	}

	PEB peb = { 0 };
	BOOL bReadPeb = ReadProcessMemory(hProc, pbi.PebBaseAddress, &peb, sizeof(peb), 0);
	if (bReadPeb == 0)
	{
		printf("ReadProcessMemory peb failed\n");
		return 1;
	}
	
	SIZE_T heapSize = sizeof(IMAGE_DOS_HEADER) + sizeof(IMAGE_NT_HEADERS) + 0x1000;
	PVOID pHeap = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, heapSize);
	if (pHeap == NULL)
	{
		printf("HeapAlloc failed\n");
		return 1;
	}

	BOOL bReadImage = ReadProcessMemory(hProc, peb.ImageBaseAddress, pHeap, heapSize, 0);
	if (bReadImage == 0)
	{
		printf("ReadProcessMemory Image failed\n");
		return 1;
	}

	PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)pHeap;
	if (pDosHeader->e_magic != 0x5a4d)
	{
		printf("pDosHeader->e_magic failed\n");
		return 1;
	}

	PIMAGE_NT_HEADERS pNtHeader = (PIMAGE_NT_HEADERS)((ULONGLONG)pHeap + (ULONGLONG)pDosHeader->e_lfanew);
	if (pNtHeader->Signature != 0x4550)
	{
		printf("pNtHeader->Signature failed\n");
		return 1;
	}

	auto rvaIdd = pNtHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].VirtualAddress;
	auto tlsDirOffsett = (long long)(peb.ImageBaseAddress) + (long long)rvaIdd;

	IMAGE_TLS_DIRECTORY tlsDir = { 0 };
	BOOL bReadIdd = ReadProcessMemory(hProc, (PVOID)tlsDirOffsett, &tlsDir, sizeof(tlsDir), 0);
	if (bReadIdd == 0)
	{
		printf("ReadProcessMemory tlsDirOffsett failed\n");
		return 1;
	}

	PIMAGE_TLS_CALLBACK pTlsCallback[10] = { 0 };
	BOOL bReadCallOff = ReadProcessMemory(hProc, (PVOID)tlsDir.AddressOfCallBacks, &pTlsCallback, sizeof(pTlsCallback), 0);
	if (bReadCallOff == 0)
	{
		printf("ReadProcessMemory tlsDir.AddressOfCallBacks failed\n");
		return 1;
	}

	printf("IMAGE_TLS_DIRECTORY\n");
	printf("  StartAddressOfRawData 0x%llp\n", tlsDir.StartAddressOfRawData);
	printf("  EndAddressOfRawData   0x%llp\n", tlsDir.EndAddressOfRawData);
	printf("  AddressOfCallBacks    0x%llp\n", tlsDir.AddressOfCallBacks);

	for (int i = 0; i < sizeof(pTlsCallback) / sizeof(PIMAGE_TLS_CALLBACK); i++)
	{
		if (pTlsCallback[i] != 0)
			printf("    PIMAGE_TLS_CALLBACK    0x%llp\n", pTlsCallback[i]);
		else
			break;
	}


	HeapFree(pHeap, NULL, NULL);
	CloseHandle(hProc);

}