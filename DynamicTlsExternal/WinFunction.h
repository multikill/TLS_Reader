#pragma once
#include "WinApi.h"

BOOL SetDebugPrivilege(bool Enable);
DWORD GetPidByName(const WCHAR* szProcName);
BOOL GetProcessThreads(DWORD dwOwnerPID, DWORD* dwThreadList, DWORD& dwThreadListCount);
PTEB GetTeb(DWORD dwThreadId);