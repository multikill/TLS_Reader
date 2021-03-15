#pragma once
#include "WinApi.h"

DWORD TlsAlloc();
BOOL WINAPI TlsFree(DWORD dwTlsIndex);
BOOL WINAPI TlsSetValue(DWORD dwTlsIndex, LPVOID lpTlsValue);
LPVOID TlsGetValue(DWORD dwTlsIndex);

LPVOID TlsGetValue(DWORD dwThreadId, DWORD dwTlsIndex);
