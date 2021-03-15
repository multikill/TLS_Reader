#include <Windows.h>
#include <stdio.h>

// Set Windows Linking Options for use of TLS and TLS_CALLBACK.
#pragma comment (linker, "/INCLUDE:_tls_used")
#pragma comment (linker, "/INCLUDE:tls_callback_func")

// Declare of the TLS Callback functions to execute.
void tls_callback(PVOID hModule, DWORD dwReason, PVOID pContext)
{
	if (dwReason == DLL_PROCESS_ATTACH) {
		printf("TLS Callback 0x%llp: Process Attach Triggered\n", tls_callback);
	}

	if (dwReason == DLL_PROCESS_DETACH) {
		// this is not visible because stdout is no longer available
		printf("TLS Callback: Process Detach Triggered\n");
	}
}

// Under x64 it must be a const_seg
#pragma const_seg(".CRT$XLB")

// declared with EXTERN_C to avoid name wrangling of CPP
EXTERN_C const
PIMAGE_TLS_CALLBACK tls_callback_func = (PIMAGE_TLS_CALLBACK)tls_callback;

// End section decleration
#pragma const_seg()


int main()
{
	printf("TLS Main\n");
	system("pause");
	return 0;
}
