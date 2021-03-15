#include <windows.h> 
#include <stdio.h> 

#define THREADCOUNT 2 
DWORD dwTls_i;


VOID CommonFunc(VOID)
{
    LPVOID lpvData = TlsGetValue(dwTls_i);

    printf("TlsIndex=%d thread=%d data=%d\n", dwTls_i, GetCurrentThreadId(), lpvData);

    Sleep(5000);
}

DWORD WINAPI ThreadFunc(VOID)
{

    LPVOID lpvData = (LPVOID)GetCurrentThreadId();
    if (!TlsSetValue(dwTls_i, lpvData))
    {
        printf("TlsSetValue failed\n");
        return 1;
    }

    while (TRUE)
    {
        CommonFunc();
    }

    return 0;
}

int main(VOID)
{
    DWORD IDThread;
    HANDLE hThread[THREADCOUNT];
    int i;

    // Allocate a TLS index. 

    if ((dwTls_i = TlsAlloc()) == TLS_OUT_OF_INDEXES)
    {
        printf("TlsAlloc failed\n");
        return 1;
    }

    // Create multiple threads. 

    for (i = 0; i < THREADCOUNT; i++)
    {
        hThread[i] = CreateThread(NULL, // default security attributes 
            0,                           // use default stack size 
            (LPTHREAD_START_ROUTINE)ThreadFunc, // thread function 
            NULL,                    // no thread function argument 
            0,                       // use default creation flags 
            &IDThread);              // returns thread identifier 

      // Check the return value for success. 
        if (hThread[i] == NULL)
        {
            printf("CreateThread failed\n");
            ExitProcess(1);
        }

    }

    for (i = 0; i < THREADCOUNT; i++)
        WaitForSingleObject(hThread[i], INFINITE);

    TlsFree(dwTls_i);

    return 0;
}

