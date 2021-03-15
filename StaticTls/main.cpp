#include <windows.h> 
#include <stdio.h> 

#define THREADCOUNT 2 
__declspec(thread) DWORD dwTls_i1 = 1;
thread_local DWORD dwTls_i2 = 2;

extern "C" VOID CommonFunc(VOID);

VOID CommonFunc(VOID)
{
    DWORD dwData1 = dwTls_i1;
    DWORD dwData2 = dwTls_i2;

    printf("thread=%d dwTls_i1=%d dwTls_i2=%d\n", GetCurrentThreadId(), dwData1, dwData2);

    Sleep(5000);
}

DWORD WINAPI ThreadFunc(VOID)
{
    dwTls_i1 = GetCurrentThreadId();
    dwTls_i2 = GetCurrentThreadId() + 1;

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

    printf("CommonFunc: 0x%p\n", &CommonFunc);

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

    return 0;
}
