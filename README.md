# TLS Thread Local Storage
In this post I will give you a short overview about the different types of TLS.
The main use of TLS is to make data accessible only to a thread.
Each of the following TLS categories contains an example of usage.
Furthermore there is an **External** variant to read the relevant TLS data with an external console application.
**Tested with Debug Configuration and x64.**

## Dynamic TLS
This type of TLS is usually used in combination with a Dynamic Link Library.
A detailed description with example can be found in the MSDN Documentation.
https://docs.microsoft.com/en-us/windows/win32/dlls/using-thread-local-storage-in-a-dynamic-link-library

For usage Microsoft provides us with the following 4 functions.
These can also be found as decompiled version in the download.
* DWORD TlsAlloc()
* BOOL WINAPI TlsFree(DWORD dwTlsIndex)
* BOOL WINAPI TlsSetValue(DWORD dwTlsIndex, LPVOID lpTlsValue)
* LPVOID TlsGetValue(DWORD dwTlsIndex)

With the TlsAlloc function we get an index with which we can access the thread variable.
It should be mentioned that the function normally does not even allocate memory. 
With the functions TlsSetValue can be written and the function TlsGetValue can be read.
The function TlsFree releases the index in the bitmap and if necessary the allocated memory.

This diagram ilustrates a simplified internal structure. <br/>
![Dynamic TLS ](https://docs.microsoft.com/en-us/windows/win32/procthread/images/tls.png) <br/>
https://docs.microsoft.com/en-us/windows/win32/procthread/thread-local-storage <br/>


To understand how these functions work, you should also know about bitmaps.
On OSR Online you can find an example of how it works.
https://www.osronline.com/article.cfm%5Earticle=523.htm

### Relevant structs
```
typedef struct _PEB
{
  // ...
  PVOID TlsBitmap;
  // ...
  PVOID TlsExpansionBitmap;
  // ...
} PEB, *PPEB;
```
```
typedef struct _TEB
{
  // ...
  PVOID TlsSlots[64];
  // ...
  PVOID *TlsExpansionSlots;
  // ...
} TEB, *PTEB;
```


### Simple instruction
* Open Process
* Get Thread List
* Read TlsIndex from Global Variable 
* Get TEB
* Read TEB->TlsSlots[Index], if the index < 64
* Read TEB->TlsExpansionSlots[Index], if the index > 64 

### Console output preview
![conhost_Eb7TBejXls](https://user-images.githubusercontent.com/33375406/111152761-62d7e400-8591-11eb-9a0b-6336e451d970.png)


# Static TLS
Have you ever encountered a TLS while reversing and didn't know how to extract the data?
Here is a small example image of what this might look like.
![devenv_Wjg34feCWD](https://user-images.githubusercontent.com/33375406/111140304-7af43700-8582-11eb-8f25-7bcb2b834802.png)

This is the Microsoft implementation of the thread local variant.
For this the keyword **__declspec( thread )** or the c++ variants **thread_local** are used.
When analyzing, I could not find any difference and thus consider them equivalent.
More information can be found again on the MSDN page
https://docs.microsoft.com/en-us/cpp/parallel/thread-local-storage-tls?view=msvc-160

With this variant all accesses to these variables are translated at compile time.
Therefore we also get a fixed offset in the code to access the data.
This of course makes it more difficult to access the data.

### Relevant structs
```
typedef struct _TEB
{
  // ...
  PVOID ThreadLocalStoragePointer;
  // ...
} TEB, *PTEB;
```

### Simple instruction
* Open Process
* Get Thread List
* Patternscan function, which are read from tls
* Get the TlsOffset from the function
* Get TEB
* Read TEB->ThreadLocalStoragePointer[Offset]

### Console output preview
![conhost_EIHQKangt5](https://user-images.githubusercontent.com/33375406/111152712-52c00480-8591-11eb-9d7b-2b82bcd436b2.png)

Akaion has another detailed good article about TLS internals.
Never understood how the mapping works exactly.
https://guidedhacking.com/threads/tls-internals-ldrphandletlsdata-and-friends.14960/


# TLS callbacks

Tls callbacks are subroutines thar are executed before and after the entry point.
An array of these callbacks can be easily found in the NT header under IMAGE_TLS_DIRECTORY.
It should be mentioned that these can also be changed dynamically at runtime.
A good example for this are the calls from a Dll the DllMain Function.


### Relevant structs
```
typedef struct _IMAGE_TLS_DIRECTORY64 {
  // ...
  ULONGLONG AddressOfCallBacks; // PIMAGE_TLS_CALLBACK *;
  // ...
} IMAGE_TLS_DIRECTORY64;
```

### Simple instruction
* Open Process
* Get PEB
* Get IMAGE_DIRECTORY_ENTRY_TLS
* Read Array of AddressOfCallBacks

If you just want to execute code before the main, there are easier ways like this example.
```
DWORD CalledBeforeMain(VOID)
{
    printf("Called before main\n");
    return 42;
}
static DWORD temp = CalledBeforeMain();
```

### Console output preview
![conhost_cfUSjxr0bn](https://user-images.githubusercontent.com/33375406/111152609-32904580-8591-11eb-9d9f-df0c9cec826d.png)

Detailed examples of TLS callbacks with explanations can be found in kevinalmansa his repository.
https://github.com/kevinalmansa/TLS_Examples
