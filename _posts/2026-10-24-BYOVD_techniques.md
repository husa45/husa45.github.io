---
title: "An Overview of BYOVD and it's abuse"
date: 2026-10-24 21:00:00 +0300
categories: [malware analysis, Misc] 
tags: [malware,kernel,BYOVD,rootkits,EDR,edr-killers]
render_with_liquid: false
---

In the early days of windows , malware authors would write **rootkits** that can do essentially anything in  the kernel , including hiding itself and it's artefacts , or embedding itself  into the system , making them impossible to be removed .

**Black energy** was a famous malware back in the day  , that had a kernel-mode **rootkit** component to enable system-level operations.<sup>[[1]](#references-and-resources)</sup>


If you analyzed a rootkit before , you will notice that it heavily depends on **kernel Data structures** manipulation .

Popular techniques including Direct Kernel Object Manipulation **DKOM** used to manipulate **EPROCESS** structure to hide processes <sup>[[2]](#references-and-resources)</sup> . Also , System Service Descriptor Table **SSDT** hooking was a popular one .In short , when **syscalls** are done , eventually , they will call APIs exposed mostly by **Ntoskernel.exe** . So , SSDT provides a lookup table , that correlates **syscall numbers** with the corresponding **function** from the kernel .

Malware authors (and Anti-Virus products  also) would  hook this table from the kernel , So instead of a **syscall number** X resolves to function Y , it will now be redirected to the malicious kernel driver function (So it can block it  , manipulate the return ...etc) .


In 2005 , with the  introduction of ``x64`` editions of Windows ``Vista`` and ``Windows Server 2003 Service Pack 1``, Microsoft released a new protection fetaure called **Kernel Patch Guard KPP** .

KPP is intended to protect core Kernel Data Structures from being manipulated in any way . It would calculate a ***hash***  value of some Data structures on the system startup , then it would regularly re-calulcate it to verfiy that the Data Structures are **intact** . If windows detects that any protected Data Structure is manipulated , it will raise a bugcheck , ``with bugcheck number  0x109 and  the bugcheck code is CRITICAL_STRUCTURE_CORRUPTION`` , wich would directly terminate the system , causing the popular **BSOD Blue Screen Of Death** to be shown .<sup>[[3]](#references-and-resources)</sup>

Some Of the Core Data Structures Protected :

- Modifying system service descriptor tables *SSDT*
- Modifying the interrupt descriptor table *IDT*
- Modifying the global descriptor table  *GDT*
- Using kernel stacks not allocated by the kernel 
- Modifying or patching code contained within the kernel itself, or the HAL or NDIS kernel libraries

All Of those Data Structures were abused by **rootkits** in some fashion .



Is this the End of the story ? No , malware authors would still write **rootkits** that will avoid patching the kernel , but will offcourse exert other functionality (like reading any process memory , accessing restricted files and processes ).


That's why microsoft released another Kernel protection , which is called **Driver Signature Enforcment DSS** .

By this mechanism , only Drivers **Signed** by microsoft or trusted code signers can be loaded into the kernel , otherwise it will not load .

That introduced a big hurdle for adversaries  , because now they do not just need to write the driver , they need to sign it , which often involves identity checks , malware scans and other obstacles .


**DSS** coupled with **KPP** have significantly reduced the prevalence of kernel mode **rootkits** in the past years .



If you pay attention to details , you will notice that we have not mentioned that drivers are prohibited to load , they just need to be **code-signed** .


So have adversaries found a way around these protecitons ?


## Bring Your Own Vulnerable driver BYOVD 

You have probably heard before about **Bring your Own Land** techniques , so what about **Bring Your Own Vulnerable Driver** ?


If Kernel Patching is forbidden , and driver loading needs signature , why would adversaries bother to go through this minefield . Instead , adversaries will do research about  already **signed** drivers , that expose unsafe functionality .

Because these drivers are **signed** , they can be loaded to the kernel easily , but what makes these drivers attractive is the functionalities that they provide .


Most of these **vulnerable** drivers are abused in two ways : 

- They  allow for **unsafe functionality** exposed through **IOCTL** , so the malware from the usermode can control them . Example of that would be a driver that calls **ZwTerminateProcess** with a user-mode supplied **PID** . A normal AV software for example , will use this to terminate malicious processes , but malware will use it to kill **EDRs** .


- They have vulnerable design , wich allows adversaries to exploit them , to access the kernel . For example , they may be exploited to achieve a **memory read** (which is devatasting at the level of the kernel , because restrictions  are not applied).

> Note: This vulnerable driver will be either **embedded** in the malwre  , or **dropped** from the C2 server
{: .prompt-info }
<br>

A very popular example of those BYOVDs in the modern day are **EDR killers** .Those are vulnerable drivers that can terminate processes from kernel mode , making them seducing targets for adversaries to terminate **EDR** processes .

For example  , the **gentleman** ransomware is famous for using EDR killers to terminate security software before it begins it's actions .<sup>[[4]](#references-and-resources)</sup>


#### The escalation journey

Loading the driver to the kernel is not a trivial task , it is usually a final step in a multi-step escalation path .

To be able to load the **vunerable** driver into the kernel , the malware needs to have **SeLoadDriverPrivilege** , which requires **Administrator** access .

![Demonstration image](/resources/BYOVD-rsrcs/escalation-path.jpeg)
*Typical Escalation chain leading to kernel privileges*

**A typical chain of events typically occur :**

Initial access (the malware has low privileges) &rarr; Privilege Escalation (escalate to admin to obtain **SeLoadDriverPrivilege**) &rarr; Gain kernel-mode privilege level by loading the **Vulnerable driver** into the kernel. 



### The final dance , loading the driver

After the malware Escalates To Admin , and obtains **SeLoadDriverPrivilege** , it will :

- Drop the driver **embedded** or **dropped** from the C2 .

- Create a service to load the driver , with service type ``SERVICE_KERNEL_DRIVER`` and ``Auto start`` .

- Communicate with the Driver using **IOCTL** . Ex : using **DeviceIOControl** API .



In the next part of the article , we will analyze a real world vulnerable driver used as an **EDR** killer . 



## NSecKrnl.sys 

According to [LOLdrivers](https://www.loldrivers.io/drivers/c1143cd9-a709-4323-9678-2117285d1b47/?hash=206f27ae820783b7755bca89f83a0fe096dbb510018dd65b63fc80bd20c03261#samples)  this driver was first discovered ``2025-09-18`` , it was assigned **CVE-2025-68947** .

It is a legitimate driver used by **NSecsoft** Anti-Virus , which is designed to terminate processes from kernel-mode , by a supplied PID from user mode using **IOCTL** .

It is also a driver **minifilter** designed to intercept **ProcessCreation** events for certain PIDs (supplied from user-mode) , and prevent their termination . Most write-ups and articles i have seen does not mention this aspect , they all focus on **process termination** capability .


After some reverse engineering  , you will notice that in the **DeviceIOControl** handler ,  corresponding to IOCTL code ``0x2248E0`` , the following is routine is invoked (The process id is passed from the usermode with the IOCTL buffer) : 

```
char __fastcall sub_1400013E8(DWORd PID)
{
  HANDLE ProcessHandle;
  PEPROCESS Process;

  Process = nullptr;
  ProcessHandle = nullptr;
  if ( PsLookupProcessByProcessId(ProcessId: PID, &Process) >= 0
    && ObOpenObjectByPointer(
         Object: Process,
         HandleAttributes: 0x200u,
         PassedAccessState: nullptr,
         DesiredAccess: 1u,
         ObjectType: (POBJECT_TYPE)PsProcessType,
         AccessMode: 0,
         Handle: &ProcessHandle) >= 0 )
  {
    ZwTerminateProcess(ProcessHandle, ExitStatus: 0);
    ZwClose(Handle: ProcessHandle);
  }
  if ( Process != nullptr )
    ObfDereferenceObject(Object: Process);
  return 0;
}
```

First , using ``PsLookupProcessByProcessId`` will return the **Eprocess** node of the process using the PID . Next , using ``ObOpenObjectByPointer`` to obtains a handle to the process . Finally , calling ``ZwTerminateProcess`` to terminate the process . 


> Note: Since the driver runs in kernel mode , any process can be terminated , including EDR processes , making this driver an EDR killer .
{: .prompt-info }


I will Leave the process termination inhibitor part for you as an Exercise , but you might need to learn about the wonderfull world of **driver** minifilters , check the resources at the end of the article .<sup>[[5]](#references-and-resources)</sup>



# References and resources 

[1] [Huntress article about Black energy](https://www.huntress.com/threat-library/malware/blackenergy)

[2] [Hiding Processes Using DCOM](https://www.ired.team/miscellaneous-reversing-forensics/windows-kernel-internals/manipulating-activeprocesslinks-to-unlink-processes-in-userland)

[3] [A wonderfull article about KPP](https://en.wikipedia.org/wiki/Kernel_Patch_Protection)

[4] [Inside Gentlemen’s EDR killer framework](https://www.welivesecurity.com/en/eset-research/killing-me-gently-inside-gentlemens-edr-killer-framework/)

[5] [General article with good resources on minifilters](https://medium.com/@WaterBucket/understanding-mini-filter-drivers-for-windows-vulnerability-research-exploit-development-391153c945d6)