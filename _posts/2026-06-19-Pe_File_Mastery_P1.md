---
title: "PE file headers analysis mastery series , Introduction"
date: 2026-06-19 11:33:30 +0300
categories: [malware analysis, PE file structure] 
tags: [misc,malware]
---
# PE file headers Analysis Mastery series ,Part1 ,Introduction :

**Have you ever wondered how an executable (which is just compact sequence of instruction opcodes) gets understood and executed by the OS ,or you maybe heard about advanced evasion techniques like PE walking ,or API hashing and manual API resolving ,and you were wondering how all that works ?**
<br><br>

In this series , we will be diving deep into the structure of the PE header ,its main components , focusing on fields and structures that are most relevant to malware analysis and threat hunting
<br><br>

In this and the next few blogs ,we are going to explain in a detailed clear way , the main headers in the PE file  and as a final project ,we will be writing our custom PE loader <br><br>

By the end of this series ,you will  gain necessary knowledge to analyze PE file headers and structures, so that when you face any technique utilizing PE headers ,it will be easy to point it out
<br><br>


## What are PE files to begin with

It is the standard file format for executables, object code, and dynamic-link libraries (DLLs) in 32-bit and 64-bit Windows operating systems  <br><br>In other words ,thats the file structure that the  windows loader can understand and parse 

```Examples of PE files are executables (.exe) ,msc files  and Dynamic link libraries DLLs```

But Why is this file format needed , cant the OS  just execute instructions and call it a day ?

PE file Structure contains all metadata that the Windows loader needs in order to map executables from disk format , to memory (**We will explain this mapping in a future blog**)  and doing other stuff like  knowing where global variables live ,fixing addresses when image base changes (**more on that in the relocations section blog later**) , section offsets ,and many other functionalities 

```TL;DR ,without this format ,executable files are just a sequence of bytes that cannot be executed or interpreted```


**This is a sample image of the PE file , so you can better imagine the topic ,keep it around ,we will reference it very often**<br><br>
![title](/resources/PEHeaderStrurcure.png)
<br>


**To not make this blog post to long ,we will focus on the first two headers which are  DOS Header  and the  DOS Stub :**


## DOS Header 

**Dos Header** , or as frequently mentioned in windows documentation **IMAGE_DOS_HEADER** ,is the first header in the PE File ,it contains only few relevant information to us : 

```
_IMAGE_DOS_HEADER{
   +0x000 e_magic          : Uint2B //This field
   +0x002 e_cblp           : Uint2B
   +0x004 e_cp             : Uint2B
   +0x006 e_crlc           : Uint2B
   +0x008 e_cparhdr        : Uint2B
   +0x00a e_minalloc       : Uint2B
   +0x00c e_maxalloc       : Uint2B
   +0x00e e_ss             : Uint2B
   +0x010 e_sp             : Uint2B
   +0x012 e_csum           : Uint2B
   +0x014 e_ip             : Uint2B
   +0x016 e_cs             : Uint2B
   +0x018 e_lfarlc         : Uint2B
   +0x01a e_ovno           : Uint2B
   +0x01c e_res            : [4] Uint2B
   +0x024 e_oemid          : Uint2B
   +0x026 e_oeminfo        : Uint2B
   +0x028 e_res2           : [10] Uint2B
   +0x03c e_lfanew         : Int4B      //and this field

}
```

1.The first field that is important to us is  ```e_magic``` , this field always have the value  ```MZ or  4d 5a (in hex ,little endian) ``` ,this field just tells the OS loader that this is a PE file ,so it can prepare necessary loader routines

**Offset: +0x0 from the start of the image**<br><br>
```Side note :MZ are the initials of Mark Zbikowski, one of the leading developers of MS-DOS```<br><br>

**Importance of this field :** Any time you are analyzing a malware ,or looking at  a memory dump ,and noticed the string MZ  , immediately recognize that this is an executable

**Usually ,malware hides embedded executables ,so if you see an MZ string in a memory view or dump ,that should take immediate attention from you , as it may precede an injection or dropping behavior**
<Br><br>
2. The second field of interest ,is  ```e_lfanew```  , this weird named field is important ,because it  gives us an offset to another important header (**which we will explain in the next blog**) which is the PE header , ```As it starts with   PE string``` <br><br>

**Offset: +0x3c from the start of the image**<br><br>



## DOS Stub 

**Dos Stub** , or as frequently mentioned in windows documentation **IMAGE_DOS_STUB** ,which is a small header that is only found for backwards compatibility with old **DOS systems** 

It only contains the string  **This Program cannot be run in DOS mode !!** ,however  it might contain any other data/string instead of that ,and the binary will function normally


**Note :** You can literally hide anything , such as an encoded C2 domain address  in this header ,but that will be more exposing than the benefit it could give to the attackers (No **This program cannot be run in DOS mode** will draw immediate attention)

![title](/resources/imageDosStub.png)



## Tools you might need :

There are many popular tools that are used to parse PE headers ,from my experience the best tools are the following:

1.PE bear by hasherezade  , link : [PE bear by hasherezade](https://github.com/hasherezade/pe-bear) ,it is a free  ,frequently updated Open source tool <br><br>
2.PE studio  ,which also parses PE headers in a neat way ,and provide other insights that will help in basic malware triage  , link :[PE studio by Marc Ochsenmeier](https://www.winitor.com/download)

I will be using the free trial of another popular tool **010 editor** throughout this blog ,due to its visual appearance and structure colorizing  ,link : [010 editor](https://www.sweetscape.com/010editor/)

We might also use  WinDbg to get structure layouts and offsets,<bR>
to get any structure layout ,type the following command :
```dt  structure_name  <optional memory offset to apply the structure on it>```
<br><br>

**And as a  task**, try to open any executable file ,and practice what we have learned ,practice finding PE start from e_lfanew , and other stuff .The more you practice ,the more PE headers look more familiar and easy to you


**That's it for todays blog ,see you in the next one**

