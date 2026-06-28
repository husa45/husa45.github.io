---
title: "PE file headers analysis mastery series , part 2"
date: 2026-06-26 17:03:30 +0300
categories: [malware analysis, PE file structure] 
tags: [misc,malware]
---

In the previous blog post ,we have discussed about the first two headers in the PE file ```IMAGE DOS HEADER and IMAGE DOS STUB``` .In this blog post ,we are going to dissect the most important header so far , the PE header

As a reference ,see the image below which will help you better understand the file structure as we progress

![title](/resources/PEHeaderStrurcureModified1.png)

## The PE header 
PE header , or as it is  mentioned in the documentation ```IMAGE_NT_HEADERS``` , contains crucial information needed by the loader during executable mapping process

It has the following structure :
```
struct _IMAGE_NT_HEADERS
{
  DWORD Signature;
  IMAGE_FILE_HEADER FileHeader;
  IMAGE_OPTIONAL_HEADER32 OptionalHeader;
};
```
Starting with field ```signature``` ,  this field always have the value 0x4550 (in little endian) ,which corresponds to ```PE``` in ASCII encoding .Thus ,giving this header it's name ```PE header```

This header is  reached by reading ```IMAGE_DOS_HEADER.e_lfanew``` and adding it to the image base address

**Formula :** ```PE offset=IMAGE_DOS_HEADER.e_lfanew + image base address```

![Pe signature image](/resources/PeSignature.png)


The second field in ```IMAGE_NT_HEADERS``` is the file header , aka ```IMAGE_FILE_HEADER```

it has the following structure :

```
struct _IMAGE_FILE_HEADER
{
  WORD Machine;
  WORD NumberOfSections;
  DWORD TimeDateStamp;
  DWORD PointerToSymbolTable;
  DWORD NumberOfSymbols;
  WORD SizeOfOptionalHeader;
  WORD Characteristics;
};
```
The ```Machine``` field indicates the architecture that this binary is supposed to work on . A value of ```0x14C``` indicates 32 bit architecture and a value of ```0x8664``` indicates 64 bit architecture 

Moving on to ```NumberOfSections``` which is self explanatory , the number of sections in this binary , or more concisely , the number of entries in the ```IMAGE_SECTION_HEADERS``` table
<br>

```TimeDateStamp``` is another important field that indicates the actual date that this binary was compiled on . This value is commonly used in threat intelligence feeds , because it helps analysts create an approximate timeline for the malware campaigns

**However , this field can be changed easily with a simple hex editing tool , so it is not a definitive indicator**

The next field of interest is ```SizeOfOptionalHeader``` , which is the size of the next structure in the PE header , the ```IMAGE_OPTIONAL_HEADER```

**Note: This field is usually used by manual parsing techniques to get another offset to important structure ,which is the start of the Section table  , as follows :**

```Section table offset= PE offset + 0x18 <which is the size of PE signature 4 bytes ,and the File header 20 bytes> + IMAGE_FILE_HEADER.SizeOfOptionalHeader ```

Finally , the ```Characteristics``` field is just a bitmask .The most important bit to us is ```IMAGE_FILE_DLL``` , which is set to 1 in DLLs . This is the only bit that discriminates a DLL from an EXE  ,  the rest of the PE file is identical  

**If you are somehow lost in details , see the below picture which demonstrates the exact layout of IMAGE_NT_HEADERS , and it's relation to it's surrounding structures** 

![Overview sofar](/resources/SuperDimensional1.PNG)




## A misnamed header

As many other weird naming incidents made by windows , the ```IMAGE_OPTIONAL_HEADER``` is very far from being optional. In fact , it contains the bulk of the important metadata needed for correct loading and execution of the executable 

**Note: We will explain the most important fields in this header .You do not need to memorize anything , because eventually you will use your favorite tools to parse those fields. However , with time and experience , you will find yourself familiar with most fields**

The optional header has the following structure :
```
struct _IMAGE_OPTIONAL_HEADER
{
  WORD Magic;
  BYTE MajorLinkerVersion;
  BYTE MinorLinkerVersion;
  DWORD SizeOfCode;
  DWORD SizeOfInitializedData;
  DWORD SizeOfUninitializedData;
  DWORD AddressOfEntryPoint;
  DWORD BaseOfCode;
  DWORD BaseOfData;
  DWORD ImageBase;
  DWORD SectionAlignment;
  DWORD FileAlignment;
  WORD MajorOperatingSystemVersion;
  WORD MinorOperatingSystemVersion;
  WORD MajorImageVersion;
  WORD MinorImageVersion;
  WORD MajorSubsystemVersion;
  WORD MinorSubsystemVersion;
  DWORD Win32VersionValue;
  DWORD SizeOfImage;
  DWORD SizeOfHeaders;
  DWORD CheckSum;
  WORD Subsystem;
  WORD DllCharacteristics;
  DWORD SizeOfStackReserve;
  DWORD SizeOfStackCommit;
  DWORD SizeOfHeapReserve;
  DWORD SizeOfHeapCommit;
  DWORD LoaderFlags;
  DWORD NumberOfRvaAndSizes;
  IMAGE_DATA_DIRECTORY DataDirectory[16];
};
```

Starting with ```Magic```  field , which indicates whether it is a 64 bit PE ```0x20B``` or a 32 bit PE ```0x10B``` 

**Importance : You will see this header often referenced in multi-architectural loaders , which can load both 32 bit and 64 bit  binaries**

The ```AddressOfEntryPoint``` is the Relative virtual address RVA of the first instruction that is going to be executed by the loader 

**Important Note : An RVA is just an offset from the start of the image , since the image will not take it's preferable address every time (we will explain the reasons in the relocations blog) , windows can not trust absolute addresses (ie :0x1400050 , which is a direct address ,relying on the image taking base address 0x1400000).<br><br>
Thats why almost always , when you see an address mentioned in the headers , it is an RVA (which is just an offset) from the taken image base**

To get the real address in memory from the RVA

```Absolute address= RVA of the field + image base taken```


The next field of interest is ```ImageBase``` , which is the preferable address that the image wants to start at (the MZ header will start there) .



**For now , don't worry about ```SectionAlignment``` or ```FileAlignment``` , we will explain them deeply when discussing  in-disk versus in-memory executable layout**

Another two fields of interest are ```SizeOfImage``` and  ```SizeOfHeaders``` . The first one being the size of the whole executable , which equals ```the size of all headers + size of all sections``` . Conversely , ```SizeOfHeaders``` is only the size of the File headers , which is usually ```0x400```

See the below image for a demonstration :

![title](/resources/PEHeaderStrurcureModified2.png)

<br><br>

## Data directories
```IMAGE_DATA_DIRECTORY DataDirectory[16]``` is an array of 16 entries , each one is called a **DataDirectory** , each DataDirectory has the following structure : 

```
typedef struct _IMAGE_DATA_DIRECTORY {
  DWORD VirtualAddress;
  DWORD Size;
} IMAGE_DATA_DIRECTORY, *PIMAGE_DATA_DIRECTORY;
```
The ```VirtualAddress``` field is the RVA of the currently examined DataDirectory (which if we calculated the absolute address , every data directory will be in a certain section ,i.e: .text , .data , .idata etc.) , with size equals to ```Size```

But what is a data directory?
They are structures , located in image sections , that hold important Information for the loader .

**Each data directory holds certain type of information , i.e: how to resolve imports ,how to resolve exports ,how to apply relocations and so on** 

Let's take the  ```IMAGE_EXPORT_DIRECTORY``` , a frequently referenced directory . It holds all information necessary to locate exported functions , in order to resolve their pointers from the DLL , and store in the Import address table **IAT** of the binary  . That's how you can call an API like ```VirtualAllocEx``` without the need to statically link it's dll to your executable
 
So , in the optional header ,we have ```IMAGE_DATA_DIRECTORY DataDirectory[16]``` which the loader could use to locate every directory that it needs .By taking the ```VirtualAddress``` field , and adding it up to the ```ImageBaseAddress``` which was taken when the image was loaded


**It is noteworthy these directories have a certain order , as mentioned in the documentation  , check  in this [MSDN Documentation for the optional header](https://learn.microsoft.com/en-us/windows/win32/api/winnt/ns-winnt-image_optional_header32) article** 

**In Future posts , we will go over the most important directories for malware analysis , which are the imports ,exports , relocations and the security directories**
<br><br>

**That's it for this blog , see you on the next one**