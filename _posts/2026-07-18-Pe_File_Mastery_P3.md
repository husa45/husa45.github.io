---
title: "PE file headers analysis mastery series , part 3"
date: 2026-07-18 20:30:30 +0300
categories: [malware analysis, PE file structure] 
tags: [misc,malware]
---

In Previous blog posts , we have covered important headers in the PE file . we have so far discussed  the ```DOS header``` , ```DOS stub header``` , ```NT header``` and it's sub-headers ```FILE``` and ```OPTIONAL``` headers

In this blog post , we are going to end our tour discussing the headers of the ```PE``` file . We will elaborate the final structure of the PE headers , which is the ```IMAGE_SECTION_HEADERS``` table .<br>In future posts , we will continue the sequel discussing the ```DATA DIRECTORIES``` structures , and how they relate to common techniques we see in malware


As always , to help you bring the pieces together and don't get lost , here is an image that dictates our current area of coverage in the file structure 

![title](/resources/PEHeaderStrurcureModified3.png)


In order to have full understanding of the ```IMAGE_SECTION_HEADERS``` table , and it's role in the executable loading process , we need to answer the following questions .<br>

Is there a difference between the executable on memory and on disk , and if so , how is the executable moved to the process memory , in a form that could be executed ?

## Memory mapping of the executable files
For simplicity , we can say that memory mapping is traced back to two fields , residing in the ```IMAGE_OPTIONAL_HEADER``` , which are ```SectionAllignment``` and ```FileAllignment```

The ```FileAllignment``` requirement dictates the following :

### File allignment
**The executable file sections must start at address which is multiple of the drive sector size , so , when the OS reads or writes to the file , the access is in the  multiples of sectors (one , two ,three sectors and so on) , not partial access , which is usually slower**


This means that on disk , the executable section offsets will be usually in multiples of the ```sector size``` (which is usually 512 byte , or 0x200 in hex)

This also means that if the section ended up having let's say one and half sector of size , the next section cannot start at the half , so a padding of zero will be filled , to enusre the next section starts at the next sector allignment

If the above looks somewhat cryptic , see the below image for clearer understanding


![file allignment](/resources/FileAllign.png)

Notice how each section starts at multiple of ```0x200``` 

```Section Table``` starts at 0x200 , ```.text``` section starts at ```0x400``` , ```.data``` starts at ```0x3DC00``` (which is a multiple of 0x200)


### Section allignment

The name is misleading somewhat **(in the end it is all about alligning sections , whether on disk or in memory)**
so memorize it as ```Memory allignment```

In order to ease up memory management , modern OSes divide the memory (whether physical or virtual) into small building units called ```Memory Pages```

This design is amazing , since it  facilitates  many operations , like 
**applying memory protections** . If you have done any malware investigation before , you probably encountered a ```Memory Page``` that is readable ,writable , executable , or a mix of those (like PAGE_EXECUTE_READWRITE) 

This design also makes it easier to manage and map virtual memory to physical memory <br>

**If you do not know the difference between virtual and physical memory , check the resources at the end of the article**

For the purposes of this demonstration , just imagine that the executable memory that you are debugging , is divided into small areas called ```Pages```

How paging looks

![A picture showing how virtual and physical memory is paged](/resources/Paging.jpg)


**But what does that have to do with the loading process ?**

Using the same logic we used for the previous explanation , every section must start at the mutiples of ```SectionAllignment``` , which is intentionally equal to the ```Page``` size , which is in most OSes ```0x1000``` or ```4096``` byte in decimal

TL;DR : **Every section must begin at the start of a page , not somewhere else**

So , using the image we used  before  , the ```.text``` section cannot start at ```0x400``` in the memory , since ```0x400``` is not a start of a page .

It will usually start at the next page , at offset ```0x1000``` 

And that applies for all sections . So , if a section does not end at the ```Page``` end , the rest of the space is filled zeros , in order for the next section to start at the ```Page``` offset


This is where the ```Memory Mapping``` Process takes place



The loader cannot load the executable into the memory as you would load a file , no , it has to ```Map``` it first

```Mapping``` the executable means copying every section from their ```Physical``` offset , to their ```Virtual``` Offset , which is dictated for every section in the corresponding entry in ```IMAGE_SECTION_HEADERS``` table . Eventually , satisfying memory allignment requirements

see the below image for a visualization

![Image showing how images are mapped](/resources/PeFileMapping.png)

**Note : The padding is usally zeros**

**Note : If there is an overlay (appended data) , it will not be mapped to the Memory**

The PE file is a few steps left from being fully functional . We will discuss those steps in future blogs in this series (**remmember that we are going to build our custom PE loader**)


# Section table

The section table is just a table (array) of ```IMAGE_SECTION_HEADER``` structures

The Section table contains an ```IMAGE_SECTION_HEADER``` for every section in the PE file 

The ```IMAGE_SECTION_HEADER``` structure contains every needed detail that will help the windows loader  **map** the section from disk-state to memory

Here is it's layout :

```
typedef struct _IMAGE_SECTION_HEADER {
  BYTE  Name[IMAGE_SIZEOF_SHORT_NAME];
  union {
    DWORD PhysicalAddress;
    DWORD VirtualSize;
  } Misc;
  DWORD VirtualAddress;
  DWORD SizeOfRawData;
  DWORD PointerToRawData;
  DWORD PointerToRelocations;
  DWORD PointerToLinenumbers;
  WORD  NumberOfRelocations;
  WORD  NumberOfLinenumbers;
  DWORD Characteristics;
} IMAGE_SECTION_HEADER, *PIMAGE_SECTION_HEADER;
```

The first field of importance is the ```Name``` field , which just declares the name of the section . For example , ```.text``` ```.rdata``` ```.data``` ```.reloc``` 

The next field is a union , usually both of it's fields ```PhysicalAddress``` and ```VirtualSize``` have the same value , and it is the Virtual Size of the section when mapped to memory 

```VirtualAddress``` field is the RVA (relative virtual address) of the section when mapped to memory .

**we have explained RVAs in detail in the previous blog , but for now , it is just the relative , not direct virtual address , add it to the ```image base``` to get the real offset in memory**


If you used your favorite parsing tool , you will always notice that the ```VirtualAddress``` field is of multiples of 0x1000 . For example , ```.text``` section starts at ```0x1000``` , next the ```.rdata``` section starts at ```0x7A000``` , which is also a multiple  of **0x1000** . Remmember that sections in memory must be alligned to ```SectionAllignment``` also called ```Page``` allignment , which is usually **0x1000**


Moving on to ```PointerToRawData``` and ```SizeOfRawData``` . The first one is the offset of the section in the disk-state (if you parse an executable using any tool , this is where the section will start)

We also notice that ```PointerTorRawData``` is of multiples of the ```FileAllignment``` , which is **0x200**

For example ,the ```.text``` starts at ```0x400``` , and the next section ```.rdata```  starts at  ```0x1c000``` and so on

The ```SizeOfRawData``` is self-explanatory , which is the size of section on disk



The last field to take a look at is the  ```Characteristics``` field , which is a bit-mask that contains all of the section properties and ```memory protections```


We will focus on bits 29-31 , which dictates ```memory protection``` of the section

Bit 29 indicates whether it is executable or not ,bit 30 is for readable  , and bit 31 is for writable protections


For example , if all bits are set we will get ```PAGE_EXECUTE_READWRITE``` . If only bit 29 and 30 are set we get ```PAGE_EXECUTE_READ``` and so forth


## Key assumptions about sections

1. The ```.text``` section holds the executable instruction ```opcodes``` . It is usually ```PAGE_EXECUTE_READ```


2. The ```.rdata``` contains the programs global , read-only data (static and global variables) . It is usually ```PAGE_READONLY```

3. The ```.data``` section contains the programs global , readable-writable data (static and global variables) . It is usally ```PAGE_READWRITE```

4. The ```.reloc``` section usually hold the relocation information (we will discuss relocations when we explain to **Data Directories**)

5. The ```.rsrc``` section is a very important section . This section holds all executable resources , arranged as a ```binary tree``

  It conatins icons , font descriptions , manifest , media resources like audio , and string resources

  It is important because the attacker can hide any form of data inside the ```resources``` . It could hide entire executables , which it will extract and drop .

  **As a bonus tip , you can parse resources using a powerfull tool called ```resource hacker```**



## Final notes 

When you parse more and more PE files , you will notice that the ```SizeOfrawData``` is usually smaller than ```VirtualSize``` . This is due to the fact that  ```Memory Allignment``` requirements are bigger than ```Disk allignment``` , which means more padding will be done to allign sections in memory

We have also mentioned the default protections for sections , as seeing them changed is a malicious sign. Usually a self modifying malware like ```packed``` malware will have , for example , the ```.text``` section writable (it will unpack the binary to this section) .<br><br>



So far ,We noticed that almost all information provided in the PE fields are **RVAs** , so how can we convert them to a physical offset , so we can see them actively in parsers?

First , you need to find the section it belongs to . Just walk over the ```VirtualAddress``` field of every ```IMAGE_SECTOIN_HEADER```  , until you find the section that contains this RVA 

Now , just use this euqation

```Physical offset =(filed_RVA-section_RVA)+ PointerToRawData``` of the section

For instance , if we have the **imports** directory RVA of ```0xA4398``` .We walk the section table and see that ```.idata``` section , with RVA ```0xA4000``` contains this structure .

Now we get the physical offset  :

```Physcial offset= (0xA4398-A4000)+0x9FA00 (which is pointer to raw data of the same section)``` , we get ```0x9FD98``` 



**That's it for this post , hope to see you in the next one**


## resources

[Virtual Address spaces , by MSDN ](http://example.com)

[Memory Protection in windows , by MSDN](https://learn.microsoft.com/en-us/windows/win32/memory/memory-protection)

[Image Section Header , by MSDN](https://learn.microsoft.com/en-us/windows/win32/api/winnt/ns-winnt-image_section_header)



























