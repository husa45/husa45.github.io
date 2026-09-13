---
title: "PE file headers analysis mastery series , part 6"
date: 2026-09-13 20:00:30 +0300
categories: [malware analysis, PE file structure] 
tags: [misc,malware]
---

We have come a long way so far  in this series , we have discussed important concepts like   the general PE file structure , section headers , import and export resolving  and many other important topics .

But as they say , for every beginning there is an end , so this is going to be our final station in our glorious PE file structure tour . In this article we are going to discuss and simplify one of the most confusing topics about the PE file , which is the relocations .

To be fully honest , this is not the entire PE file structure , there are still some structures that we have not discussed , like  CodeSigning and where does the signing certificate reside , ``exceptions`` dir ,  ``resources``   and others . But , we have covered the most important structures which you will face day to day in your malware analysis studies . For other structures  , we might cover them in future blogs . They are relatively rare to deal with , and even if you faced them , a simple documentation lookup will be enough .

To ignite our discussion of this blog , what are ``relocations`` , and why they are needed ?


## The main problem 

When the compiler compiles  the source code , many  referenced addresses are ```hardcoded``` into the binary  . But , what is the problem with hardcoding ? 

Those addresses are hardcoded depending on the **Preferred Image Base** address . I think you guessed what happens when the  **Image Base** changes , All these hardcoded addresses break .

To illustrate that better , assume we have a  ```call 0x14000113c``` . The ``call`` target is based on the preffered **image base** ```0x140000000``` , so , if for some reason , the **image base** taken at runtime was not the same as the **preferred base** , this address is no longer valid . Assume the taken **image base** is ``0x7f00000000000000`` , address ``0x14000113c`` is not meaningfull any more . 

If the CPU now tried to access ``0x14000113c`` , it will raise ```Access violation exception : 0xC0000005``` . So , all these hardcoded addresses need to be fixed by the ``loader`` during runtime , to be compatible with the new **image base**  , this process is called ``relocation`` . 


Now , before digging into how ``relocations`` are applied , you might ask yourself , what are the usual **preferred** addresses   , and why they might not be taken during runtime . 

For 32 bit applications ,  the preferred addresses for ```.exe```  and ```.dll```  are as follows:

A.For ```.exe``` , the usual preferred base is : ````0x400000```` 

B.For ```.dll``` , the usual preferred base is : ````0x10000000```` 

For 64 bit applications ,  the preferred addresses for ```.exe```  and ```.dll```  are as follows:

A.For ```.exe``` , the usual preferred base is : ````0x140000000```` 

B.For ```.dll``` , the usual preferred base is : ````0x180000000```` 


Now , why would the loader not take this base , causing **relocations**  to be necessary ?

1.A protection mehcanism called ```Address Space Layout Randomization``` , ```ASLR``` for short . In a nutshell , if all addresses are fixed across program runs , attackers can do their calculations  , to land their exploit ```shellcode``` at a fixed location everytime ,  this made exploitation easier . But with ```ASLR``` , the **image base** taken every time the program runs is different , making static calculations for adversaries harder , and thus , exploitation less fruitful . Check this [wiki article](https://en.wikipedia.org/wiki/Address_space_layout_randomization) for more information about this topic . 

2.Sometimes , the loader tries to load a certain ```dll``` at it's preferred base , but this address is already occupied by another ```dll``` .Here , the loader will take another image base , and this is called  ```rebasing``` .


## Relocations and how they are applied


In the ```OptionalHeader.DataDirArr[5]``` we have the ```IMAGE_DIRECTORY_ENTRY_BASERELOC``` data directory . 

If we take the ```OptionalHeader.DataDirArr[5].RVA``` and added it to  the **image base** , we will reach to ```.reloc``` section , which is a section that holds all information needed by the ``loader`` to apply ``relocations`` . This section has size of ```OptionalHeader.DataDirArr[5].Size``` .


The section has the following structure : 

![relocation section structure](/resources/pepart6_resources/relocation_structure.png)




The ```.reloc``` section is composed of one or more ```32 bit alligned``` blocks of the following form : 

**Block Start :**

 ```IMAGE_BASE_RELOCATION``` structure , with the following layout :

```
typedef struct _IMAGE_BASE_RELOCATION {
    DWORD   VirtualAddress;
    DWORD   SizeOfBlock;
} IMAGE_BASE_RELOCATION;
typedef IMAGE_BASE_RELOCATION UNALIGNED * PIMAGE_BASE_RELOCATION;
```

``VirtualAddress`` field is the RVA to the memory page  whose relocations will be fixed by this ``block`` (Relocations are organzied to be handled page by page ).

```SizeOfBlock``` is the size of the entire block , including the ```_IMAGE_BASE_RELOCATION``` header .
<br>


**Block body :**
<br>
After this ```_IMAGE_BASE_RELOCATION``` , we have an array of ``two`` byte entries , where each entry will fix a certain address.

Every relocation entry in this array is a ```WORD``` (2 bytes) , with the following form :

```[upper four bits <relocation type> | lower 12 bits <the offset of the address to fix>]```


For the ```relocation type``` , there are many types , but we will focus on the two most used types :

```IMAGE_REL_BASED_HIGHLOW``` : The 12 bits offset is to fix a 32 bit pointer  .

```IMAGE_REL_BASED_DIR64``` : The 12 bits offset is to fix a 64 bit pointer .



**To sum up** , the ```.reloc``` section is the section holding all info to apply relocations .It is composed of one or more blocks , where each block will fix  all addresses in the ```PAGE``` that this block handles :

```Block : [RVA of the page to fix || size of block ||  array of offsets that needs fixing in this Page]```


**Note :** The number of entries in the array is : ```(BlockSize-8)/2``` (8 to exclude the ``_IMAGE_BASE_RELOCATION`` header , and divide by two since every array element is 2 bytes ).


## Applying relocations  

To demonstrate the process of relocation fixing , we will be using the following CPP code : 

```
//relocation_section_offset=IMAGE_OPTIONAL_HEADER.DataDirArr[5].RVA + imagebase
//section_size=IMAGE_OPTIONAL_HEADER.DataDirArr[5].Size
void WINAPI WalkRelocations(PBYTE relocation_section_offset,DWORD section_size,DWORD DELTA,DWORD new_base) {
	BYTE* temp = relocation_section_offset;
	DWORD handled_size = 0;
	while (true) {
		IMAGE_BASE_RELOCATION* block_header = (IMAGE_BASE_RELOCATION*)(relocation_section_offset);
		DWORD pageRva = block_header->VirtualAddress, Size=block_header->SizeOfBlock;

		DWORD array_size = (block_header->SizeOfBlock - 8) / 2; //explained above

		if (array_size) {

			WORD* relocations_array = (WORD *)(((BYTE*)block_header) + 8);

			for (int j = 0;j < array_size;j++) {
				
				switch ((relocations_array[j] >> 12)&0xf) {

				case IMAGE_REL_BASED_HIGHLOW: //we are fixing relocations for 32 bit app
					*((DWORD*)new_base+pageRva+ (relocations_array[j]&0xfff)) += DELTA;

				case IMAGE_REL_BASED_DIR64://we are fixing relocations for 64 bit app
					*((DWORDLONG *)new_base + pageRva + (relocations_array[j] & 0xfff)) += DELTA;

				}
			}
			//we have finished the block , moving to  the next : 
			handled_size += block_header->SizeOfBlock;
			if (handled_size > section_size) {
				break; //done fixing relocations for every page
			}

			relocation_section_offset += (block_header->SizeOfBlock);
			
		}




	}
```
<br>
I think the code is self-descriptive , so we are going to highlight the main steps in the algorithm (assuming we have the start of the ```.reloc``` section) : 


1.For every block , iterate over it's ``relocations`` WORD array .

2.Check the type of the relocation , then for the two types of the relocation do the same following  : 

```
A.Get the address of the pointer that we want to fix  :

fix-address = (new-image-base + Page RVA) //now we reached the page offset according to the new base 

fix-address += (relocations_array[j] & 0xfff <The relocation offset>) //by this , we reach the correct destination

B.Now we have the pointer address , we will do the same for 64 bit and 32 bit , but with differences in  pointer size :

new-fixed-address = old-fixed-address + DELTA //where DELTA is  new-base-old-base
```

And we repeat that  , for every block , untill we fix-relocations for all pages . 


**Example :** Assuming ```call 0x14000113c``` needs fixing for the call destination 

Given the old base : ``0x140000000`` , new base : ```0x530000000``` , and PageRva in the block is ```0x1000``` , and one entry in the relocations array is ```0xa13c``` : 

```
new-offset = 0x530000000 + 0x1000 //result is 0x530001000

new-offset += 0x13c (ignored 0xa , it is the relocation type)

*(DWORDLONG *)new-offset += (0x530000000-0x140000000)  //which equals 92000113C
```

Now , the fixed call became ```call 0x92000113C``` .


## Final notes 

1.The ```.reloc```section will have relocation info only for ```pages``` that have addresses which needs fixing .So , Not all of  pages in the program address space will have a relocations block in the ``.reloc`` section .

2.The ```.reloc``` is not filled randomly , it is filled based on what needs fixing , For example : if ```0x14000113c``` needs fixing , then the loader : Create a block for Page at offset ``0x1000`` if not created ----> in it's block relocations array , place  ```0xa13c``` as an entry (the upper 0xa for relocation type).

3.Relocations are only applied if the ```image base``` changes , if it does not change , **no** relocations are applied . 
This means that if you set ```IMAGE_OPTIONAL_HEADER.Characteresitcs.DLL_CAN_MOVE to 0``` (which effictevely disables ```ASLR```) , ```.reloc``` section is not needed anymore .


<br><br>


**And by that our series will cease to end , i enjoyed every bit of time spent writing the blogs , hope you all benifeted from it . If you have any notes , make sure to ping me on on of the socials appearing on the page .Happy reversing  !!!**

I have not forgot about the ``reflective`` loader project that i promised at the debut of the series , so next blog will be the sequel to this series  , where we will build a custom pseudo-loder , similar to the one usually used by malware to execute their malware **in-memory** , without every touching the disk .


## Resources 

1.A magnificant hands-on tutorial , by ```Elias Bachaalany , AKA all-things IDA``` on relocations and their practice using **IDA** : [
Understanding the PE+ file format - Part 5: Relocation table](https://youtu.be/36Ncv-SMmI4)

2.Relocations documentation : [Relocations MSDN](https://learn.microsoft.com/en-us/windows/win32/debug/pe-format#the-reloc-section-image-only)





