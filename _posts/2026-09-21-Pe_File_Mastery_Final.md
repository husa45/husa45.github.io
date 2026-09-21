---
title: "PE file headers analysis mastery series , Capstone project"
date: 2026-09-21 14:00:30 +0300
categories: [malware analysis, PE file structure] 
tags: [misc,malware]
---

Hello everybody ,  this will be the final part of our series ***PE file headers analysis mastery series*** , where we will write a custom  **Reflective loader** . If you do not know what **reflective loading** is , it is just a custom implemented loader (similar to the one windows uses to load PE files) . **Reflective loading** is also a  **defense evasion** technique used by Threat-Actors to manually load a PE file in to memory , without leaving any disk-trace , minimizing forensics footprint , and making it harder to track telemetry  , since it was loaded **manually** .

To follow-up with this article , you can check the full source-code of this project repository [here](https://github.com/husa45/Malware-analysis/tree/main/MalwareAnalysisUtilities/ReflectiveLoader/ReflectiveLoader) .


We will go over each function as we progress in explaining each-step down the road .


## Universal Steps To build any Reflective Loader

The following steps are the key phases in writing a working reflective-loader : 

1.get a pointer to your  **Executable** or **DLL** that you want to load . This could be achieved in countless amount of ways , ex : embedded in ***.rsrc*** section , installed from the *C2* server  .


2.Map the file  from  disk-state  to Memory-state . Which just involves copying PE-headers to the memory , then mapping sections according to **SectionAllignment** (check [Part 6 of the series for more information](https://husa45.github.io/posts/Pe_File_Mastery_P3/) ).



3.Apply relocations if necessary (*if the image-base taken was not equal to the preferred-base*) .
check [Part 3 of the series for more information](https://husa45.github.io/posts/Pe_File_Mastery_P6/)


4.Resolve imports by filling the ***IAT*** table of each imported ***DLL*** . check [Part 4 of the series for more information](https://husa45.github.io/posts/Pe_File_Mastery_P4/)


5.Apply memory protections to each *section* . 


6.If the PE file to load is a ***DLL*** and you want to call a certain export , you should parse the *exports* data directory , and resolve the *export* pointer .

7.Find and call the entry point .

The above steps , if it is coded correclty , will gaurantee a successful manual loading of any PE file .


## Reflective loader implementation 

As you know , to understand any concept in IT in general , you should apply it .So , now we will explain the key aspects of a reflective loader  , utilizing [this](https://github.com/husa45/Malware-analysis/tree/main/MalwareAnalysisUtilities/ReflectiveLoader/ReflectiveLoader) project that i implemented to erlaborate concepts .




### Acquiring your image

In my implementation  , the PE is embedded as a resource in *.rsrc* section : 

```
//Getting the base of the embedded PE to reflectively load
embedded_executable_size= GetResourcePointer(&ptr_image);

QWORD  GetResourcePointer(LPVOID* rsrc_offset_out) {
	//Getting a handle to the resource
	HRSRC hRsrc = FindResourceW(NULL, MAKEINTRESOURCE(IDR_RCDATA1), RT_RCDATA);

	if (hRsrc == NULL) {
		DBGhelp(GetLastError());
		exit(1);
	}
	HGLOBAL hGlobal = LoadResource(NULL, hRsrc);

	if (hGlobal == NULL) {
		DBGhelp(GetLastError());
		exit(1);
	}
	//Getting the pointer to the resource start
	*rsrc_offset_out = LockResource(hGlobal);
	if (rsrc_offset_out == NULL) {
		DBGhelp(GetLastError());
		exit(1);
	}
	QWORD size = SizeofResource(NULL, hRsrc);
	if (size == 0) {
		DBGhelp(GetLastError());
		exit(1);
	}
	return size;
}


```

The snippet just locates and loads a resource with ID **IDR_RCDATA1** from the **.rsrc** section .



### Mapping to memory
 
```
//Mapping Headers and Sections to memory
MapImage((BYTE*)ptr_staging_memory, (BYTE*)ptr_image);

void MapImage(BYTE* ptr_staging_memory, BYTE* ptr_src_image) {

	//A.Mapping Headers
	memmove(ptr_staging_memory, ptr_src_image, sizeOfheaders);

	//Mapping sections from physical offset (disk layout) to VirtualOffset (Memory Layout)
	//Getting a pointer to the section table , which is right after the OptionalHeader
	sectionTable = (IMAGE_SECTION_HEADER*)((BYTE*)ntHeaders + 0x18 + ntHeaders->FileHeader.SizeOfOptionalHeader);
	QWORD sectionCount = ntHeaders->FileHeader.NumberOfSections;
	
	for (int i = 0;i < sectionCount;i++) {
		DWORD MinSize = (sectionTable[i].Misc.VirtualSize < sectionTable[i].SizeOfRawData) ? sectionTable[i].Misc.VirtualSize : sectionTable[i].SizeOfRawData;            //the loader takes the minimum of the two
		DWORD VirtualAddress = sectionTable[i].VirtualAddress, physicalOffset = sectionTable[i].PointerToRawData;

		memmove(ptr_staging_memory + VirtualAddress, ptr_src_image + physicalOffset, MinSize);


	}


	std::cout << "Finished Mapping the Image" << std::endl;
}
```

The above snippet  just  : 

A.Copy headers directly to memory (usually first 0x400) .

B.It maps every section from it's **RawOffset** to it's **VirtualAddress** . 


After the aforementioned chunk executes ,  we will have the following  : 

![Mapping from disk state to memory ](/resources/PeFileMapping.png)


**Note that overlays will not be mapped to memory**



### Applying relocations 

Now , if the image base taken was not equal to the **PreferredBase** in the PE file , we need to apply relocations to fix all **hardcoded** addresses

```
//Handle relocations if neccessary :
printf("Image base taken : 0x%llx\n", PreferredImageBaseAddress);
handleRelocations((BYTE*)ptr_staging_memory, (BYTE*)ptr_image);

void handleRelocations(BYTE*  ptr_staging_memory, BYTE* ptr_image) {
	//If the image base taken was the same as the preffered base , no need for relocations

	if ((QWORD)ptr_staging_memory == PreferredImageBaseAddress) {
		std::cout << "Image base have not changed , will not apply relocations" << std::endl;
		return;

	}
	//If the base taken was different , we will apply relocations
		QWORD relocations_offset= getDataDirectoryPhysicalOffset(IMAGE_DIRECTORY_ENTRY_BASERELOC); //Entry 5 in the data directories
		
		if (relocations_offset==0) {
			std::cerr << "Relocations must be applied, but relocations dir is not available , exitting !!!" << std::endl;
			exit(1);
		}
		QWORD section_size = DataDirArray[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size;

		QWORD temp = (QWORD)(relocations_offset+ptr_image), handled_size = 0;

		QWORD DELTA = *(QWORD*)ptr_staging_memory - PreferredImageBaseAddress; //DELTA = new-base - old-base

		QWORD new_base = *(QWORD*)ptr_staging_memory;

		while (true) {
			IMAGE_BASE_RELOCATION* block_header = (IMAGE_BASE_RELOCATION*)(temp);
			DWORD pageRva = block_header->VirtualAddress, Size = block_header->SizeOfBlock;

			DWORD array_size = (block_header->SizeOfBlock - 8) / 2;

			if (array_size) {

				WORD* relocations_array = (WORD*)(((BYTE*)block_header) + 8);

				for (int j = 0;j < array_size;j++) {

					switch ((relocations_array[j] >> 12) & 0xf) {

					case IMAGE_REL_BASED_HIGHLOW: //we are fixing relocations for 32 bit app
						*((DWORD*)new_base + pageRva + (relocations_array[j] & 0xfff)) += DELTA;

					case IMAGE_REL_BASED_DIR64://we are fixing relocations for 64 bit app
						*((QWORD*)new_base + pageRva + (relocations_array[j] & 0xfff)) += DELTA;

					}
				}
				//we have finished the block , moving to  the next : 
				handled_size += block_header->SizeOfBlock;
				if (handled_size > section_size) {
					break; //done fixing relocations for every page
				}

				temp += (block_header->SizeOfBlock);

			}




		}
		std::cout << "Finished handling relocations ........ " << std::endl;
```

The above snippet first reads the **.reloc** section from the **on-disk** PE (which is the same as our embedded PE , not the one we are loading) .

Next , it iterates over every block in **.reloc** section , and for every block (which handles relocartions for a certain page) , we enumerate all of it's needed-to-be-fixed  **relocation-entries** . For every offset inside the ```relocations_array``` , we determine the relocation type  , then apply it . To fully understand equations and calculations used here , refer to [this part](https://husa45.github.io/posts/Pe_File_Mastery_P6/).

Finally , after finishing each block , we move to the next one , untill finishing all blocks .



### Resolving imports 

Now , we need to resolve all imported functions : 

```
//Resolve imports and fill IAT  :
handleImports((BYTE*)ptr_staging_memory, (BYTE*)ptr_image);

void handleImports(BYTE *ptr_staging_memory, BYTE* ptr_image) {
	QWORD imports_offset = getDataDirectoryPhysicalOffset(IMAGE_DIRECTORY_ENTRY_IMPORT); //Entry 1 in the data directories

	if (imports_offset ==0) {
		std::cerr << "Relocations must be applied, but relocations dir is not available , exitting !!!" << std::endl;
		exit(1);
	}
	//Getting the array of IMAGE_IMPORT_DESCRIPTOR
	IMAGE_IMPORT_DESCRIPTOR* imports_dir = (IMAGE_IMPORT_DESCRIPTOR*)(imports_offset+ptr_image);

	//Iterating over each import block , to resolve imports for every dll:
	int i = 0;
	while (true) {
		if (imports_dir[i].Name == 0) { //no more blocks
			break;           
		}
		LPSTR dllName = (LPSTR)(getPhysicalOffset(imports_dir[i].Name) + ptr_image); //Dll name 
		
		if (dllName == NULL) {
			std::cerr << "Imports for the current entry can not be resolved  , skipping to  next one" << std::endl;
			continue;
		}
		HMODULE current_dll = LoadLibraryA(dllName);
		if (current_dll==NULL) {
			std::cerr << "Can not load the current iterating dll   , skipping to  next one" << std::endl;
			continue;
		}

		//resolving all imports of the current dll
		if (is64Bit) {
			QWORD resolved_func = NULL;
			QWORD* ILT = (QWORD*)(getPhysicalOffset(imports_dir[i].OriginalFirstThunk) + ptr_image); //from disk

			QWORD* IAT = (QWORD*)((imports_dir[i].FirstThunk) + ptr_staging_memory); //in memory
			int index = 0;
				for (QWORD* j = ILT;*j != NULL;j = j + 1,index++) {
				
					if (((*j) & 0x8000000000000000) != 0) { //if bit 63 is set,  this entry will resolve an ordinal
						WORD ordinal = (*j) & 0xffff;
					 resolved_func=(QWORD)GetProcAddress(current_dll, MAKEINTRESOURCEA(ordinal));
					}
					else { //this entry is an RVA ot IMAGE_NAME_TABLE
						DWORD image_name_RVA = (*j) & 0xffffffff;

						IMAGE_IMPORT_BY_NAME* hint_name_table= (IMAGE_IMPORT_BY_NAME*)(getPhysicalOffset(image_name_RVA) + ptr_image);
						
															//Must validate if name is not null
						resolved_func= (QWORD)GetProcAddress(current_dll,hint_name_table->Name);
					}
//fill in the corresponding entry in the IAT
					if (resolved_func)
						IAT[index] = resolved_func;
				}


		}
		else {
			DWORD resolved_func = NULL;
			DWORD* ILT = (DWORD*)(getPhysicalOffset(imports_dir[i].OriginalFirstThunk) + ptr_image);
			DWORD* IAT = (DWORD*)((imports_dir[i].FirstThunk) + ptr_staging_memory);
			int index = 0;
			for (DWORD* j = ILT;j != NULL;j = j + 1, index++) {
				if (((*j) & 0x80000000) != 0) { //if bit 63 is set,  this entry will resolve an ordinal
					WORD ordinal = (*j) & 0xffff;
					resolved_func = (DWORD)GetProcAddress(current_dll, MAKEINTRESOURCEA(ordinal));
				}
				else { //this entry is an RVA ot IMAGE_NAME_TABLE
					DWORD image_name_RVA = (*j) & 0xffffffff;
					IMAGE_IMPORT_BY_NAME* hint_name_table = (IMAGE_IMPORT_BY_NAME*)(getPhysicalOffset(image_name_RVA) + ptr_image);

					//Must validate if name is not null
					resolved_func = (DWORD)GetProcAddress(current_dll, hint_name_table->Name);
				}
				//fill in the corresponding entry in the IAT
				if (resolved_func)
					IAT[index] = resolved_func;
			}
		}
			i++;
	}

}

```

In this part , we will resolve imports by iterating over ```IMAGE_IMPORT_DESCRIPTOR``` array , where each block must handle **imports** for a certain dll . But before doing any import resolving  , we will use **LoadLibraryA** to load the **DLL**  , so we can resolve it's exports to get our imports .



Note that we have two versions  , one for ***32 bit*** and one for ***64 bit*** , the only difference is the **size** of each entry in  **ILT/INT Image Name/Lookup table** . In ***64 bit*** ,  each entry is 64 bit , in ***32 bit*** , 32 bit . Also the size of resolved pointer differs in the same manner .


To resolve an import , we begin iterating over **OriginalFirstThunk** array for each **IMAGE_IMPORT_DESCRIPTOR** , which contains **ordinals/names** of functions to resolve . 

Each entry in the  **ILT** have the following structure :

```
if bit 31/63 is set ----> the first 16 bits are an ordinal , no name

else : The first 32 bits will always be an RVA  (whether in 64 or 32 bit) to IMAGE_IMPORT_BY_NAME .So ,resolving using function name 


```


Finally , using **GetProcAddress** to resolve the function pointer , either by **Name** or **Ordinal** .Then  , we place each pointer in the **corresponding** entry in the **IAT** . *Remmember that IAT and ILT are parallel arrays* .



<br>

**Before** Resolving imports , **IAT** and **ILT** will look as following : 

![before resolving imports](/resources/pepart4_resources/iat_int_same.png)


**After** Resolving imports , **IAT** and **ILT** will look as following : 

![after resolving imports](/resources/pepart4_resources/iat_int_loaded.png)



### Protections  , why do we need them 

Every section should have a certain memory protection , conforming with it's **Functionality** . For Example , the **.text** section must be executable , the **.rdata** must be read-only  , and so on .

Applying memory protections is very easily done with **VirtualProtect/Ex** API , or using it's native API counterpart **NtProtectVirtualMemory**

But , before applying protections blindly , we need to get the necessary **protection** for every section , and that is done by reading **IMAGE_SECTION_HEADER.Characteristics** field , especially the last three bits , which represents ```IMAGE_SCN_MEM_EXECUTE```  , ```IMAGE_SCN_MEM_READ```   and ```IMAGE_SCN_MEM_WRITE``` respectively (from bit at positiion 29 to 31 respectively).

```

//Fix memory protections
fixSections((BYTE*)ptr_staging_memory, (BYTE*)ptr_image);


void fixSections(BYTE* ptr_staging_memory, BYTE* ptr_src_image) {
	/*from  Characteristics field of every section, the last 3 bits define the  Memory Protection  combo of this section
	From those three bits,  we have  8 possible Memory protections
	*/
	DWORD MemProtection = 0;

	QWORD sectionCount = ntHeaders->FileHeader.NumberOfSections;

	for (int i = 0;i < sectionCount;i++) {
		DWORD charachteristics = sectionTable[i].Characteristics;

		if ((charachteristics & 0x80000000) !=0) {
			if ((charachteristics & 0x40000000) != 0) {//it is gauranteed to be readable writable
				
				if ((charachteristics & 0x20000000) != 0) {//it is gauranteed to be readable writable executable
					MemProtection = PAGE_EXECUTE_READWRITE;
				}
				else {
					MemProtection = PAGE_READWRITE;
				}
			}
			else { //Write only or execute read write
				if ((charachteristics & 0x20000000) != 0)
					MemProtection = PAGE_EXECUTE_WRITECOPY;
				else
					MemProtection = PAGE_WRITECOPY;
					

			}
		}

		else {  //not writable at all , checking readblility and executability
			if ((charachteristics & 0x40000000) != 0) { //readbale gauranteed

				if ((charachteristics & 0x20000000) != 0)
					MemProtection = PAGE_EXECUTE_READ;

				else
					MemProtection = PAGE_READONLY;
			}
			else{ //not readable and not writable , maybe executable only
				if ((charachteristics & 0x20000000) != 0)
				MemProtection = PAGE_EXECUTE;
				else
					MemProtection = PAGE_NOACCESS;

			}


		}

		//Applying protection
		DWORD old = 0;
		if (!VirtualProtect((LPVOID)(QWORD *)(ptr_staging_memory + sectionTable[i].VirtualAddress), sectionTable[i].Misc.VirtualSize, MemProtection, &old)) {
			DBGhelp(GetLastError());
				exit(1);
		}

	}

}
```

The above snippet might look intimidating , but it just  parses **MemoryProtections** combinations . 

To check if ```IMAGE_SCN_MEM_WRITE``` is set , we use bit mask ```0x80000000``` which isolates bit 31 . To check if ```IMAGE_SCN_MEM_READ``` is set , we use bit mask ```0x40000000``` which isolates bit 30 .  To check if ```IMAGE_SCN_MEM_READ``` is set , we use bit mask ```0x20000000``` which isolates bit 29 .


Then we use this bitmasks to get **MemoryProtection combinations** . For example , the section might have ```IMAGE_SCN_MEM_WRITE``` and ```IMAGE_SCN_MEM_READ``` set , in this case it will have **PAGE_READWRITE** protection .It might have only ```IMAGE_SCN_MEM_READ``` , which means it have **PAGE_READONLY** as a Protection , and so on .
<br>

> Check [MSDN](https://learn.microsoft.com/en-us/windows/win32/memory/memory-protection-constants) to learn about all available memory-protections out there .

<br><br>

### Finding Entry point , and starting the execution 

Now , our binary is fully loaded , and we can proceed with calling the **EntryPoint** to start execution :

```
QWORD (*EntryPoint)() = (QWORD (*)())(EntryPointRva + (BYTE*)ptr_staging_memory);
EntryPoint();
```

We just read **IMAGE_OPTIONAL_HEADER.AddressOFEntryPoint** and added it to **ImageBase** to reach to the entry point in **memory** .


### Execution demo

I wrote a sample **POC** to test whether our code is working as expected  or not  :

```
#include<windows.h>
#include<iostream>
DWORD WINAPI threadRoutine() {
	wchar_t str[] = L"Reflective Loading succeed!!!";
	MessageBoxW(NULL, str, L"Bishop-444", MB_ICONINFORMATION);
	return 0;
}
int main(void) {
	HANDLE hthread;
	DWORD threadid;
	CreateThread(0, 0, (LPTHREAD_START_ROUTINE)threadRoutine, NULL, 0, 0);
	//message loop to keep the program alive:
	tagMSG msg;
	while (GetMessage(&msg, NULL, 0, 0) > 0) {
		if (TranslateMessage(&msg) == 0) {
			break;
		}
		DispatchMessageW(&msg);

	}

}
```

It just Creates a thread to show a message box , and wait indefinetly using a **MessageLoop** 


![POC](/resources/POC.gif)




**It worked !!!!!!!!!!!**


## Closing Notes 


1.This is a  basic ***working*** reflective loader POC , but it is not a **fit-for-all** code . For example , if you have 
***TLScallbacks*** you need to call them on by one before jumping to the ***EntryPoint*** . Also , if you are reflectively loading a **DLL** , you might need to parse it's **exports** .

For ***TLScallbacks*** , the project already covers it , but for ***exports*** handling , i might add support in future commits . Take it as an exercise to test your overall knowledge .


2.For ***.NET assemblies***  ,the discussed approach will not work at all , since ***.NET assemblies*** are managed code , and are executed and loaded by the ***.CLR***  , with minimal intervention from windows loader . 




<br><br><br><br>

**If you followed this series patiently , practiced and took notes , you will be equipped with a deep understanding of the PE file structure and you will be able to handle techniques that abuses it effectively .**


And by that , we are officially done with our ***PE file headers analysis mastery series*** , if you have any notes about current articles or suggestions for future ones , do not hesitate to contact me and convey your ideas .
<br><br>


> Rememmber , The best way to understand any concept  is practice . For any malware sample or crackme that you analyze from now on , take a look at PE file headers using your favorite tool , by time , you will be very familiar with all ins and outs of it . You might also consider to do some projects like reimplementing your own reflective loader  , or writing a simple PE file parser .





