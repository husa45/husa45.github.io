---
title: "PE file headers analysis mastery series , part 4"
date: 2026-08-06 20:46:30 +0300
categories: [malware analysis, PE file structure] 
tags: [misc,malware]
---

## Data Directories
If you can recall our discussion about  the **optional headers** , you will surely remember the **data directories** array at the end of the header

![data directories array](/resources/pepart4_resources/data_directories_array.png)

The image above demonstrates the data directory array

Notice that it is an array of ```IMAGE_DATA_DIRECTORY``` , which is like an indexer for each data directory available in the binary

It has the following structure : 
```
IMAGE_DATA_DIRECTORY{
DWORD  VirtualAddress;
DWORD Size;
}
```

But , what is a data directory ? They are structures further down in the sections , that contain important inforamtion needed by the windows loader to load and execute the binary . For instance  , the **imports** , **exports** and **relocations** info are all data directories


In the ```IMAGE_DATA_DIRECTORY``` structure , ```VirtualAddress``` is the ```RVA``` of the directory (we have discussed RVAs and addressing in the previous post) .The ```size``` field is the size of the directory

Usually , if there is a data directory , it will have values in these two fields .If they are zero , this means that the directory does not exist

It is noteworthy that those directories have a certain order , as defined by the documentation [here](https://learn.microsoft.com/en-us/windows/win32/api/winnt/ns-winnt-image_optional_header32)

**We will begin our discussion of the data directories with the frequently encountered ```Import``` directory , we will see how APIs are loaded from libraries to your binary , and related details**


## Import directory 

Have you ever wondered how you can call an API like ```CreateProcessA``` without it being implemented in your binary ? If you have studied windows internals you will say "Off course , we do not need to re-implement them , we just import the DLL" , but how does that work ?

Almost every executable has an import array , which is accessed with the following formula : 

```Imports start = IMAGE_OPTIONAL_HEADERS.DataDirectories[1].VirtualAddress + ImageBase```


**Imports** directory is just an array of ```IMAGE_IMPORT_DESCRIPTOR``` structures . Every   ```IMAGE_IMPORT_DESCRIPTOR``` corresponds to an import DLL . For example , if we used functions from **kernel32** , **advapi** and **user32** DLLs , we will have ```3``` entries , every one handles resolving all APIs used from that ```DLL```

See it's structure below
```
struct _IMAGE_IMPORT_DESCRIPTOR
{
  union
  {
    DWORD Characteristics;
    DWORD OriginalFirstThunk;
  };
  DWORD TimeDateStamp;
  DWORD ForwarderChain;
  DWORD Name;
  DWORD FirstThunk;
};
```
**To understand how importing works , we will explain the fields :** 

Starting with the union , It is mostly used to access ```OriginalFirstThunk``` , aka ```INT``` or the ```Image Name Table```

This table contains in every entry either a **function name** or an **ordinal**


Now ,  Shifting our focus to the last field ```FirstThunk``` , this is commonly referred as  the ```IAT``` or ```Image Address Table```

This is the array , where all import function pointers are going to be placed during runtime . When you call an api like ```CloseHandle``` or any other api , you are using this pointer from the IAT

It is important to mention that  on-disk , ```IAT``` and ```INT``` contains the same data (either function names or ordinals)

It is during runtime that the loader will replace every name inside ```IAT``` with the corresponding **function pointer**

see the following graphs :

![iat int same before loading](/resources/pepart4_resources/iat_int_same.png)

**Notice how before loading the binary , they contain the same data  , which are the function names/ordinals**

![iat int same before loading](/resources/pepart4_resources/iat_int_loaded.png)

**Now , after loading , IAT array is filled with the function pointers , resolved depending on ```INT```**


Back to the import descriptor ,  you will see the ```TimeDateStamp``` . If this value is zero , this means that the imports for this DLL is ```unbound``` , means that they are resolved during runtime 

If it is 1 , this means that imports are ```bound``` 

**bound** imports used to be in the early days of windows , nowadays , mostly you will face the **unbound** type of imports (which we are discussing in this article)

**If you want to read more about bound imports , check the resources at the end of the article**

It is noteworthy that during runtime , this ```TimeDateStamp``` will be replaced with the timestamp of the loaded DLL


Finally , ```Name``` is the RVA to the DLL name that this Entry in the imports  handles


### The image name table

As we discussed , ```INT``` is used as a guide to resolve API pointers and store in the ```IAT```

The ```INT``` is either an array of ```ordinals``` . **we will discuss ordinals in more depth in the exports directory blog** . For now , think of them as a number that is used to get the API .

Or , it is an array of ```IMAGE_NAME_TABLE``` 

```
struct _IMAGE_IMPORT_BY_NAME
{
  WORD Hint;
  CHAR Name[1];
};
```
The ```Name``` is the name of the API . For instance , "CreateServiceA" , "CreateMutexA" and so on .


### Import resolving , from disk to usage

First , the loader walks the imports directory block by block . **Remmember , every block is ```IMAGE_IMPORT_DESCRIPTOR``` that handles imports for a certain dll**

Then , for every block , it must first load the dll (which contains the APIs implementation)

```LoadLibrary(IMAGE_IMPORT_DESCRIPTOR[i].Name)```

Now , the dll that contains our imports is loaded , however you need to picture the following :

**We do not copy any code to our binary , all API implementation is in the ```DLL``` , we will just retrieve a function pointer to the API . Eventually , API execution is going to be in the hosting ```DLL```**

check this image from **msdn**

![](/resources/pepart4_resources/ApiCalling.gif)


**If you want to understand this better , use ```x64dbg``` and put a breakpoint on one API , follow execution and you will be inside the dll**



Cut to the chase , now it's time to retrieve the API function pointers . For each ```IMAGE_IMPORT_DESCRIPTOR``` , the loader is going to iterate over the ```INT``` or so called ```OriginalFirstThunk``` . Now , for each entry , it is either a direct **API name** of an **ordinal** . In both cases , it is going to use ```GetProcAddress(DLLhandle,API name)``` or ```GetProcAddress(DLLhandle,ordinal)```

```GetProcAddress()``` will walk the **export** directory of the target ```DLL``` , returning the target API pointer


Now , At the corresponding ```index``` in the ```IAT``` table , we will put the ```function pointer```



#### Flow summary

**Load the DLL** ----> **walk it's INT** ---> **for every API , resolve by name or ordinal** ---> **place the resulting pointer at the corresponding index in the IAT**


This is how the IAT/INT will look after the binary has loaded 

![iat int same before loading](/resources/pepart4_resources/iat_int_loaded.png)

**Notice that IAT now is just an array of function pointer , each one will allow us to call an API from the loaded DLL**


This image from the **documentation** will make the notion clearer :

![](/resources/pepart4_resources/IAT_INT_combo.gif)


## Final thoughts 

Firstly , The above process is repeated for every block in the **import** directory , untill all imported APIs are resolved

Moreover , For every loaded ```DLL``` there will be usually a seperate ```IAT``` . To sum up , ```IATs``` of different ```DLLs``` will not be mixed



We have briefly touched how ```GetProcAddress``` is called to resolve functions by ```name``` or ```ordinal``` , but we have not explained how this works 

In the next blog post , we will elaborate from the ```DLL``` side , how ```DLLs``` export functions , and how does these exports get resolved from binaries which loads this ```DLL``` 


**That's it for this blog post , see you in the next one**


## Resources : 

[DLL import binding](https://devblogs.microsoft.com/oldnewthing/20100318-00/?p=14563) from microsoft devblogs











