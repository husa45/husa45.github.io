---
title: "PE file headers analysis mastery series , part 5"
date: 2026-08-28 16:00:30 +0300
categories: [malware analysis, PE file structure] 
tags: [misc,malware]
---

In the previous blog , we have discussed the **Imports** directory , and it's importance in the loading process . We also discussed how imports are resolved by the binary during the load-time . 

In this article , we are going to look at it from the corresponding side , the **exports** . So , what is exports to begin with ? what is  the effect of linking type on exports and export resolving ?  



## Linking types 

Why linking from the first place ? While you are writing code , you will not re-implement every requirement by yourself . Usually , there will be **libraries** that implement the needed functionality , so now , you just need to reference this library , and use the provided **functions** .

For example , if you want to allocate memory , you do not implement it manually , you will usually use the Winapi **VirtualAlloc** . Another example is if you need to use compression algorithms , you will usually use a **library** like **zlib** .

To sum up , instead of re-implementing everything manually , you use the  **libraries** that provide it . **Linking** is just how you would reference these libraries . Whether it is one-time during compilation , or every-time you launch the executable .  


We have two main types of linking that we should be aware of : 

### Static linking

In this **linking** method , the  **library** code which you linked against , will be baked into your binary during **compilation time** .

After that , no need anymore for the original library (the functionality is embeded in your binary rightnow)

**This provides several benifits :**

A.This makes binaries more **portable** . You just link your binary against the libraries needed , and you can use it on any platform/OS  , even if those libraries are not present there .

For example , this is how  **rust** binaries can execute anywhere , even if **rust** compiler is not installed . **Sidenote: This is what also makes rust intense to Reverse-engineer , since main logic will be mixed heavily with library code** .

B.This also makes them faster , since no dependencies need to be loaded every time we launch the executable .

<br>

**The main drawback of static linking** is the enormous inflation in the binary size , since library code is merged with the ```.text``` section .


Usually , binaries are statically linked against the  ```.lib``` file of the library . For example , to link your ```.cpp``` project against  ```user32.dll``` statically , you would use :
```cl.exe  <path to .cpp file> /link  user32.lib```



### Dynamic linking

In this approach  , we have what we call  a **DLL** (Dynamic Linking Library) , which is just a **PE file** that implements functionality needed by other apps  , then  **export** them , so executables can **import** them during **runtime** .

The image below show some exports of a  common windows DLL **kerenel32.dll** :

![kernel32](/resources/pepart5_resources/kernel32_exports.png)


But , how can we use code/functions , when they are not implemented in our binary ? 

During **runtime** , the **DLL** that conatains the **exports** that you **imported** and used in your app , will be loaded to you binary , typically via **LoadLibraryA** .

Next , the loader will parse the **exports** of the **DLL** and resolve pointers to these **functions** and fill them in the **IAT** .



For example , when you use **VirtualAlloc** in your binary , the linker created an **IMAGE_IMPORT_DESCRIPTOR** in the **Imports** directory , and added **kernel32.dll** as a **Dllname** , and placed **VirtualAlloc** inside the **INT** , so it will get resolved dynamically (if you do not understand this process , read the previous article on import resolving) .



**The main benifit for dynamic-linking** is the significantly smaller binary than **static-linking** , since we just reference APIs from the library , instead of baking it into the binary .

**The main drawback for dynamic-linking** is that the libraries used needs to be on the target system , otherwise linking fails . That's why you see games and apps bundle ```DLLs``` with the installation .
<br><br>

Now , diving deep into the **export** parsing process , and linking it to **import** resolving .
## The export directory

If the **PE file** exports functions , it will  have an **export data directory** , which is accessed with the following formula :

```Exports start = IMAGE_OPTIONAL_HEADERS.DataDirectories[0].VirtualAddress + ImageBase```


The export directory is a structure called ```IMAGE_EXPORT_DIRECTORY``` which contains all information about the **exports**  , which helps the loader to get the pointers of the functions during the **export** parsing proces .

It has the following structure : 
```
struct _IMAGE_EXPORT_DIRECTORY
{
  DWORD Characteristics;
  DWORD TimeDateStamp;
  WORD MajorVersion;
  WORD MinorVersion;
  DWORD Name;
  DWORD Base;
  DWORD NumberOfFunctions;
  DWORD NumberOfNames;
  DWORD AddressOfFunctions;
  DWORD AddressOfNames;
  DWORD AddressOfNameOrdinals;
};
```

Starting off with ```Name``` which is an RVA to the Dllname string .

Moving on to the ```base``` , which is a number used to derive the **exported ordinal** .

Exports are represented in two ways : using ```ordinals``` , which is just a ```WORD``` that represents the export as a number , and using ```name``` , where the export is exported by it's name.


Correlating this with ```AddressOfNames``` and ```AddressOfNameOrdinals``` . ```Address of names``` is an RVA to an array of RVAs (every RVA will get you to an export name)

To make it more clear : To get the array of name-RVAs ```AddressOfNames+imagebase``` ----> then to get a certain name ```RVAarray[i]+imagebase```

On the other hand , ```AddressOfNameOrdinals``` is an RVA to the array of export ```ordinals```


Now , ```AddressOfFunctions``` is the RVA to something we call ```EAT or Export Address Table``` . This is just an array of ```function``` RVAs to every export of the DLL.  Means that , if we resolved the RVA : ```EAT[i]+imagebase``` we will get a pointer to the first instruction of this function in the ```.text``` section of the ```DLL``` 

This is the resolved pointer that will be placed in the ```IAT``` during runtime . So , when you call ```VirtualAlloc``` you are using this pointer to jump to it's code inside ```kernel32.dll```

Final field of discussion is ```NumberOfNames``` , which is the total number of APIs exported by this ```DLL```


**To sum up :** The ```DLL``` has exported functions to be used by other apps , those functions are represented in the ```exports``` dir in two ways :

Using  ```Names``` and using ```ordinals``` . To get to the ```names``` , ```AdressOfNames``` is used . To get to the ```ordinals``` , ```AdressOfNameOrdinals``` is used . So , an **export** could be resolved in either way .

Eventually , whether the export is a ```name``` or ```ordinal```  , we need to get the pointer to it's first instruction . To do that , we use ```AdressOfFunctions``` , which provides an RVA to every exported function .
<br><br><br>


Before moving on , we need to grasp this important concept : **AddressOfNames  and AddressOfNameOrdinals  and  AddressOfFunctions**  are all **parallel arrays** .


This means that , assuming we have ```MessageBoxA``` at index 3 in **AddressOfNames** , at the same index in  **AddressOfNameOrdinals** we will find it's **ordinal** . Also , if using the **ordinal** that we got as an index to  **AddressOfFunctions** we will get it's RVA in the ```DLL```


see the following image :

![exports layout](/resources/pepart5_resources/exports_layout.png)

The following algorithm could be applied to get the function pointer of an export using it's ```name``` :

```
ordinals_index=search(AddressOfNames,target_name)
ordinal=ArrayOfNameOrdinals[ordinals_index]
Function pointer = EAT[ordinal] + imagebase
```
Using the ```ordinal``` , it is much simpler : 
```
ordinal= exported_ordinal - base  //base field from the directory

Function pointer = EAT[ordinal] + imagebase
```


### Export parsing process

Now , starting with an ```ordinal``` or a ```name``` from the ```INT or Image Name Table``` during ```Import``` parsing , how can the loader find the ```function pointer``` to place it in the corresponding ```IAT``` entry , so you can call it in you binary ?


**Steps :**

**First :** The loader will load the ```DLL``` to the process memory space , so we can call exports using pointers , and to parse it's exports to get those pointers


**Secondly :** Assuming the loader is already parsing **imports** , now we have an import to resolve , we might have two cases : 

1.We have an ```ordinal``` : This is the easiest case . The loader will get ```AddressOfNameOrdinals``` from the export directory of the ```DLL``` 

Next , the  **ordinal** is used as an index to the ```AddressOfFunctions``` .But , not directly , we must subtract ```Base``` field we talked about earlier .

```Index to EAT = ordinal - base```

Now, we have the RVA of the API , we will  add ```dll image base``` to get the ```api pointer``` needed

**Refer to the algorithm discussed above**

2.we have a ```name``` : This case is more complex in some sense . 

**First** , the loader will do binary search on the ```AddressOfNames``` searching for the ```name```

When it finds it , it records the index . The same index is used to get the ```ordinal``` from from ```AdressOfNameOrdinals``` 

So : ```Ordinal = AddressOfNameOrdinals[Index of the name inside names array]```

Now , the ordinal is used as an index to the ```AddressOfFunctions``` , to get the API RVA , which is added to the ```DLL``` base to get the needed ```pointer```

So : ```Export pointer = AddressOfFunctions[ordinal]+imagebase```

**Refer to the algorithm discussed above**

See the following graph :

![exports](/resources/pepart5_resources/exports.msdn.gif)



That is all it is about . It starts from a certain entry in ```Image Name Table```  , the loader gets an ```ordinal``` or a ```name```  , parses corresponding ```DLL``` exports , finds the API pointer , fills it back in the ```IAT``` .


## Final Notes 

A.**exports**  are not limited for ```DLLs``` , normal exectuables can export functions .For example , go and check ```Ntoskernel.exe``` , and see how it exports functions .


B.If you have paid attention  , when we used ```ordinal``` to resolve the export , we have subtracted ```Base``` , why ? 

Because the real index to get the RVA from ```EAT``` is  ```AddressOfNameOrdinals[i]``` , but , the ordinal exported by the ```DLL``` is ```AddressOfNameOrdinals[i]+base``` , thats why we subtract the ```base``` when resolving directly using ```ordinals```

<br><br><br>
C.The discussed **export** type before is a **direct** export . Means that the export is implemented inside the same ```DLL``` 

In this case , in ```AddressOfNames[i]+image_base``` you will find a direct ```name``` , ie : **VirtualAlloc**

We have a second type of export , which is called a ```forwarded``` export . The implementation of this function is not inside the current ```DLL``` , but it is in another ```DLL```

In this case , in ```AddressOfNames[i]+image_base``` you will find  ```TARGETDLLNAME.name``` , ie : **NTDLL.AcquireSRWLockExclusive**

Here , the loader will load the ```DLL``` before "**.**" then do the resolving of the name after "**.**" as usual . 

To sum up , some **exports** are implmented directly in the ```DLL```  , while others are **proxied** to other ```DLL```

You will commonly face this technique accompanying **DLL side loading attacks** , why ?

The attacker has crafted his malicious **DLL** , but , this is not the original , so the loading **App** will crash , which brings user suspicion .

To avoid that , adversaries  creates the malicious **side-loaded DLL** as a **proxy** , where all **original** exports are forwarded to the original **DLL** . So now , the app will execute correctly , since exported functions are resolved correctly from the **original** DLL .

![](/resources/pepart5_resources/dllproxying.png)


Image referenced is from  [Read Team notes](https://www.ired.team/offensive-security/persistence/dll-proxying-for-persistence)


check this article from [Read Team notes](https://www.ired.team/offensive-security/persistence/dll-proxying-for-persistence) for a more in depth explanation of the technique .



 

**That's it for todays blog , see you in the next one .**











