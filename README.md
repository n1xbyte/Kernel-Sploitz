# AWE-prep

CVE-2014-3434 Symantec Endpoint Protection sysplant.sys Heap Overflow - Win7 x86
![cve-2014-3434](https://user-images.githubusercontent.com/18420902/31064068-92d6ec5c-a6fe-11e7-91e5-55adfbc068ec.png)

OSEE Extra Mile Heap Overflow - Win7 x86
![extramile](https://user-images.githubusercontent.com/18420902/31160174-12400168-a894-11e7-81ce-5fdf0c4bad3f.png)

HEVD - Heap Overflow - Win7 x86

Heap allocation max 0x1f8, fill up a fake object and overwrite next chunk pool and object header. Change the pointer to the crafted chunk to null in the Type Index Table so when the chunk is freed, the execution path will jump to OkayToCloseProcedure parameter at offset 0x74. We set shellcode pointer to null page at offset 0x74 and free the crafted chunk thus causing the execution to jump to shellcode.
![heapoverflow](https://user-images.githubusercontent.com/18420902/30308091-686a8d04-9748-11e7-9f4a-ef3dc8d5355d.png)

HEVD - Use-After-Free - Win7 x86

Heap spray size of 0x60 using IoCompleteReserve objects fits the object used here perfectly. After heap fung shui is done, allocating and freeing the object forcably leaves a pointer to the old object.
![uaf](https://user-images.githubusercontent.com/18420902/30304710-8466306c-9734-11e7-85d4-7289d9e5a9e7.png)

HEVD - Type Confusion - Win7 x86

Callback structure member is not set before passing the pointer to the TypeConfusionObjectInitializer() function.
![typeconfusion](https://user-images.githubusercontent.com/18420902/30252651-17389046-963c-11e7-8075-f82dc4b131fb.png)

HEVD - Uninitialized Stack Variable - Win7 x86

When you pass the incorrect magic value the callback parameter is not initialized. Spray stack to overwrite callback using the       undocumented function NtMapUserPhysicalPages which copies input to kernel stack.
![uninitstackvar](https://user-images.githubusercontent.com/18420902/30252393-42875b60-9637-11e7-8008-eea401fc7d51.png)

HEVD - Null Pointer Dereference - Win7 x86

When you pass the incorrect magic value the callback parameter is nulled. Allocate null page and pass shellcode pointer.
![nullpointer](https://user-images.githubusercontent.com/18420902/30246695-12925600-95c7-11e7-8384-cc3a0c9268eb.png)

HEVD - Integer Overflow - Win7 x86

Supplying an IOCTL input size of 0xffffffff will cause the buffer to pass the max buffer size check due to program adding a size of 4 (terminator size 0xbad0b0b0) to the user buffer input size. 
![integeroverflow](https://user-images.githubusercontent.com/18420902/30245487-ee233aee-95a0-11e7-9734-fb884165fcbc.png)

HEVD - Stack Overflow - Win7 x86
![image 6](https://cloud.githubusercontent.com/assets/18420902/23335109/b34ba266-fb73-11e6-8131-3f1970ba354c.jpg)

HEVD - Stack Overflow - Win7 x64
![image 4](https://cloud.githubusercontent.com/assets/18420902/23334842/2560ccd4-fb6d-11e6-9ac9-b15cdff620d1.jpg)

Capcom - Win10 x64
![capcomw10](https://cloud.githubusercontent.com/assets/18420902/24686876/1a5aac38-197c-11e7-9c79-fc3697764e81.png)

Capcom - Win7 x64
![image 2](https://cloud.githubusercontent.com/assets/18420902/23334841/2560485e-fb6d-11e6-9ec3-52abd7361d77.jpg)
