# AWE-prep

HEVD - Use-After-Free - Win7 x86
![uaf](https://user-images.githubusercontent.com/18420902/30302198-12ad1544-9725-11e7-9dd4-a03f54a7c68d.png)

HEVD - Type Confusion - Win7 x86

Callback structure member is not set before passing the pointer to the TypeConfusionObjectInitializer() function
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
