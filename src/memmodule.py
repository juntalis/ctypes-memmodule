from ctypes import *
from ctypes.wintypes import *
import functools, sys

# Our public debug flag
debug_output = True

# Our system DLLs
_kernel32 = WinDLL('kernel32')
_msvcrt = CDLL('msvcrt')

# Utility stuff (decorators/base classes/functions)
def memoize(obj):
	"""
	From the Python Decorator Library:
	Cache the results of a function call with specific arguments. Note that this decorator ignores **kwargs.
	"""
	cache = obj.cache = {}

	@functools.wraps(obj)
	def memoizer(*args, **kwargs):
		if args not in cache:
			cache[args] = obj(*args, **kwargs)
		return cache[args]

	return memoizer

# Check if the current machine is x64 or x86
_isx64 = sizeof(c_void_p) == sizeof(c_ulonglong)

# Some general type declarations
PWORD = POINTER(WORD)
PDWORD = POINTER(DWORD)
PHMODULE = POINTER(HMODULE)
LONG_PTR = c_longlong if _isx64 else LONG
ULONG_PTR = c_ulonglong if _isx64 else DWORD
UINT_PTR = c_ulonglong if _isx64 else c_uint
SIZE_T = ULONG_PTR
POINTER_TYPE = ULONG_PTR
LP_POINTER_TYPE = POINTER(POINTER_TYPE)
FARPROC = CFUNCTYPE(None)
PFARPROC = POINTER(FARPROC)
c_uchar_p = POINTER(c_ubyte)
c_ushort_p = POINTER(c_ushort)

# Generic Constants
NULL = 0

# Win32/Module-specific constants for declaring our structs.
IMAGE_SIZEOF_SHORT_NAME = 8
IMAGE_NUMBEROF_DIRECTORY_ENTRIES = 16
IMAGE_SIZEOF_SECTION_HEADER = 40

# Struct declarations
class IMAGE_SECTION_HEADER_MISC(Union):
	_fields_ = [
		('PhysicalAddress', DWORD),
		('VirtualSize', DWORD),
	]


class IMAGE_SECTION_HEADER(Structure):
	_anonymous_ = ('Misc',)
	_fields_ = [
		('Name', BYTE * IMAGE_SIZEOF_SHORT_NAME),
		('Misc', IMAGE_SECTION_HEADER_MISC),
		('VirtualAddress', DWORD),
		('SizeOfRawData', DWORD),
		('PointerToRawData', DWORD),
		('PointerToRelocations', DWORD),
		('PointerToLinenumbers', DWORD),
		('NumberOfRelocations', WORD),
		('NumberOfLinenumbers', WORD),
		('Characteristics', DWORD),
	]

PIMAGE_SECTION_HEADER = POINTER(IMAGE_SECTION_HEADER)


class IMAGE_DOS_HEADER(Structure):
	_fields_ = [
		('e_magic', WORD),
		('e_cblp', WORD),
		('e_cp', WORD),
		('e_crlc', WORD),
		('e_cparhdr', WORD),
		('e_minalloc', WORD),
		('e_maxalloc', WORD),
		('e_ss', WORD),
		('e_sp', WORD),
		('e_csum', WORD),
		('e_ip', WORD),
		('e_cs', WORD),
		('e_lfarlc', WORD),
		('e_ovno', WORD),
		('e_res', WORD * 4),
		('e_oemid', WORD),
		('e_oeminfo', WORD),
		('e_res2', WORD * 10),
		('e_lfanew', LONG),
	]

PIMAGE_DOS_HEADER = POINTER(IMAGE_DOS_HEADER)


class IMAGE_DATA_DIRECTORY(Structure):
	_fields_ = [
		('VirtualAddress', DWORD),
		('Size', DWORD),
	]

PIMAGE_DATA_DIRECTORY = POINTER(IMAGE_DATA_DIRECTORY)


class IMAGE_BASE_RELOCATION(Structure):
	_fields_ = [
		('VirtualAddress', DWORD),
		('SizeOfBlock', DWORD),
	]

PIMAGE_BASE_RELOCATION = POINTER(IMAGE_BASE_RELOCATION)


class IMAGE_EXPORT_DIRECTORY(Structure):
	_fields_ = [
		('Characteristics', DWORD),
		('TimeDateStamp', DWORD),
		('MajorVersion', WORD),
		('MinorVersion', WORD),
		('Name',DWORD),
		('Base',DWORD),
		('NumberOfFunctions', DWORD),
		('NumberOfNames', DWORD),
		('AddressOfFunctions', DWORD),
		('AddressOfNames', DWORD),
		('AddressOfNamesOrdinals', DWORD),
	]

PIMAGE_EXPORT_DIRECTORY = POINTER(IMAGE_EXPORT_DIRECTORY)


class IMAGE_IMPORT_DESCRIPTOR_START(Union):
	_fields_ = [
		('Characteristics', DWORD),
		('OriginalFirstThunk', DWORD),
	]


class IMAGE_IMPORT_DESCRIPTOR(Structure):
	_anonymous_ = ('DUMMY',)
	_fields_ = [
		('DUMMY', IMAGE_IMPORT_DESCRIPTOR_START),
		('TimeDateStamp', DWORD),
		('ForwarderChain',DWORD),
		('Name', DWORD),
		('FirstThunk', DWORD),
	]

PIMAGE_IMPORT_DESCRIPTOR = POINTER(IMAGE_IMPORT_DESCRIPTOR)


class IMAGE_IMPORT_BY_NAME(Structure):
	_fields_ = [
		('Hint', WORD),
		('Name', ARRAY(BYTE, 1)),
	]

PIMAGE_IMPORT_BY_NAME = POINTER(IMAGE_IMPORT_BY_NAME)


class IMAGE_OPTIONAL_HEADER(Structure):
	_fields_ = [
		('Magic', WORD),
		('MajorLinkerVersion', BYTE),
		('MinorLinkerVersion', BYTE),
		('SizeOfCode', DWORD),
		('SizeOfInitializedData', DWORD),
		('SizeOfUninitializedData', DWORD),
		('AddressOfEntryPoint', DWORD),
		('BaseOfCode', DWORD),
		('BaseOfData', DWORD),
		('ImageBase', POINTER_TYPE),
		('SectionAlignment', DWORD),
		('FileAlignment', DWORD),
		('MajorOperatingSystemVersion', WORD),
		('MinorOperatingSystemVersion', WORD),
		('MajorImageVersion', WORD),
		('MinorImageVersion', WORD),
		('MajorSubsystemVersion', WORD),
		('MinorSubsystemVersion', WORD),
		('Reserved1', DWORD),
		('SizeOfImage', DWORD),
		('SizeOfHeaders', DWORD),
		('CheckSum', DWORD),
		('Subsystem', WORD),
		('DllCharacteristics', WORD),
		('SizeOfStackReserve', POINTER_TYPE),
		('SizeOfStackCommit', POINTER_TYPE),
		('SizeOfHeapReserve', POINTER_TYPE),
		('SizeOfHeapCommit', POINTER_TYPE),
		('LoaderFlags', DWORD),
		('NumberOfRvaAndSizes', DWORD),
		('DataDirectory', IMAGE_DATA_DIRECTORY * IMAGE_NUMBEROF_DIRECTORY_ENTRIES),
	]

PIMAGE_OPTIONAL_HEADER = POINTER(IMAGE_OPTIONAL_HEADER)


class IMAGE_FILE_HEADER(Structure):
	_fields_ = [
		('Machine', WORD),
		('NumberOfSections', WORD),
		('TimeDateStamp', DWORD),
		('PointerToSymbolTable', DWORD),
		('NumberOfSymbols', DWORD),
		('SizeOfOptionalHeader', WORD),
		('Characteristics', WORD),
	]

PIMAGE_FILE_HEADER = POINTER(IMAGE_FILE_HEADER)


class IMAGE_NT_HEADERS(Structure):
	_fields_ = [
		('Signature', DWORD),
		('FileHeader', IMAGE_FILE_HEADER),
		('OptionalHeader', IMAGE_OPTIONAL_HEADER),
	]

PIMAGE_NT_HEADERS = POINTER(IMAGE_NT_HEADERS)


class MEMORYMODULE(Structure):
	_fields_ = [
		('headers', PIMAGE_NT_HEADERS),
		('codeBase', c_uchar_p),
		('modules', PHMODULE),
		('numModules', c_int),
		('initialized', c_int)
	]

PMEMORYMODULE = POINTER(MEMORYMODULE)

# Win32 API Function Prototypes
VirtualAlloc = _kernel32.VirtualAlloc
VirtualAlloc.restype = LPVOID
VirtualAlloc.argtypes = [POINTER_TYPE, SIZE_T, DWORD, DWORD]

VirtualFree = _kernel32.VirtualFree
VirtualFree.restype = BOOL
VirtualFree.argtypes = [ LPVOID, SIZE_T, DWORD ]

VirtualProtect = _kernel32.VirtualProtect
VirtualProtect.restype = BOOL
VirtualProtect.argtypes = [ LPVOID, SIZE_T, DWORD, PDWORD ]

HeapAlloc = _kernel32.HeapAlloc
HeapAlloc.restype = LPVOID
HeapAlloc.argtypes = [ HANDLE, DWORD, SIZE_T ]

GetProcessHeap = _kernel32.GetProcessHeap
GetProcessHeap.restype = HANDLE
GetProcessHeap.argtypes = []

HeapFree = _kernel32.HeapFree
HeapFree.restype = BOOL
HeapFree.argtypes = [ HANDLE, DWORD, LPVOID ]

GetProcAddress = _kernel32.GetProcAddress
GetProcAddress.restype = FARPROC
GetProcAddress.argtypes = [HMODULE, LPCSTR]

LoadLibraryA = _kernel32.LoadLibraryA
LoadLibraryA.restype = HMODULE
LoadLibraryA.argtypes = [ LPCSTR ]

FreeLibrary = _kernel32.FreeLibrary
FreeLibrary.restype = BOOL
FreeLibrary.argtypes = [ HMODULE ]

IsBadReadPtr = _kernel32.IsBadReadPtr
IsBadReadPtr.restype = BOOL
IsBadReadPtr.argtypes = [ LPCVOID, UINT_PTR ]

realloc = _msvcrt.realloc
realloc.restype = c_void_p
realloc.argtypes = [ c_void_p, c_size_t ]

# Type declarations specific to our module.
DllEntryProc = WINFUNCTYPE(BOOL, HINSTANCE, DWORD, LPVOID)
HMEMORYMODULE = HMODULE

# Constants dealing with VirtualProtect and some other things.
MEM_COMMIT = 0x00001000
MEM_DECOMMIT = 0x4000
MEM_RELEASE = 0x8000
MEM_RESERVE = 0x00002000
MEM_FREE = 0x10000
MEM_MAPPED = 0x40000
MEM_RESET = 0x00080000

PAGE_NOACCESS = 0x01
PAGE_READONLY = 0x02
PAGE_READWRITE = 0x04
PAGE_WRITECOPY = 0x08
PAGE_EXECUTE = 0x10
PAGE_EXECUTE_READ = 0x20
PAGE_EXECUTE_READWRITE = 0x40
PAGE_EXECUTE_WRITECOPY = 0x80
PAGE_NOCACHE = 0x200

ProtectionFlags = ARRAY(ARRAY(ARRAY(c_int, 2), 2), 2)(
	(
		(PAGE_NOACCESS, PAGE_WRITECOPY),
		(PAGE_READONLY, PAGE_READWRITE),
	), (
		(PAGE_EXECUTE, PAGE_EXECUTE_WRITECOPY),
		(PAGE_EXECUTE_READ, PAGE_EXECUTE_READWRITE),
	),
)


IMAGE_SCN_MEM_EXECUTE = 0x20000000
IMAGE_SCN_MEM_READ = 0x40000000
IMAGE_SCN_MEM_WRITE = 0x80000000
IMAGE_SCN_MEM_DISCARDABLE = 0x02000000
IMAGE_SCN_MEM_NOT_CACHED = 0x04000000
IMAGE_SCN_CNT_INITIALIZED_DATA = 0x00000040
IMAGE_SCN_CNT_UNINITIALIZED_DATA = 0x00000080

# TODO: Get rid of what I don't need here.
IMAGE_DIRECTORY_ENTRY_EXPORT = 0
IMAGE_DIRECTORY_ENTRY_IMPORT = 1
IMAGE_DIRECTORY_ENTRY_RESOURCE = 2
IMAGE_DIRECTORY_ENTRY_EXCEPTION = 3
IMAGE_DIRECTORY_ENTRY_SECURITY = 4
IMAGE_DIRECTORY_ENTRY_BASERELOC = 5
IMAGE_DIRECTORY_ENTRY_DEBUG = 6
# IMAGE_DIRECTORY_ENTRY_COPYRIGHT = 7
IMAGE_DIRECTORY_ENTRY_ARCHITECTURE = 7
IMAGE_DIRECTORY_ENTRY_GLOBALPTR = 8
IMAGE_DIRECTORY_ENTRY_TLS = 9
IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG = 10
IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT = 11
IMAGE_DIRECTORY_ENTRY_IAT = 12
IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT = 13
IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR = 14

DLL_PROCESS_ATTACH = 1
DLL_THREAD_ATTACH = 2
DLL_THREAD_DETACH = 3
DLL_PROCESS_DETACH = 0

INVALID_HANDLE_VALUE = -1

IMAGE_SIZEOF_BASE_RELOCATION = sizeof(IMAGE_BASE_RELOCATION)
IMAGE_REL_BASED_ABSOLUTE = 0
IMAGE_REL_BASED_HIGH = 1
IMAGE_REL_BASED_LOW = 2
IMAGE_REL_BASED_HIGHLOW = 3
IMAGE_REL_BASED_HIGHADJ = 4
IMAGE_REL_BASED_MIPS_JMPADDR = 5
IMAGE_REL_BASED_MIPS_JMPADDR16 = 9
IMAGE_REL_BASED_IA64_IMM64 = 9
IMAGE_REL_BASED_DIR64 = 10

IMAGE_ORDINAL_FLAG64 = 0x8000000000000000
IMAGE_ORDINAL_FLAG32 = 0x80000000
_IMAGE_ORDINAL64 = lambda o: (o & 0xffff)
_IMAGE_ORDINAL32 = lambda o: (o & 0xffff)
_IMAGE_SNAP_BY_ORDINAL64 = lambda o: ((o & IMAGE_ORDINAL_FLAG64) != 0)
_IMAGE_SNAP_BY_ORDINAL32 = lambda o: ((o & IMAGE_ORDINAL_FLAG32) != 0)
_IMAGE_ORDINAL = _IMAGE_ORDINAL64 if _isx64 else _IMAGE_ORDINAL32
_IMAGE_SNAP_BY_ORDINAL = _IMAGE_SNAP_BY_ORDINAL64 if _isx64 else _IMAGE_SNAP_BY_ORDINAL32

IMAGE_DOS_SIGNATURE = 0x5A4D # MZ
IMAGE_OS2_SIGNATURE = 0x454E # NE
IMAGE_OS2_SIGNATURE_LE = 0x454C # LE
IMAGE_VXD_SIGNATURE = 0x454C # LE
IMAGE_NT_SIGNATURE = 0x00004550 # PE00

def create_unsigned_buffer(indata, sz = None):
	if sz is None:
		sz = len(indata)
	result = (c_ubyte * sz)()
	for c in range(0, sz - 1):
		result[c] = ord(indata[c])
	return result

# CTypes implementations of various generic macros
@memoize
def FIELD_OFFSET(struct, field):
	"""
	CTypes implementation of the FIELD_OFFSET macro. Sort of.

	:param struct: The structure type who's field we're finding the offset of.
	:param field: The name of our target field.
	:type struct: type(Structure)
	:type field: str
	:return: The offset of our target field.
	:rtype: int
	"""
	result = 0
	for fld in struct._fields_:
		if fld[0] == field: return result
		result += sizeof(fld[1])
	return None

# Ctypes implementations of Win32 PE/Module specific macros
def IMAGE_FIRST_SECTION(ntheader):
	"""
	Couldn't find any documentation on this on MSDN, but judging from the name of the macro, and the actual code,
	it looks like it finds the first section header following the OptionalHeader of an image.

	:param ntheader: Image headers
	:type ntheader: PIMAGE_NT_HEADERS
	:return: Our first section header.
	:rtype: PIMAGE_SECTION_HEADER
	"""
	return cast(addressof(ntheader) + FIELD_OFFSET(IMAGE_NT_HEADERS, 'OptionalHeader') + ntheader.contents.FileHeader.SizeOfOptionalHeader, PIMAGE_SECTION_HEADER)

def GET_HEADER_DICTIONARY(module, idx):
	""" I just realized: why the hell am I documenting internal functions that I plan to hide, anyways? """
	return pointer(module.contents.headers.contents.OptionalHeader.DataDirectory[idx])

# I realize OutputDebugString is an actual win32 api function, but most python users most likely won't have a debugger
# listening to debug messages while attempting to troubleshoot their scripts.
def _OutputDebugString(msg):
	global debug_output
	if not debug_output: return
	sys.stderr.write(msg)

def _OutputLastError(msg):
	_OutputDebugString('%s: %s\n' % (msg, FormatError()))

# Actual module code
def _CopySections(data, old_headers, module):
	codeBase = module.contents.codeBase
	section = IMAGE_FIRST_SECTION(module.contents.headers)
	numSections = module.contents.headers.contents.FileHeader.NumberOfSections
	for i in range(1, numSections):
		size = old_headers.contents.OptionalHeader.SectionAlignment
		if size > 0:
			dest = addressof(codeBase) + section.contents.VirtualAddress
			destbuf = cast(dest, LPCVOID)
			VirtualAlloc(destbuf, size, MEM_COMMIT, PAGE_READWRITE )
			section.contents.PhysicalAddress = POINTER_TYPE(dest)
			destbuf = cast(dest, POINTER(c_ubyte * size))
			memset(destbuf, 0, size)
		size = section.contents.SizeOfRawData
		dest = cast(addressof(codeBase) + section.contents.VirtualAddress, c_uchar_p)
		VirtualAlloc(dest, size, MEM_COMMIT, PAGE_READWRITE )
		memmove(dest, addressof(data) + section.contents.PointerToRawData, size)
		section.contents.PhysicalAddress = addressof(dest)
		section = cast(addressof(section) + sizeof(PIMAGE_SECTION_HEADER), PIMAGE_SECTION_HEADER)

def _FinalizeSections(module):
	section = IMAGE_FIRST_SECTION(module.contents.headers)
	imageOffset = POINTER_TYPE(module.contents.headers.contents.OptionalHeader.ImageBase & 0xffffffff00000000) if _isx64 else 0
	numSections = module.contents.headers.contents.FileHeader.NumberOfSections
	checkCharacteristic = lambda sect, flag: 1 if (sect.contents.Characteristics & flag) != 0 else 0
	getPhysAddr = lambda sect: POINTER_TYPE(section.contents.PhysicalAddress) | imageOffset
	for i in range(1, numSections):
		oldProtect = DWORD(0)
		executable = checkCharacteristic(section, IMAGE_SCN_MEM_EXECUTE)
		readable = checkCharacteristic(section, IMAGE_SCN_MEM_READ)
		writeable = checkCharacteristic(section, IMAGE_SCN_MEM_WRITE)

		if checkCharacteristic(section, IMAGE_SCN_MEM_DISCARDABLE):
			addr = getPhysAddr(section)
			VirtualFree(cast(addr, LPVOID), section.contents.SizeOfRawData, MEM_DECOMMIT)
			continue

		protect = ProtectionFlags[executable][readable][writeable]
		if checkCharacteristic(section, IMAGE_SCN_MEM_NOT_CACHED):
			protect |= PAGE_NOCACHE

		size = section.contents.SizeOfRawData
		if size == 0:
			if checkCharacteristic(section, IMAGE_SCN_CNT_INITIALIZED_DATA):
				size = module.contents.headers.contents.OptionalHeader.SizeOfInitializedData
			elif checkCharacteristic(section, IMAGE_SCN_CNT_UNINITIALIZED_DATA):
				size = module.contents.headers.contents.OptionalHeader.SizeOfUninitializedData

		if size > 0:
			addr = getPhysAddr(section)
			if VirtualProtect(addr, size, protect, byref(oldProtect)) == 0:
				_OutputLastError("Error protecting memory page")
		section = cast(addressof(section) + sizeof(PIMAGE_SECTION_HEADER), PIMAGE_SECTION_HEADER)

def _PerformBaseRelocation(module, delta):
	codeBase = module.contents.codeBase
	codeBaseAddr = addressof(codeBase)

	lpdirectory = GET_HEADER_DICTIONARY(module, IMAGE_DIRECTORY_ENTRY_BASERELOC)
	directory = lpdirectory.contents
	if directory.Size <= 0: return
	relocation = cast(codeBaseAddr + directory.VirtualAddress, PIMAGE_BASE_RELOCATION)
	while relocation.contents.VirtualAddress > 0:
		dest = cast(codeBaseAddr + relocation.contents.VirtualAddress, c_uchar_p)
		relInfo = cast(addressof(relocation) + IMAGE_SIZEOF_BASE_RELOCATION, c_ushort_p)
		for i in range(1, (relocation.contents.SizeOfBlock - IMAGE_SIZEOF_BASE_RELOCATION) / 2):
			type = relInfo.contents >> 12
			offset = relInfo.contents & 0xfff
			if type == IMAGE_REL_BASED_HIGHLOW or (type == IMAGE_REL_BASED_DIR64 and _isx64):
				patchAddrHL = cast(addressof(dest) + offset, LP_POINTER_TYPE)
				patchAddrHL.contents += delta
			relocation = cast(addressof(relocation) + relocation.contents.SizeOfBlock, IMAGE_BASE_RELOCATION)
			relInfo = cast(addressof(relInfo) + sizeof(c_ushort_p), c_ushort_p)


def MemoryFreeLibrary(hmod):
	if not bool(hmod): return
	pmodule = cast(hmod, PMEMORYMODULE)
	module = pmodule.contents
	if module.initialized != 0:
		DllEntry = DllEntryProc(addressof(module.codeBase) + module.headers.contents.OptionalHeader.AddressOfEntryPoint)
		DllEntry(cast(module.codeBase, HINSTANCE), DLL_PROCESS_DETACH, 0)
		pmodule.contents.initialized = 0
	if bool(module.modules) and module.numModules > 0:
		#mods = cast(module.modules, ARRAY(HMODULE, module.numModules))
		for i in range(1, module.numModules):
			if module.modules[i] != HANDLE(INVALID_HANDLE_VALUE):
				FreeLibrary(module.modules[i])

	if bool(module.codeBase):
		VirtualFree(module.codeBase, 0, MEM_RELEASE)

	HeapFree(GetProcessHeap(), 0, module)

#noinspection PyUnusedLocal
def _BuildImportTable(module):
	result = -1
	codeBase = module.contents.codeBase
	codeBaseAddr = addressof(codeBase)
	lpdirectory = GET_HEADER_DICTIONARY(module, IMAGE_DIRECTORY_ENTRY_IMPORT)
	directory = lpdirectory.contents
	if directory.Size <= 0: return result
	importDesc = cast(codeBaseAddr + directory.FirstThunk, PIMAGE_IMPORT_DESCRIPTOR)

	while not bool(IsBadReadPtr(importDesc, sizeof(IMAGE_IMPORT_DESCRIPTOR))) and bool(importDesc.contents.Name):
		handle = LoadLibraryA(cast(codeBaseAddr + importDesc.contents.Name, LPCSTR))
		thunkRef = None
		funcRef = None
		if not bool(handle):
			_OutputLastError("Can't load library")
			result = 0
			break
		importDesc = cast(addressof(importDesc) + sizeof(PIMAGE_IMPORT_DESCRIPTOR), PIMAGE_IMPORT_DESCRIPTOR)
		module.contents.modules = realloc(module.contents.modules, (module.contents.numModules + 1) * sizeof(HMODULE))
		if not bool(module.contents.modules):
			result = 0
			break

		module.contents.modules[module.contents.numModules] = handle
		module.contents.numModules += 1
		if importDesc.contents.OriginalFirstThunk > 0:
			thunkRef = cast(codeBaseAddr + importDesc.contents.OriginalFirstThunk, LP_POINTER_TYPE)
			funcRef = cast(codeBaseAddr + importDesc.contents.FirstThunk, PFARPROC)
		else:
			thunkRef = cast(codeBaseAddr + importDesc.contents.FirstThunk, LP_POINTER_TYPE)
			funcRef = cast(codeBaseAddr + importDesc.contents.FirstThunk, PFARPROC)
		while thunkRef.contents:
			if _IMAGE_SNAP_BY_ORDINAL(thunkRef.contents):
				funcRef.contents = GetProcAddress(handle, cast(_IMAGE_ORDINAL(thunkRef.contents), LPCSTR))
			else:
				thunkData = cast(codeBaseAddr + thunkRef.contents, PIMAGE_IMPORT_BY_NAME)
				funcRef.contents = GetProcAddress(handle, cast(pointer(thunkData.contents.Name), LPCSTR))
			if not bool(funcRef):
				result = 0
				break
		if not result:
			break
	return result


def MemoryLoadLibrary(data):
	udata = create_unsigned_buffer(data)
	dos_header = cast(udata, PIMAGE_DOS_HEADER)
	if dos_header.contents.e_magic != IMAGE_DOS_SIGNATURE:
		_OutputDebugString("Not a valid executable file.\n")
		return NULL
	ubufi = cast(addressof(udata) + dos_header.contents.e_lfanew, c_uchar_p)
	old_header = cast(ubufi, PIMAGE_NT_HEADERS)
	if old_header.contents.Signature != IMAGE_NT_SIGNATURE:
		_OutputDebugString("No PE header found.\n")
		return NULL

	codebase = old_header.contents.OptionalHeader.ImageBase
	Pcodebase = VirtualAlloc(
		codebase,
		old_header.contents.OptionalHeader.SizeOfImage,
		MEM_RESERVE,
		PAGE_READWRITE
	)
	code = cast(Pcodebase, POINTER(c_ubyte * old_header.contents.OptionalHeader.SizeOfImage))


	if not bool(code):
		codebase = cast(VirtualAlloc(
			NULL,
			old_header.contents.OptionalHeader.SizeOfImage,
			MEM_RESERVE,
			PAGE_READWRITE
		), c_uchar_p)
		Pcodebase = cast(pointer(codebase), POINTER(c_ubyte * old_header.contents.OptionalHeader.SizeOfImage))
		code = Pcodebase.contents
		if not bool(code):
			_OutputLastError("Can't reserve memory")
			return NULL

	result = cast(HeapAlloc(GetProcessHeap(), 0, sizeof(MEMORYMODULE)), PMEMORYMODULE)
	result.contents._fields_[1] = ('codeBase', (c_ubyte * old_header.contents.OptionalHeader.SizeOfImage))
	result.contents.codeBase = code
	result.contents.numModules = 0
	result.contents.modules = cast(NULL, PHMODULE)
	result.contents.initialized = 0

	VirtualAlloc(
		addressof(code),
		old_header.contents.OptionalHeader.SizeOfImage,
		MEM_COMMIT,
		PAGE_READWRITE
	)

	headers = cast(VirtualAlloc(
		addressof(code),
		old_header.contents.OptionalHeader.SizeOfHeaders,
		MEM_COMMIT,
		PAGE_READWRITE
	), c_uchar_p)

	memmove(headers, dos_header, dos_header.contents.e_lfanew + old_header.contents.OptionalHeader.SizeOfHeaders)

	result.contents.headers = cast(cast(addressof(headers) + dos_header.contents.e_lfanew, c_uchar_p), PIMAGE_NT_HEADERS)

	result.contents.headers.contents.OptionalHeader.Image = POINTER_TYPE(addressof(code))
	_CopySections(data, old_header, result)

	locationDelta = SIZE_T(addressof(code) - old_header.contents.OptionalHeader.ImageBase)
	if locationDelta != 0:
		_PerformBaseRelocation(result, locationDelta)

	if not bool(_BuildImportTable(result)):
		MemoryFreeLibrary(result)
		return NULL

	_FinalizeSections(result)
	if result.contents.headers.contents.OptionalHeader.AddressOfEntryPoint != 0:
		DllEntry = cast(addressof(code) + result.contents.headers.contents.OptionalHeader.AddressOfEntryPoint, DllEntryProc)
		if DllEntry == 0:
			_OutputDebugString("Library has no entry point.\n")
			MemoryFreeLibrary(result)
			return NULL
		success = DllEntry(cast(code, HINSTANCE), DLL_PROCESS_ATTACH, 0)
		if not bool(success):
			_OutputDebugString("Can't attach library.\n")
			MemoryFreeLibrary(result)
			return NULL
		result.contents.initialized = 1

	return cast(result, HMEMORYMODULE)

def MemoryGetProcAddress(hmod, name):
	module = cast(hmod, PMEMORYMODULE)
	codeBase = module.contents.codeBase
	codeBaseAddr = addressof(codeBase)
	idx = -1
	lpdirectory = GET_HEADER_DICTIONARY(module, IMAGE_DIRECTORY_ENTRY_EXPORT)
	directory = lpdirectory.contents
	if directory.size <= 0:
		# No export table
		return None

	lpexports = cast(codeBaseAddr + directory.VirtualAddress, PIMAGE_EXPORT_DIRECTORY)
	exports = lpexports.contents
	if exports.NumberOfNames == 0 or exports.NumberOfFunctions == 0:
		# DLL doesn't export anything
		return None

	nameRef = cast(codeBaseAddr + exports.AddressOfNames, PDWORD)
	ordinal = cast(codeBaseAddr + exports.AddressOfNames, PWORD)
	for i in range(1, exports.NumberOfNames):
		if name.lower() == cast(codeBaseAddr + nameRef.contents, LPCSTR).value == 0:
			idx = ordinal.contents
			break
		ordinal = cast(addressof(ordinal) + sizeof(PWORD), PWORD)

	if idx == -1: return None
	if idx > exports.NumberOfFunctions: return None
	funcOffset = cast(codeBaseAddr + exports.AddressOfFunctions + ( idx * 4 ), PDWORD).contents
	return FARPROC(codeBaseAddr + funcOffset)


