from ctypes import *
from ctypes.wintypes import *
import functools, sys

# Our public debug flag
debug_output = False

# Our system DLLs
_kernel32 = WinDLL('kernel32')

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
SIZE_T = ULONG_PTR
PTRTYP = ULONG_PTR
FARPROC = CFUNCTYPE(None)
c_uchar_p = POINTER(c_ubyte)

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
		('ImageBase', PTRTYP),
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
		('SizeOfStackReserve', PTRTYP),
		('SizeOfStackCommit', PTRTYP),
		('SizeOfHeapReserve', PTRTYP),
		('SizeOfHeapCommit', PTRTYP),
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
VirtualAlloc.argtypes = [LPVOID, SIZE_T, DWORD, DWORD]

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

FreeLibrary = _kernel32.FreeLibrary
FreeLibrary.restype = BOOL
FreeLibrary.argtypes = [ HMODULE ]




# Type declarations specific to our module.
DllEntryProc = WINFUNCTYPE(BOOL, HINSTANCE, DWORD, LPVOID)
HMEMORYMODULE = HMODULE

# Constants dealing with VirtualProtect and some other things.
MEM_COMMIT = 0x1000
MEM_DECOMMIT = 0x4000
MEM_RELEASE = 0x8000

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

DLL_PROCESS_DETACH = 0

INVALID_HANDLE_VALUE = -1

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
	return module.contents.headers.OptionalHeader.DataDirectory[idx]


def OutputLastError(msg):
	global debug_output
	if not debug_output: return
	sys.stderr.write('%s: %s\n' % (msg, FormatError()))

# Actual module code
def _CopySections(data, old_headers, module):
	codeBase = module.contents.codeBase
	section = IMAGE_FIRST_SECTION(module.contents.headers)
	numSections = module.contents.headers.contents.FileHeader.NumberOfSections
	allocDest = lambda sz, sect: cast(VirtualAlloc(addressof(codeBase) + sect.contents.VirtualAddress, sz, MEM_COMMIT, PAGE_READWRITE ), c_uchar_p)
	for i in range(1, numSections):
		size = old_headers.contents.OptionalHeader.SectionAlignment
		if size > 0L:
			dest = allocDest(size, section)
			section.contents.PhysicalAddress = addressof(dest)
			memset(dest, 0, size)
		size = section.contents.SizeOfRawData
		dest = allocDest(size, section)
		memmove(dest, addressof(data) + section.contents.PointerToRawData, size)
		section.contents.PhysicalAddress = addressof(dest)
		section = cast(addressof(section) + sizeof(PIMAGE_SECTION_HEADER), PIMAGE_SECTION_HEADER)

def _FinalizeSections(module):
	section = IMAGE_FIRST_SECTION(module.contents.headers)
	imageOffset = PTRTYP(module.contents.headers.contents.OptionalHeader.ImageBase & 0xffffffff00000000) if _isx64 else 0
	numSections = module.contents.headers.contents.FileHeader.NumberOfSections
	checkCharacteristic = lambda sect, flag: 1 if (sect.contents.Characteristics & flag) != 0 else 0
	getPhysAddr = lambda sect: PTRTYP(section.contents.PhysicalAddress) | imageOffset
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
				OutputLastError("Error protecting memory page")
		section = cast(addressof(section) + sizeof(PIMAGE_SECTION_HEADER), PIMAGE_SECTION_HEADER)

def _PerformBaseRelocation(module, delta):
	pass

def _BuildImportTable(module):
	pass

def MemoryLoadLibrary(data):
	pass

def MemoryGetProcAddress(hmod, name):
	module = cast(hmod, PMEMORYMODULE)
	codeBase = module.contents.codeBase
	codeBaseAddr = addressof(codeBase)
	idx = -1
	directory = GET_HEADER_DICTIONARY(module, IMAGE_DIRECTORY_ENTRY_EXPORT)
	if directory.size == 0:
		# No export table
		return None

	pexports = cast(codeBaseAddr + directory.VirtualAddress, PIMAGE_EXPORT_DIRECTORY)
	exports = pexports.contents
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
			if module.modules[i].value != INVALID_HANDLE_VALUE:
				FreeLibrary(module.modules[i])

	if bool(module.codeBase):
		VirtualFree(module.codeBase, 0, MEM_RELEASE);

	HeapFree(GetProcessHeap(), 0, module)