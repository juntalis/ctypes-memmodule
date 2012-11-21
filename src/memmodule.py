#!/usr/bin/env python
# encoding: utf-8
"""
memmodule.py.py
Created by Charles on 10/25/12.

This program is free software. It comes without any warranty, to
the extent permitted by applicable law. You can redistribute it
and/or modify it under the terms of the Do What The Fuck You Want
To Public License, Version 2, as published by Sam Hocevar. See
http://sam.zoy.org/wtfpl/COPYING for more details.
"""
from extern import pefile as _pefile
from ctypes import *
from ctypes.wintypes import *
import functools, sys, warnings
try:
	import _ctypes_d as _ctypes
except ImportError:
	import _ctypes

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

LoadLibraryA = _kernel32.LoadLibraryA
LoadLibraryA.restype = HMODULE
LoadLibraryA.argtypes = [ LPCSTR ]

LoadLibraryW = _kernel32.LoadLibraryW
LoadLibraryW.restype = HMODULE
LoadLibraryW.argtypes = [ LPCWSTR ]

FreeLibrary = _kernel32.FreeLibrary
FreeLibrary.restype = BOOL
FreeLibrary.argtypes = [ HMODULE ]

IsBadReadPtr = _kernel32.IsBadReadPtr
IsBadReadPtr.restype = BOOL
IsBadReadPtr.argtypes = [ LPCVOID, UINT_PTR ]

realloc = _msvcrt.realloc
realloc.restype = c_void_p
realloc.argtypes = [ c_void_p, c_size_t ]

memcpy = _msvcrt.memcpy
memcpy.restype = c_void_p
memcpy.argtypes = [ c_void_p, c_void_p, c_size_t ]

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

class MEMORYMODULE(Structure):
	_fields_ = [
		('headers', PIMAGE_NT_HEADERS),
		('codeBase', c_void_p),
		('modules', PHMODULE),
		('numModules', c_int),
		('initialized', c_int),
		('pe', POINTER(py_object)),
	]
PMEMORYMODULE = POINTER(MEMORYMODULE)

def _MemoryModuleStruct(cbType):
	class _MEMORYMODULE(Structure):
		_fields_ = [
			('headers', PIMAGE_NT_HEADERS),
			('codeBase', cbType),
			('modules', PHMODULE),
			('numModules', c_int),
			('initialized', c_int)
		]
	return _MEMORYMODULE

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


def GET_PEHEADER_DIRECTORY(pe, idx):
	""" I just realized: why the hell am I documenting internal functions that I plan to hide, anyways? """
	return pe.OPTIONAL_HEADER.DATA_DIRECTORY[idx]


def create_unsigned_buffer(indata, sz = None):
	if sz is None:
		sz = len(indata) + 1
	result = (c_ubyte * sz)()
	for c in range(0, sz - 1):
		result[c] = ord(indata[c])
	return result

def _BuildImportTable(pe, module, dlopen = LoadLibraryW):
	def load_imports(pe):
		importdir = GET_PEHEADER_DIRECTORY(pe, IMAGE_DIRECTORY_ENTRY_IMPORT)
		imports = pe.parse_import_directory(importdir.VirtualAddress, importdir.Size)
		for imp in imports: yield imp.dll
	result = [ HMODULE(dlopen(dll)) for dll in load_imports(pe) ]
	resultCount = len(result)
	modules = (resultCount * HMODULE)()
	for i, m in enumerate(result):
		modules[i] = m
	module.contents.modules = cast(modules, PHMODULE)
	return module.contents.modules

def _CopySections(pe, module):
	codeBase = module.contents.codeBase
	section = IMAGE_FIRST_SECTION(module.contents.headers)
	numSections = pe.FILE_HEADER.NumberOfSections
	for i in range(1, numSections):
		size = pe.OPTIONAL_HEADER.SectionAlignment
		if size > 0:
			destAddr = codeBase + pe.sections[i]
			destbuf = cast(destAddr, LPCVOID)
			VirtualAlloc(destbuf, size, MEM_COMMIT, PAGE_READWRITE )
			section.contents.PhysicalAddress = POINTER_TYPE(destAddr)
			memset(destbuf, 0, size)
		size = section.contents.SizeOfRawData
		dest = cast(codeBase + section.contents.VirtualAddress, c_void_p)
		VirtualAlloc(dest, size, MEM_COMMIT, PAGE_READWRITE )
		memmove(dest, pe.OPTIONAL_HEADER.ImageBase + section.contents.PointerToRawData, size)
		section.contents.PhysicalAddress = dest.value
		section = cast(addressof(section) + sizeof(PIMAGE_SECTION_HEADER), PIMAGE_SECTION_HEADER)
	return module

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
				raise WindowsError("Error protecting memory page")
		section = cast(addressof(section) + sizeof(PIMAGE_SECTION_HEADER), PIMAGE_SECTION_HEADER)

def _PerformBaseRelocation(module, delta):

	codeBaseAddr = module.contents.codeBase

	lpdirectory = GET_HEADER_DICTIONARY(module, IMAGE_DIRECTORY_ENTRY_BASERELOC)
	directory = lpdirectory.contents
	if directory.Size <= 0: return
	relocation = cast(codeBaseAddr + directory.VirtualAddress, PIMAGE_BASE_RELOCATION)
	while relocation.contents.VirtualAddress > 0:
		dest = cast(codeBaseAddr + relocation.contents.VirtualAddress, c_uchar_p)
		relInfo = cast(addressof(relocation) + IMAGE_SIZEOF_BASE_RELOCATION, c_uchar_p)
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

def MemoryLoadLibrary(data):
	pe = _pefile.PE(data=data)
	if pe.DOS_HEADER.e_magic != IMAGE_DOS_SIGNATURE:
		raise WindowsError('Not a valid executable file.')
	if pe.NT_HEADERS.Signature != IMAGE_NT_SIGNATURE:
		raise WindowsError('"No PE header found.')
	codeBaseAddr = pe.OPTIONAL_HEADER.ImageBase
	codeBaseSize = pe.OPTIONAL_HEADER.SizeOfImage
	codeBaseType = (c_ubyte * codeBaseSize)
	codeBase = c_void_p(codeBaseAddr)
	codeBaseAddr = VirtualAlloc(
		codeBase,
		codeBaseSize,
		MEM_RESERVE,
		PAGE_READWRITE
	)
	if not codeBaseAddr:
		codeBaseAddr = VirtualAlloc(
			NULL,
			codeBaseSize,
			MEM_RESERVE,
			PAGE_READWRITE
		)
		if not codeBaseAddr:
			raise WindowsError('Can\'t reserve memory')
		codeBase = cast(codeBaseAddr, c_void_p)

	ubuf = codeBaseType.from_address(pe.OPTIONAL_HEADER.ImageBase)

	result = cast(HeapAlloc(GetProcessHeap(), 0, sizeof(MEMORYMODULE)), PMEMORYMODULE)
	result.contents.codeBase = codeBase
	result.contents.numModules = 0
	result.contents.modules = cast(NULL, PHMODULE)
	result.contents.initialized = 0
	VirtualAlloc(
		codeBase,
		codeBaseSize,
		MEM_COMMIT,
		PAGE_READWRITE
	)
	headerSize = pe.OPTIONAL_HEADER.SizeOfHeaders
	headers = VirtualAlloc(
		codeBase,
		headerSize,
		MEM_COMMIT,
		PAGE_READWRITE
	)

	if not headers:
		raise WindowsError('Could not commit the memory for our PE Headers!')
	sizeh = pe.DOS_HEADER.e_lfanew + headerSize
	pheaders = cast(headers, c_void_p)
	memmove(pheaders, ubuf, sizeh)

	result.contents.headers = cast(headers + pe.DOS_HEADER.e_lfanew, PIMAGE_NT_HEADERS)
	result.contents.headers.contents.OptionalHeader.Image = POINTER_TYPE(codeBaseAddr)
	_CopySections(pe, result)

	locationDelta = SIZE_T(codeBaseAddr - pe.OPTIONAL_HEADER.ImageBase)
	if locationDelta != 0:
		_PerformBaseRelocation(result, locationDelta)

	if not bool(_BuildImportTable(pe, result)):
		MemoryFreeLibrary(result)
		raise WindowsError('Failed to build import table!')

	_FinalizeSections(result)
	if pe.OPTIONAL_HEADER.AddressOfEntryPoint != 0:
		DllEntry = cast(pe.OPTIONAL_HEADER.ImageBase + pe.OPTIONAL_HEADER.AddressOfEntryPoint, DllEntryProc)
		if DllEntry == 0:
			MemoryFreeLibrary(result)
			raise WindowsError('Library has no entry point.\n')
		success = DllEntry(pe.OPTIONAL_HEADER.ImageBase, DLL_PROCESS_ATTACH, 0)
		if not bool(success):
			MemoryFreeLibrary(result)
			raise WindowsError('Library could not be loaded.')
		result.contents.initialized = 1
	result.contents.pe = py_object(pe)
	return cast(result, HMEMORYMODULE)


def MemoryGetProcAddress(hmod, name):
	module = cast(hmod, PMEMORYMODULE)
	codeBaseAddr = module.contents.codeBase
	idx = -1
	lpdirectory = GET_HEADER_DICTIONARY(module, IMAGE_DIRECTORY_ENTRY_EXPORT)
	directory = lpdirectory.contents
	if directory.Size <= 0:
		# No export table
		raise WindowsError('No export table.')

	lpexports = cast(codeBaseAddr + directory.VirtualAddress, PIMAGE_EXPORT_DIRECTORY)
	exports = lpexports.contents
	if exports.NumberOfNames == 0 or exports.NumberOfFunctions == 0:
		# DLL doesn't export anything
		raise WindowsError('DLL doesn\'t export anything.')

	nameRef = cast(codeBaseAddr + exports.AddressOfNames, PDWORD)
	ordinal = cast(codeBaseAddr + exports.AddressOfNames, PWORD)
	for i in range(1, exports.NumberOfNames):
		if name.lower() == cast(codeBaseAddr + nameRef.contents, LPCSTR).value == 0:
			idx = ordinal.contents
			break
		ordinal = cast(addressof(ordinal) + sizeof(PWORD), PWORD)

	if idx == -1:
		raise WindowsError('Ordinal of -1')
	if idx > exports.NumberOfFunctions:
		raise WindowsError('Ordinal number higher than our actual count.')
	funcOffset = cast(codeBaseAddr + exports.AddressOfFunctions + ( idx * 4 ), PDWORD).contents
	return FARPROC(codeBaseAddr + funcOffset)






