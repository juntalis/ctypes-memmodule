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
from ctypes import *
from ctypes.wintypes import *
import pefile as pe

# Our public debug flag
debug_output = __debug__

# Our system DLLs
_kernel32 = WinDLL('kernel32')
_msvcrt = CDLL('msvcrt')

# Check if the current machine is x64 or x86
isx64 = sizeof(c_void_p) == sizeof(c_ulonglong)

# Some general type declarations
PWORD = POINTER(WORD)
PDWORD = POINTER(DWORD)
PHMODULE = POINTER(HMODULE)
LONG_PTR = c_longlong if isx64 else LONG
ULONG_PTR = c_ulonglong if isx64 else DWORD
UINT_PTR = c_ulonglong if isx64 else c_uint
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


#noinspection PyTypeChecker
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


#noinspection PyTypeChecker
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
		('Name', DWORD),
		('Base', DWORD),
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


#noinspection PyTypeChecker
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

# Type declarations specific to our module.
DllEntryProc = WINFUNCTYPE(BOOL, HINSTANCE, DWORD, LPVOID)
PDllEntryProc = POINTER(DllEntryProc)
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

_IMAGE_ORDINAL_FLAG64 = 0x8000000000000000
_IMAGE_ORDINAL_FLAG32 = 0x80000000
_IMAGE_ORDINAL64 = lambda o: (o & 0xffff)
_IMAGE_ORDINAL32 = lambda o: (o & 0xffff)
_IMAGE_SNAP_BY_ORDINAL64 = lambda o: ((o & _IMAGE_ORDINAL_FLAG64) != 0)
_IMAGE_SNAP_BY_ORDINAL32 = lambda o: ((o & _IMAGE_ORDINAL_FLAG32) != 0)
IMAGE_ORDINAL = _IMAGE_ORDINAL64 if isx64 else _IMAGE_ORDINAL32
IMAGE_SNAP_BY_ORDINAL = _IMAGE_SNAP_BY_ORDINAL64 if isx64 else _IMAGE_SNAP_BY_ORDINAL32
IMAGE_ORDINAL_FLAG = _IMAGE_ORDINAL_FLAG64 if isx64 else _IMAGE_ORDINAL_FLAG32

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
	]
PMEMORYMODULE = POINTER(MEMORYMODULE)

#noinspection PyTypeChecker,PyUnresolvedReferences
def as_unsigned_buffer(sz=None, indata=None):
	if sz is None:
		if indata is None:
			raise Exception('Must specify either initial data, or a buffer size.')
		sz = len(indata)
	rtype = (c_ubyte * sz)
	if indata is None:
		return rtype
	else:
		tindata = type(indata)
		if tindata in [ long, int ]:
			return rtype.from_address(indata)
		elif tindata in [ c_void_p, DWORD, POINTER_TYPE ] or hasattr(indata, 'value') and type(indata.value) in [ long, int ]:
			return rtype.from_address(indata.value)
		else:
			return rtype.from_address(addressof(indata))

def create_unsigned_buffer(sz, indata):
	res = as_unsigned_buffer(sz)()
	for i, c in enumerate(indata):
		if type(c) in [ basestring, str, unicode ]:
			c = ord(c)
		res[i] = c
	return res

class MemoryModule(pe.PE):

	_foffsets_ = {}

	def __init__(self, name = None, data = None, debug=False):
		self._debug_ = debug or debug_output
		pe.PE.__init__(self, name, data, fast_load=True)
		self.load_module()

	def dbg(self, msg, *args):
		if not self._debug_: return
		if len(args) > 0:
			msg = msg % tuple(args)
		print 'DEBUG: %s' % msg

	def load_module(self):
		if not self.is_dll():
			raise WindowsError('The specified module does not appear to be a DLL.')
		if self.PE_TYPE == pe.OPTIONAL_HEADER_MAGIC_PE and isx64:
			raise WindowsError('The dll you attempted to load appears to be an 32-bit DLL, but you are using a 64-bit version of Python.')
		elif self.PE_TYPE == pe.OPTIONAL_HEADER_MAGIC_PE_PLUS and not isx64:
			raise WindowsError('The dll you attempted to load appears to be an 64-bit DLL, but you are using a 32-bit version of Python.')
		self._codebaseaddr = VirtualAlloc(
			self.OPTIONAL_HEADER.ImageBase,
			self.OPTIONAL_HEADER.SizeOfImage,
			MEM_RESERVE,
			PAGE_READWRITE
		)

		if not bool(self._codebaseaddr):
			self._codebaseaddr = VirtualAlloc(
				NULL,
				self.OPTIONAL_HEADER.SizeOfImage,
				MEM_RESERVE,
				PAGE_READWRITE
			)
			if not bool(self._codebaseaddr):
				raise WindowsError('Can\'t reserve memory')

		codebase = self._codebaseaddr
		self.dbg('Reserved %d bytes of memory for our module at address: 0x%x', self.OPTIONAL_HEADER.SizeOfImage, codebase)
		self.memmodule = cast(HeapAlloc(GetProcessHeap(), 0, sizeof(MEMORYMODULE)), PMEMORYMODULE)
		self.memmodule.contents.codeBase = codebase
		self.memmodule.contents.numModules = 0
		self.memmodule.contents.modules = cast(NULL, PHMODULE)
		self.memmodule.contents.initialized = 0

		# Commit our memory.
		VirtualAlloc(
			codebase,
			self.OPTIONAL_HEADER.SizeOfImage,
			MEM_COMMIT,
			PAGE_READWRITE
		)
		self._headersaddr = VirtualAlloc(
			codebase,
			self.OPTIONAL_HEADER.SizeOfHeaders,
			MEM_COMMIT,
			PAGE_READWRITE
		)
		if not bool(self._headersaddr):
			raise WindowsError('Could not commit the memory for our PE Headers!')

		szheaders = self.DOS_HEADER.e_lfanew + self.OPTIONAL_HEADER.SizeOfHeaders
		tmpheaders = create_unsigned_buffer(szheaders, self.__data__[:szheaders])
		memmove(self._headersaddr, cast(tmpheaders, c_void_p), szheaders)
		del tmpheaders

		self._headersaddr += self.DOS_HEADER.e_lfanew
		self.memmodule.contents.headers = cast(self._headersaddr, PIMAGE_NT_HEADERS)
		self.memmodule.contents.headers.contents.OptionalHeader.ImageBase = POINTER_TYPE(self._codebaseaddr)
		self.dbg('Copying sections to our memory block.')
		self.copy_sections()

		# Actually think pefile handles the relocation stuff, but we'll do this on our own just to be safe.
		self.dbg('Checking for base relocations..')
		locationDelta = codebase - self.OPTIONAL_HEADER.SizeOfImage
		if locationDelta != 0:
			self.dbg('Detected relocations - Performing base relocations..')
			self.perform_base_relocations(locationDelta)

		self.dbg('Building import table..')
		self.build_import_table()
		self.dbg('Finalizing sections..')
		self.finalize_sections()

		entryaddr = self.memmodule.contents.headers.contents.OptionalHeader.AddressOfEntryPoint
		self.dbg('Checking dll for entry point..')
		if entryaddr != 0:
			entryaddr += codebase
			self.dbg('Found entry at address: 0x%x', entryaddr)
			DllEntry = DllEntryProc(entryaddr)
			if not bool(DllEntry):
				self.free_library(self.memmodule)
				raise WindowsError('Library has no entry point.\n')
			success = DllEntry(codebase, DLL_PROCESS_ATTACH, 0)
			if not bool(success):
				self.free_library(self.memmodule)
				raise WindowsError('Library could not be loaded.')
			self.memmodule.contents.initialized = 1

	#noinspection PyUnresolvedReferences
	def IMAGE_FIRST_SECTION(self):
		"""
		Couldn't find any documentation on this on MSDN, but judging from the name of the macro, and the actual code,
		it looks like it finds the first section header following the OptionalHeader of an image.

		:return: Our first section header.
		:rtype: PIMAGE_SECTION_HEADER
		"""
		return self._headersaddr + IMAGE_NT_HEADERS.OptionalHeader.offset + self.FILE_HEADER.SizeOfOptionalHeader

	def GET_HEADER_DIRECTORY(self, idx):
		""" I just realized: why the hell am I documenting internal functions that I plan to hide, anyways? """
		return pointer(self.memmodule.contents.headers.contents.OptionalHeader.DataDirectory[idx])

	def copy_sections(self):
		codebase = self._codebaseaddr
		sectionaddr = self.IMAGE_FIRST_SECTION()
		numSections = self.memmodule.contents.headers.contents.FileHeader.NumberOfSections
		i = 0
		while i < numSections:
			idx = i
			i += 1
			section = cast(sectionaddr, PIMAGE_SECTION_HEADER)
			if section.contents.SizeOfRawData == 0:
				size = self.OPTIONAL_HEADER.SectionAlignment
				if size > 0:
					destBaseAddr = codebase + self.sections[idx].VirtualAddress
					dest = VirtualAlloc(destBaseAddr, size, MEM_COMMIT, PAGE_READWRITE )
					section.contents.PhysicalAddress = POINTER_TYPE(dest)
					memset(dest, 0, size)
				continue
			size = section.contents.SizeOfRawData
			dest = VirtualAlloc(codebase + section.contents.VirtualAddress, size, MEM_COMMIT, PAGE_READWRITE )
			section.contents.PhysicalAddress = POINTER_TYPE(dest)
			tmpdata = create_unsigned_buffer(size, self.__data__[section.contents.PointerToRawData:size])
			memmove(dest, tmpdata, size)
			del tmpdata
			self.dbg('Copied section %s to address: 0x%x', string_at(section.contents.Name), dest)
			sectionaddr += sizeof(IMAGE_SECTION_HEADER)

	def finalize_sections(self):
		sectionaddr = self.IMAGE_FIRST_SECTION()
		numSections = self.memmodule.contents.headers.contents.FileHeader.NumberOfSections
		imageOffset = POINTER_TYPE(self.memmodule.contents.headers.contents.OptionalHeader.ImageBase & 0xffffffff00000000) if isx64 else POINTER_TYPE(0)
		checkCharacteristic = lambda sect, flag: 1 if (sect.contents.Characteristics & flag) != 0 else 0
		getPhysAddr = lambda sect: section.contents.PhysicalAddress | imageOffset.value
		i = 0
		while i < numSections:
			i += 1
			section = cast(sectionaddr, PIMAGE_SECTION_HEADER)
			oldProtect = DWORD(0)
			executable = checkCharacteristic(section, IMAGE_SCN_MEM_EXECUTE)
			readable = checkCharacteristic(section, IMAGE_SCN_MEM_READ)
			writeable = checkCharacteristic(section, IMAGE_SCN_MEM_WRITE)

			if checkCharacteristic(section, IMAGE_SCN_MEM_DISCARDABLE):
				addr = getPhysAddr(section)
				VirtualFree(addr, section.contents.SizeOfRawData, MEM_DECOMMIT)
				continue

			protect = ProtectionFlags[executable][readable][writeable]
			if checkCharacteristic(section, IMAGE_SCN_MEM_NOT_CACHED):
				protect |= PAGE_NOCACHE

			size = section.contents.SizeOfRawData
			if size == 0:
				if checkCharacteristic(section, IMAGE_SCN_CNT_INITIALIZED_DATA):
					size = self.memmodule.contents.headers.contents.OptionalHeader.SizeOfInitializedData
				elif checkCharacteristic(section, IMAGE_SCN_CNT_UNINITIALIZED_DATA):
					size = self.memmodule.contents.headers.contents.OptionalHeader.SizeOfUninitializedData
			if size > 0:
				addr = getPhysAddr(section)
				if VirtualProtect(addr, size, protect, byref(oldProtect)) == 0:
					raise WindowsError("Error protecting memory page")
			sectionaddr += sizeof(IMAGE_SECTION_HEADER)

	#noinspection PyUnresolvedReferences
	def perform_base_relocations(self, delta):
		codeBaseAddr = self._codebaseaddr
		directory = self.GET_HEADER_DIRECTORY(IMAGE_DIRECTORY_ENTRY_BASERELOC)
		if directory.contents.Size <= 0: return
		maxreloc = lambda r: (r.SizeOfBlock - IMAGE_SIZEOF_BASE_RELOCATION) / 2
		relocaddr = codeBaseAddr + directory.contents.VirtualAddress
		relocation = IMAGE_BASE_RELOCATION.from_address(relocaddr)
		while relocation.VirtualAddress > 0:
			i = 0
			dest = codeBaseAddr + relocation.VirtualAddress
			relinfoaddr = relocaddr + IMAGE_SIZEOF_BASE_RELOCATION
			while i < maxreloc(relocaddr):
				relinfo = c_ushort.from_address(relinfoaddr)
				type = relinfo.value >> 12
				offset = relinfo.value & 0xfff
				if type == IMAGE_REL_BASED_HIGHLOW or (type == IMAGE_REL_BASED_DIR64 and isx64):
					patchAddrHL = cast(dest + offset, LP_POINTER_TYPE)
					patchAddrHL.contents += delta
				relinfoaddr += sizeof(c_ushort_p)
				i += 1
			relocaddr += relocation.SizeOfBlock
			relocation = IMAGE_BASE_RELOCATION.from_address(relocaddr)

	def build_import_table(self, dlopen = LoadLibraryW):
		codebase = self._codebaseaddr
		directory = self.GET_HEADER_DIRECTORY(IMAGE_DIRECTORY_ENTRY_IMPORT)
		if directory.contents.Size <= 0:
			self.dbg('Import directory\'s size appears to be zero or less. Skipping.. (Probably not good)')
			return
		importdescaddr = codebase + directory.contents.VirtualAddress
		check = not bool(IsBadReadPtr(importdescaddr, sizeof(IMAGE_IMPORT_DESCRIPTOR)))
		if not check:
			self.dbg('IsBadReadPtr(address) at address: 0x%x returned true', importdescaddr)
		while check:
			self.dbg('Found importdesc at address: 0x%x', importdescaddr)
			importdesc = IMAGE_IMPORT_DESCRIPTOR.from_address(importdescaddr)
			dll = codebase + importdesc.Name
			if not bool(importdesc.Name):
				self.dbg('Importdesc at address 0x%x name is NULL. Skipping load library', importdescaddr)
				hmod = dll
			else:
				dll = string_at(dll)
				self.dbg('Found imported DLL, %s. Loading..', dll)
				hmod = dlopen(dll)
				if not bool(hmod): raise WindowsError('Failed to load library, %s' % dll)
				self.memmodule.contents.modules = realloc(
					self.memmodule.contents.modules,
					(self.memmodule.contents.modules.numModules + 1) * sizeof(HMODULE)
				)
				if not bool(self.memmodule.contents.modules):
					raise WindowsError('Failed to allocate additional room for our new import.')

				self.memmodule.contents.modules[self.memmodule.contents.numModules] = hmod
				self.memmodule.contents.numModules += 1


			thunkrefaddr = funcrefaddr = codebase + importdesc.FirstThunk
			if importdesc.OriginalFirstThunk > 0:
				thunkrefaddr = codebase + importdesc.OriginalFirstThunk
			thunkref = POINTER_TYPE.from_address(thunkrefaddr)
			while bool(thunkref.value):
				funcref = cast(funcrefaddr, PFARPROC)
				if IMAGE_SNAP_BY_ORDINAL(thunkref.value):
					thunkData = IMAGE_ORDINAL(thunkref.value)
					self.dbg('Found import by ordinal entry, 0x%x', thunkData)
					funcref.contents = GetProcAddress(hmod, cast(thunkData, LPCSTR))
				else:
					thunkData = codebase + thunkref.value + IMAGE_IMPORT_BY_NAME.Name.offset
					self.dbg('Found import by name entry, at address 0x%x', thunkData)
					thunkData = cast(pointer(c_void_p(thunkData)), c_char_p)
					funcref.contents = GetProcAddress(hmod, thunkData)
				if not bool(funcref):
					raise WindowsError('Could not locate function for thunkref %d', thunkref.value)
				funcrefaddr += sizeof(PFARPROC)
				thunkrefaddr += sizeof(POINTER_TYPE)
				thunkref = POINTER_TYPE.from_address(thunkrefaddr)
			importdescaddr += sizeof(PIMAGE_IMPORT_DESCRIPTOR)
			check = not bool(IsBadReadPtr(importdescaddr, sizeof(IMAGE_IMPORT_DESCRIPTOR)))

	def free_library(self):
		if not bool(self.memmodule): return
		pmodule = pointer(self.memmodule)
		if self.memmodule.initialized != 0:
			DllEntry = DllEntryProc(addressof(self.memmodule.codeBase) + self.memmodule.headers.contents.OptionalHeader.AddressOfEntryPoint)
			DllEntry(cast(self.memmodule.codeBase, HINSTANCE), DLL_PROCESS_DETACH, 0)
			pmodule.contents.initialized = 0
		if bool(self.memmodule.modules) and self.memmodule.numModules > 0:
			for i in range(1, self.memmodule.numModules):
				if self.memmodule.modules[i] != HANDLE(INVALID_HANDLE_VALUE):
					FreeLibrary(self.memmodule.modules[i])

		if bool(self._codebaseaddr):
			VirtualFree(self._codebaseaddr, 0, MEM_RELEASE)

		HeapFree(GetProcessHeap(), 0, self.memmodule)
		self.close()

	#noinspection PyUnresolvedReferences
	def _proc_addr_by_ordinal(self, idx):
		codebase = self._codebaseaddr
		if idx == -1:
			raise WindowsError('We could not the function specified!')
		elif idx > self._exports_.NumberOfFunctions:
			raise WindowsError('Ordinal number higher than our actual count.')
		funcoffset = DWORD.from_address(codebase + self._exports_.AddressOfFunctions + (idx * 4))
		return funcoffset.value

	#noinspection PyUnresolvedReferences
	def _proc_addr_by_name(self, name):
		codebase = self._codebaseaddr
		exports = self._exports_
		if exports.NumberOfNames == 0:
			raise WindowsError('DLL doesn\'t export anything.')

		ordinal = -1
		name = name.lower()
		namerefaddr = codebase + exports.AddressOfNames
		ordinaladdr = codebase + exports.AddressOfNameOrdinals
		i = 0
		while i < exports.NumberOfNames:
			nameref = DWORD.from_address(namerefaddr)
			funcname = string_at(codebase + nameref.value).lower()
			if funcname == name:
				ordinal = WORD.from_address(ordinaladdr).value
			i += 1
			namerefaddr += sizeof(PDWORD)
			ordinaladdr += sizeof(PWORD)
		return self._proc_addr_by_ordinal(ordinal)

	#noinspection PyUnresolvedReferences
	def get_proc_addr(self, name_or_ordinal):
		codebase = self._codebaseaddr
		if not hasattr(self, '_exports_'):
			directory = self.GET_HEADER_DIRECTORY(IMAGE_DIRECTORY_ENTRY_EXPORT)
			# No export table
			if directory.contents.Size <= 0: raise WindowsError('No export table.')
			self._exports_ = IMAGE_EXPORT_DIRECTORY.from_address(codebase + directory.contents.VirtualAddress)
			if self._exports_.NumberOfFunctions == 0:
				# DLL doesn't export anything
				raise WindowsError('DLL doesn\'t export anything.')
		targ = type(name_or_ordinal)
		if targ in [ unicode, str, basestring ]:
			name_or_ordinal = str(name_or_ordinal)
			procaddr_func = self._proc_addr_by_name
		elif targ in [ int, long ]:
			name_or_ordinal = int(name_or_ordinal)
			procaddr_func = self._proc_addr_by_ordinal
		else:
			raise TypeError('Don\'t know what to do with name/ordinal of type: %s!' % targ)

		if not name_or_ordinal in self._foffsets_:
			self._foffsets_[name_or_ordinal] = procaddr_func(name_or_ordinal)
		return FARPROC(codebase + self._foffsets_[name_or_ordinal])

