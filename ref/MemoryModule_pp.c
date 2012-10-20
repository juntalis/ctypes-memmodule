
/*
 * Memory DLL loading code
 * Version 0.0.3
 *
 * Copyright (c) 2004-2012 by Joachim Bauch / mail@joachim-bauch.de
 * http://www.joachim-bauch.de
 *
 * The contents of this file are subject to the Mozilla Public License Version
 * 2.0 (the "License"); you may not use this file except in compliance with
 * the License. You may obtain a copy of the License at
 * http://www.mozilla.org/MPL/
 *
 * Software distributed under the License is distributed on an "AS IS" basis,
 * WITHOUT WARRANTY OF ANY KIND, either express or implied. See the License
 * for the specific language governing rights and limitations under the
 * License.
 *
 * The Original Code is MemoryModule.c
 *
 * The Initial Developer of the Original Code is Joachim Bauch.
 *
 * Portions created by Joachim Bauch are Copyright (C) 2004-2012
 * Joachim Bauch. All Rights Reserved.
 *
 */

// disable warnings about pointer <-> DWORD conversions
#pragma warning( disable : 4311 4312 )

#include <Windows.h>
#include <winnt.h>

// Vista SDKs no longer define IMAGE_SIZEOF_BASE_RELOCATION!?
#include "MemoryModule.h"
typedef struct {
	PIMAGE_NT_HEADERS headers;
	unsigned char *codeBase;
	HMODULE *modules;
	int numModules;
	int initialized;
} MEMORYMODULE, *PMEMORYMODULE;

typedef BOOL (__stdcall *DllEntryProc)(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpReserved);

static void
CopySections(const unsigned char *data, PIMAGE_NT_HEADERS old_headers, PMEMORYMODULE module)
{
	int i, size;
	unsigned char *codeBase = module->codeBase;
	unsigned char *dest;
	PIMAGE_SECTION_HEADER section = ((PIMAGE_SECTION_HEADER) ((ULONG_PTR)(module->headers) + ((LONG)(LONG_PTR)&(((IMAGE_NT_HEADERS *)0)->OptionalHeader)) + ((module->headers))->FileHeader.SizeOfOptionalHeader ));
	for (i=0; i<module->headers->FileHeader.NumberOfSections; i++, section++) {
		if (section->SizeOfRawData == 0) {
			// section doesn't contain data in the dll itself, but may define
			// uninitialized data
			size = old_headers->OptionalHeader.SectionAlignment;
			if (size > 0) {
				dest = (unsigned char *)VirtualAlloc(codeBase + section->VirtualAddress,
					size,
					0x1000,
					0x04);

				section->Misc.PhysicalAddress = (DWORD)dest;
				memset(dest, 0, size);
			}

			// section is empty
			continue;
		}

		// commit memory block and copy data from dll
		dest = (unsigned char *)VirtualAlloc(codeBase + section->VirtualAddress,
							section->SizeOfRawData,
							0x1000,
							0x04);
		memcpy(dest, data + section->PointerToRawData, section->SizeOfRawData);
		section->Misc.PhysicalAddress = (DWORD)dest;
	}
}

// Protection flags for memory pages (Executable, Readable, Writeable)
static int ProtectionFlags[2][2][2] = {
	{
		// not executable
		{0x01, 0x08},
		{0x02, 0x04},
	}, {
		// executable
		{0x10, 0x80},
		{0x20, 0x40},
	},
};

static void
FinalizeSections(PMEMORYMODULE module)
{
	int i;
	PIMAGE_SECTION_HEADER section = ((PIMAGE_SECTION_HEADER) ((ULONG_PTR)(module->headers) + ((LONG)(LONG_PTR)&(((IMAGE_NT_HEADERS *)0)->OptionalHeader)) + ((module->headers))->FileHeader.SizeOfOptionalHeader ));

	// loop through all sections and change access flags
	for (i=0; i<module->headers->FileHeader.NumberOfSections; i++, section++) {
		DWORD protect, oldProtect, size;
		int executable = (section->Characteristics & 0x20000000) != 0;
		int readable =   (section->Characteristics & 0x40000000) != 0;
		int writeable =  (section->Characteristics & 0x80000000) != 0;

		if (section->Characteristics & 0x02000000) {
			// section is not needed any more and can safely be freed
			VirtualFree((LPVOID)((DWORD)section->Misc.PhysicalAddress | 0), section->SizeOfRawData, 0x4000);
			continue;
		}

		// determine protection flags based on characteristics
		protect = ProtectionFlags[executable][readable][writeable];
		if (section->Characteristics & 0x04000000) {
			protect |= 0x200;
		}

		// determine size of region
		size = section->SizeOfRawData;
		if (size == 0) {
			if (section->Characteristics & 0x00000040) {
				size = module->headers->OptionalHeader.SizeOfInitializedData;
			} else if (section->Characteristics & 0x00000080) {
				size = module->headers->OptionalHeader.SizeOfUninitializedData;
			}
		}

		if (size > 0) {
			// change memory access flags
			if (VirtualProtect((LPVOID)((DWORD)section->Misc.PhysicalAddress | 0), size, protect, &oldProtect) == 0)

			;
		}
	}

}

static void
PerformBaseRelocation(PMEMORYMODULE module, SIZE_T delta)
{
	DWORD i;
	unsigned char *codeBase = module->codeBase;

	PIMAGE_DATA_DIRECTORY directory = &(module)->headers->OptionalHeader.DataDirectory[5];
	if (directory->Size > 0) {
		PIMAGE_BASE_RELOCATION relocation = (PIMAGE_BASE_RELOCATION) (codeBase + directory->VirtualAddress);
		for (; relocation->VirtualAddress > 0; ) {
			unsigned char *dest = codeBase + relocation->VirtualAddress;
			unsigned short *relInfo = (unsigned short *)((unsigned char *)relocation + (sizeof(IMAGE_BASE_RELOCATION)));
			for (i=0; i<((relocation->SizeOfBlock-(sizeof(IMAGE_BASE_RELOCATION))) / 2); i++, relInfo++) {
				DWORD *patchAddrHL;

				int type, offset;

				// the upper 4 bits define the type of relocation
				type = *relInfo >> 12;
				// the lower 12 bits define the offset
				offset = *relInfo & 0xfff;

				switch (type)
				{
				case 0:
					// skip relocation
					break;

				case 3:
					// change complete 32 bit address
					patchAddrHL = (DWORD *) (dest + offset);
					*patchAddrHL += delta;
					break;

				default:
					//printf("Unknown relocation: %d\n", type);
					break;
				}
			}

			// advance to next relocation block
			relocation = (PIMAGE_BASE_RELOCATION) (((char *) relocation) + relocation->SizeOfBlock);
		}
	}
}

static int
BuildImportTable(PMEMORYMODULE module)
{
	int result=1;
	unsigned char *codeBase = module->codeBase;

	PIMAGE_DATA_DIRECTORY directory = &(module)->headers->OptionalHeader.DataDirectory[1];
	if (directory->Size > 0) {
		PIMAGE_IMPORT_DESCRIPTOR importDesc = (PIMAGE_IMPORT_DESCRIPTOR) (codeBase + directory->VirtualAddress);
		for (; !IsBadReadPtr(importDesc, sizeof(IMAGE_IMPORT_DESCRIPTOR)) && importDesc->Name; importDesc++) {
			DWORD *thunkRef;
			FARPROC *funcRef;
			HMODULE handle = LoadLibraryW((LPCSTR) (codeBase + importDesc->Name));
			if (handle == ((void *)0)) {

				result = 0;
				break;
			}

			module->modules = (HMODULE *)realloc(module->modules, (module->numModules+1)*(sizeof(HMODULE)));
			if (module->modules == ((void *)0)) {
				result = 0;
				break;
			}

			module->modules[module->numModules++] = handle;
			if (importDesc->OriginalFirstThunk) {
				thunkRef = (DWORD *) (codeBase + importDesc->OriginalFirstThunk);
				funcRef = (FARPROC *) (codeBase + importDesc->FirstThunk);
			} else {
				// no hint table
				thunkRef = (DWORD *) (codeBase + importDesc->FirstThunk);
				funcRef = (FARPROC *) (codeBase + importDesc->FirstThunk);
			}
			for (; *thunkRef; thunkRef++, funcRef++) {
				if (((*thunkRef & 0x80000000) != 0)) {
					*funcRef = (FARPROC)GetProcAddress(handle, (LPCSTR)(*thunkRef & 0xffff));
				} else {
					PIMAGE_IMPORT_BY_NAME thunkData = (PIMAGE_IMPORT_BY_NAME) (codeBase + (*thunkRef));
					*funcRef = (FARPROC)GetProcAddress(handle, (LPCSTR)&thunkData->Name);
				}
				if (*funcRef == 0) {
					result = 0;
					break;
				}
			}

			if (!result) {
				break;
			}
		}
	}

	return result;
}

HMEMORYMODULE MemoryLoadLibrary(const void *data)
{
	PMEMORYMODULE result;
	PIMAGE_DOS_HEADER dos_header;
	PIMAGE_NT_HEADERS old_header;
	unsigned char *code, *headers;
	SIZE_T locationDelta;
	DllEntryProc DllEntry;
	BOOL successfull;

	dos_header = (PIMAGE_DOS_HEADER)data;
	if (dos_header->e_magic != 0x5A4D) {

		return ((void *)0);
	}

	old_header = (PIMAGE_NT_HEADERS)&((const unsigned char *)(data))[dos_header->e_lfanew];
	if (old_header->Signature != 0x00004550) {

		return ((void *)0);
	}

	// reserve memory for image of library
	code = (unsigned char *)VirtualAlloc((LPVOID)(old_header->OptionalHeader.ImageBase),
		old_header->OptionalHeader.SizeOfImage,
		0x2000,
		0x04);

    if (code == ((void *)0)) {
        // try to allocate memory at arbitrary position
        code = (unsigned char *)VirtualAlloc(((void *)0),
            old_header->OptionalHeader.SizeOfImage,
            0x2000,
            0x04);
		if (code == ((void *)0)) {

			return ((void *)0);
		}
	}

	result = (PMEMORYMODULE)HeapAlloc(GetProcessHeap(), 0, sizeof(MEMORYMODULE));
	result->codeBase = code;
	result->numModules = 0;
	result->modules = ((void *)0);
	result->initialized = 0;

	// XXX: is it correct to commit the complete memory region at once?
    //      calling DllEntry raises an exception if we don't...
	VirtualAlloc(code,
		old_header->OptionalHeader.SizeOfImage,
		0x1000,
		0x04);

	// commit memory for headers
	headers = (unsigned char *)VirtualAlloc(code,
		old_header->OptionalHeader.SizeOfHeaders,
		0x1000,
		0x04);

	// copy PE header to code
	memcpy(headers, dos_header, dos_header->e_lfanew + old_header->OptionalHeader.SizeOfHeaders);
	result->headers = (PIMAGE_NT_HEADERS)&((const unsigned char *)(headers))[dos_header->e_lfanew];

	// update position
	result->headers->OptionalHeader.ImageBase = (DWORD)code;

	// copy sections from DLL file block to new memory location
	CopySections(data, old_header, result);

	// adjust base address of imported data
	locationDelta = (SIZE_T)(code - old_header->OptionalHeader.ImageBase);
	if (locationDelta != 0) {
		PerformBaseRelocation(result, locationDelta);
	}

	// load required dlls and adjust function table of imports
	if (!BuildImportTable(result)) {
		goto error;
	}

	// mark memory pages depending on section headers and release
	// sections that are marked as "discardable"
	FinalizeSections(result);

	// get entry point of loaded library
	if (result->headers->OptionalHeader.AddressOfEntryPoint != 0) {
		DllEntry = (DllEntryProc) (code + result->headers->OptionalHeader.AddressOfEntryPoint);
		if (DllEntry == 0) {

			goto error;
		}

		// notify library about attaching to process
		successfull = (*DllEntry)((HINSTANCE)code, 1, 0);
		if (!successfull) {

			goto error;
		}
		result->initialized = 1;
	}

	return (HMEMORYMODULE)result;

error:
	// cleanup
	MemoryFreeLibrary(result);
	return ((void *)0);
}

FARPROC MemoryGetProcAddress(HMEMORYMODULE module, const char *name)
{
	unsigned char *codeBase = ((PMEMORYMODULE)module)->codeBase;
	int idx=-1;
	DWORD i, *nameRef;
	WORD *ordinal;
	PIMAGE_EXPORT_DIRECTORY exports;
	PIMAGE_DATA_DIRECTORY directory = &((PMEMORYMODULE)module)->headers->OptionalHeader.DataDirectory[0];
	if (directory->Size == 0) {
		// no export table found
		return ((void *)0);
	}

	exports = (PIMAGE_EXPORT_DIRECTORY) (codeBase + directory->VirtualAddress);
	if (exports->NumberOfNames == 0 || exports->NumberOfFunctions == 0) {
		// DLL doesn't export anything
		return ((void *)0);
	}

	// search function name in list of exported names
	nameRef = (DWORD *) (codeBase + exports->AddressOfNames);
	ordinal = (WORD *) (codeBase + exports->AddressOfNameOrdinals);
	for (i=0; i<exports->NumberOfNames; i++, nameRef++, ordinal++) {
		if (stricmp(name, (const char *) (codeBase + (*nameRef))) == 0) {
			idx = *ordinal;
			break;
		}
	}

	if (idx == -1) {
		// exported symbol not found
		return ((void *)0);
	}

	if ((DWORD)idx > exports->NumberOfFunctions) {
		// name <-> ordinal number don't match
		return ((void *)0);
	}

	// AddressOfFunctions contains the RVAs to the "real" functions
	return (FARPROC) (codeBase + (*(DWORD *) (codeBase + exports->AddressOfFunctions + (idx*4))));
}

void MemoryFreeLibrary(HMEMORYMODULE mod)
{
	int i;
	PMEMORYMODULE module = (PMEMORYMODULE)mod;

	if (module != ((void *)0)) {
		if (module->initialized != 0) {
			// notify library about detaching from process
			DllEntryProc DllEntry = (DllEntryProc) (module->codeBase + module->headers->OptionalHeader.AddressOfEntryPoint);
			(*DllEntry)((HINSTANCE)module->codeBase, 0, 0);
			module->initialized = 0;
		}

		if (module->modules != ((void *)0)) {
			// free previously opened libraries
			for (i=0; i<module->numModules; i++) {
				if (module->modules[i] != ((HANDLE)(LONG_PTR)-1)) {
					FreeLibrary(module->modules[i]);
				}
			}

			free(module->modules);
		}

		if (module->codeBase != ((void *)0)) {
			// release memory of library
			VirtualFree(module->codeBase, 0, 0x8000);
		}

		HeapFree(GetProcessHeap(), 0, module);
	}
}
