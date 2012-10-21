/* This program is free software. It comes without any warranty, to
 * the extent permitted by applicable law. You can redistribute it
 * and/or modify it under the terms of the Do What The Fuck You Want
 * To Public License, Version 2, as published by Sam Hocevar. See
 * http://sam.zoy.org/wtfpl/COPYING for more details. */

#include <Windows.h>
#include <stdlib.h>
#include <stdio.h>

//DLL entry point
BOOL WINAPI DllMain(HMODULE hMod, DWORD dwReason, LPVOID lpReserved){
	switch(dwReason){
	case DLL_PROCESS_ATTACH:
		printf("Hello World!\n");
		return TRUE;
	case DLL_PROCESS_DETACH:
		printf("Goodbye World!\n");
		return TRUE;
	default:
		printf("Something World!");
		return TRUE;
	}
}