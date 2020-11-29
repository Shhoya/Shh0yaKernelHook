/*
*
* Copyright (c) 2020 by Shh0ya. All rights reserved.
*
* The contents of this file are subject to the Mozilla Public License Version
* 2.0 (the "License")); you may not use this file except in compliance with
* the License. You may obtain a copy of the License at
* http://www.mozilla.org/MPL/
*
* Software distributed under the License is distributed on an "AS IS" basis,
* WITHOUT WARRANTY OF ANY KIND, either express or implied. See the License
* for the specific language governing rights and limitations under the
* License.
*
* The Initial Developer of the Original Code is Shh0ya.
*
*/

#pragma once
#include "Util.h"

#define HOOK_SIZE 14
#define TRAM_SIZE 15 // include NOP(0x90)


// Structures

/*
Basic Informaiton Structure(Build Number, Page Table Entry, etc..)
*/
typedef struct _INITALIZE_BLOCK {
	ULONG			  BuildNumber;
	PVOID			  NtImageBase;
	ULONG			  NtImageSize;
	MiGetPdeAddress_t MiGetPdeAddress;
	MiGetPteAddress_t MiGetPteAddress;
	BOOLEAN			  ModFlag;

}INITIALIZE_BLOCK,*PINITIALIZE_BLOCK;


/*
Page Directory Entry Structure, INTEL SDM Volume 3 refer
*/
typedef union _PDE
{
	struct
	{
		UINT64 ReadAccess : 1;
		UINT64 WriteAccess : 1;
		UINT64 ExecuteAccess : 1;
		UINT64 Reserved1 : 5;
		UINT64 Accessed : 1;
		UINT64 Reserved2 : 1;
		UINT64 UserModeExecute : 1;
		UINT64 Reserved3 : 1;
		UINT64 PageFrameNumber : 36;
		UINT64 Reserved4 : 16;
	};

	UINT64 Flags;
} PDE, *PPDE;

/*
Hooking Data Structure(TargetAddress, Hooking Function, Trampoline Bytes, etc...)
*/
typedef struct _HOOK_DATA {
	PVOID		TargetAddress;
	PVOID		 HookFunction;
	ULONG		PatchSize;
	PPDE		TargetPdeAddress;
	PVOID		TargetPteAddress;
	UCHAR		PatchByte[14];
	UCHAR		TrampolineByte[255];
	ULONGLONG	TrampolineAddress;
	UCHAR		OriginalByte[255];
}HOOK_DATA,*PHOOK_DATA;


// Variables


// Functions

BOOLEAN InitializeKHook(PCWCHAR TargetName, PVOID HookingFunction, ULONG Size);
BOOLEAN InitializeKHookEx(PSTR BytePattern, PVOID HookingFunction, ULONG Size, ULONG RelSize);
BOOLEAN InitializeSystemInformation();
VOID SetupKHook();
VOID EnableKHook();
VOID DisableKHook();

// Hooking Functions // need custom
typedef PVOID(*ExAllocatePoolWithTag_t)(
	POOL_TYPE Type,
	SIZE_T Size,
	ULONG Tag
	);

PVOID ExAllocatePoolWithTagHook(POOL_TYPE Type, SIZE_T Size, ULONG Tag); 
