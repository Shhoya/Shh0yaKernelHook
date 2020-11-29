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
#include "Hook.h"
#include "Scan.h"

INITIALIZE_BLOCK InitializeBlock = { 0, };
HOOK_DATA HookData = { 0, };

BOOLEAN InitializeKHook(PCWCHAR TargetName, PVOID HookingFunction, ULONG Size)
{
	UNICODE_STRING RoutineName = { 0, };
	PVOID TargetAddress = GetRoutineAddress(&RoutineName, TargetName);
	if (!TargetAddress)
	{
		ErrLog("Not an export routine. Please use InitializeKHookEx\n");
		return FALSE;
	}

	HookData.TargetAddress = TargetAddress;
	HookData.HookFunction  = HookingFunction;
	HookData.PatchSize = Size;
	HookData.TrampolineAddress = (DWORD64)HookData.TargetAddress + Size;

	if (!InitializeSystemInformation())
	{
		return FALSE;
	}

	if (InitializeBlock.ModFlag)
	{
		HookData.TargetPdeAddress = InitializeBlock.MiGetPdeAddress(TargetAddress);
		Log("%ws PDE Address : 0x%llX\n", TargetName, HookData.TargetPdeAddress);
		if (HookData.TargetPdeAddress->WriteAccess != 1)
		{
			HookData.TargetPdeAddress->WriteAccess = 1;
		}
		// TODO
		//HookData.TargetPteAddress = InitializeBlock.MiGetPteAddress(ExAllocatePoolWithTag);
	}

	SetupKHook(Size);
	Log("Hooking data initialization complete\n");
	return TRUE;
}

BOOLEAN InitializeKHookEx(PSTR BytePattern, PVOID HookingFunction, ULONG Size, ULONG RelSize)
{
	if (!InitializeSystemInformation())
	{
		return FALSE;
	}
	PVOID TargetAddress = ScanBytes(InitializeBlock.NtImageBase, (PCHAR)InitializeBlock.NtImageBase + InitializeBlock.NtImageSize, BytePattern);
	if (!TargetAddress)
	{
		Log("Not Found Pattern\n");
		return FALSE;
	}
	HookData.TargetAddress = ((DWORD64)TargetAddress - RelSize);
	HookData.HookFunction = HookingFunction;
	HookData.PatchSize = Size;
	HookData.TrampolineAddress = (DWORD64)HookData.TargetAddress + Size;

	if (InitializeBlock.ModFlag)
	{
		HookData.TargetPdeAddress = InitializeBlock.MiGetPdeAddress(TargetAddress);
		Log("Target PDE Address : 0x%llX\n", HookData.TargetPdeAddress);
		if (HookData.TargetPdeAddress->WriteAccess != 1)
		{
			HookData.TargetPdeAddress->WriteAccess = 1;
		}
		// TODO
		//HookData.TargetPteAddress = InitializeBlock.MiGetPteAddress(ExAllocatePoolWithTag);
	}

	SetupKHook(Size);
	Log("Hooking data initialization complete\n");
	return TRUE;


}


ExAllocatePoolWithTag_t ExAllocatePoolWithTagOrig = NULL; // need custom

VOID SetupKHook()
{
	// Setting important byte codes for HOOK_DATA
	UCHAR JmpByte[14] = { 0xFF,0x25,0x00,0x00,0x00,0x00 };	// Hooking Original Function
	UCHAR TramBytes[15] = { 0x90,0xFF,0x25,0x00,0x00,0x00,0x00 };	// Jump Original Function 

	RtlCopyMemory(HookData.OriginalByte, (PVOID*)HookData.TargetAddress, HookData.PatchSize);
	RtlCopyMemory(HookData.TrampolineByte, HookData.OriginalByte, HookData.PatchSize);
	RtlCopyMemory(&TramBytes[7], &HookData.TrampolineAddress,8);
	RtlCopyMemory(&HookData.TrampolineByte[HookData.PatchSize], TramBytes, TRAM_SIZE);
	Log("Trampoline Setup Complete\n");
	
	RtlCopyMemory(&JmpByte[6], &HookData.HookFunction, 8);
	RtlCopyMemory(HookData.PatchByte, JmpByte, HOOK_SIZE);
	
	ExAllocatePoolWithTagOrig = ExAllocatePoolWithTag(NonPagedPoolExecute, PAGE_SIZE, "SHH0");	// need custom
	RtlCopyMemory(ExAllocatePoolWithTagOrig, &HookData.TrampolineByte, sizeof(HookData.TrampolineByte)); // need custom

}

BOOLEAN InitializeSystemInformation()
{
	NTSTATUS Status = STATUS_SUCCESS;
	SYSTEM_MODULE_ENTRY SystemModuleInfo = { 0, };
	Status = GetModuleInformation("\\SystemRoot\\system32\\ntoskrnl.exe", &SystemModuleInfo);
	if (NT_SUCCESS(Status))
	{
		InitializeBlock.NtImageBase = SystemModuleInfo.ImageBase;
		InitializeBlock.NtImageSize = SystemModuleInfo.ImageSize;
		PsGetVersion(NULL, NULL, &InitializeBlock.BuildNumber, NULL);
		Log("Build Number : %d\n", InitializeBlock.BuildNumber);
		if (InitializeBlock.BuildNumber >= 19041)
		{
			Log("Requires permission settings for Page Directory Entry.\n");
			InitializeBlock.MiGetPdeAddress = ScanBytes(InitializeBlock.NtImageBase, (PCHAR)InitializeBlock.NtImageBase + InitializeBlock.NtImageSize, MiGetPdeAddressP);
			InitializeBlock.MiGetPteAddress = ScanBytes(InitializeBlock.NtImageBase, (PCHAR)InitializeBlock.NtImageBase + InitializeBlock.NtImageSize, MiGetPteAddressP);
			InitializeBlock.ModFlag = TRUE;
		}
	}
	else
	{
		ErrLog("Not Found NT Image Base\n");
		return FALSE;
	}

	return TRUE;
}

VOID EnableKHook()
{
	RtlCopyMemory(HookData.TargetAddress, HookData.PatchByte, HOOK_SIZE);
	Log("Hooking has been enabled\n");
	return;
}

VOID DisableKHook()
{
	if (!ExAllocatePoolWithTagOrig)
	{
		return;
	}
	RtlCopyMemory(HookData.TargetAddress, HookData.OriginalByte, HOOK_SIZE);
	Log("Hooking has been disabled\n");

}


// Hooking Function
int i = 0;
PVOID ExAllocatePoolWithTagHook(POOL_TYPE Type, SIZE_T Size, ULONG Tag)
{
	if (i < 10)
	{
		Log("ExAllocatePoolWithTag Hooked\n");
	}
	i++;
	return ExAllocatePoolWithTagOrig(Type, Size, Tag);
}
