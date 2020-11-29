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

#include "Util.h"


VOID InitUnicode(OUT PUNICODE_STRING UnicodeString, IN PCWSTR String)
{
	RtlZeroMemory(UnicodeString, sizeof(UNICODE_STRING));
	RtlInitUnicodeString(UnicodeString, String);
}

PVOID GetRoutineAddress(IN PUNICODE_STRING UnicodeString, IN PCWSTR String)
{
	InitUnicode(UnicodeString, String);
	return MmGetSystemRoutineAddress(UnicodeString);
	
}

NTSTATUS GetModuleInformation(IN const char* szModuleName, OUT PSYSTEM_MODULE_ENTRY TargetModule)
{
	BOOLEAN FindFlag = FALSE;
	ULONG infoLen = 0;
	UNICODE_STRING ZwQueryString = { 0, };
	PSYSTEM_MODULE_INFORMATION pMod = { 0, };
	RtlInitUnicodeString(&ZwQueryString, L"ZwQuerySystemInformation");
	NtQuerySystemInformation_t ZwQuerySystemInformation = MmGetSystemRoutineAddress(&ZwQueryString);

	NTSTATUS status = ZwQuerySystemInformation(SystemModuleInformation, &infoLen, 0, &infoLen);
	pMod = (PSYSTEM_MODULE_INFORMATION)ExAllocatePoolWithTag(NonPagedPool, infoLen, 'H0YA');
	RtlZeroMemory(pMod, infoLen);
	status = ZwQuerySystemInformation(SystemModuleInformation, pMod, infoLen, &infoLen);
	PSYSTEM_MODULE_ENTRY pModEntry = pMod->Module;
	for (int i = 0; i < pMod->Count; i++)
	{
		if (!_stricmp(pModEntry[i].FullPathName, szModuleName))
		{
			Log("Find Module %s\n", pModEntry[i].FullPathName);
			*TargetModule = pModEntry[i];
			FindFlag = TRUE;
			break;
		}
	}
	ExFreePoolWithTag(pMod, 'H0YA');
	if (!FindFlag)
	{
		return STATUS_NOT_FOUND;
	}
	return status;
}