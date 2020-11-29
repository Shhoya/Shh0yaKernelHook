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

// ReacOS refer
typedef enum _SYSTEM_INFORMATION_CLASS {
    SystemBasicInformation,
    SystemProcessorInformation,
    SystemPerformanceInformation,
    SystemTimeOfDayInformation,
    SystemPathInformation,
    SystemProcessInformation,
    SystemCallCountInformation,
    SystemDeviceInformation,
    SystemProcessorPerformanceInformation,
    SystemFlagsInformation,
    SystemCallTimeInformation,
    SystemModuleInformation,
    SystemLocksInformation,
    SystemStackTraceInformation,
    SystemPagedPoolInformation,
    SystemNonPagedPoolInformation,
    SystemHandleInformation,
    SystemObjectInformation,
    SystemPageFileInformation,
    SystemVdmInstemulInformation,
    SystemVdmBopInformation,
    SystemFileCacheInformation,
    SystemPoolTagInformation,
    SystemInterruptInformation,
    SystemDpcBehaviorInformation,
    SystemFullMemoryInformation,
    SystemLoadGdiDriverInformation,
    SystemUnloadGdiDriverInformation,
    SystemTimeAdjustmentInformation,
    SystemSummaryMemoryInformation,
    SystemNextEventIdInformation,
    SystemEventIdsInformation,
    SystemCrashDumpInformation,
    SystemExceptionInformation,
    SystemCrashDumpStateInformation,
    SystemKernelDebuggerInformation,
    SystemContextSwitchInformation,
    SystemRegistryQuotaInformation,
    SystemExtendServiceTableInformation,
    SystemPrioritySeperation,
    SystemPlugPlayBusInformation,
    SystemDockInformation,
#if !defined PO_CB_SYSTEM_POWER_POLICY
    SystemPowerInformation,
#else
    _SystemPowerInformation,
#endif
    SystemProcessorSpeedInformation,
    SystemCurrentTimeZoneInformation,
    SystemLookasideInformation
}SYSTEM_INFORMATION_CLASS,*PSYSTEM_INFORMATION_CLASS;

typedef struct _SYSTEM_MODULE_ENTRY
{
    HANDLE Section;				//0x0000(0x0008)
    PVOID MappedBase;			//0x0008(0x0008)
    PVOID ImageBase;			//0x0010(0x0008)
    ULONG ImageSize;			//0x0018(0x0004)
    ULONG Flags;				//0x001C(0x0004)
    USHORT LoadOrderIndex;		//0x0020(0x0002)
    USHORT InitOrderIndex;		//0x0022(0x0002)
    USHORT LoadCount;			//0x0024(0x0002)
    USHORT OffsetToFileName;	//0x0026(0x0002)
    UCHAR FullPathName[256];	//0x0028(0x0100)
} SYSTEM_MODULE_ENTRY, * PSYSTEM_MODULE_ENTRY;

typedef struct _SYSTEM_MODULE_INFORMATION
{
    ULONG               Count;
    SYSTEM_MODULE_ENTRY Module[1];
} SYSTEM_MODULE_INFORMATION, * PSYSTEM_MODULE_INFORMATION;


typedef NTSTATUS(*NtQuerySystemInformation_t)(
	SYSTEM_INFORMATION_CLASS SystemInformationClass,
	PVOID SystemInformaiton,
	ULONG SystemInformationLenght,
	PULONG ReturnLength
	);

typedef PVOID(*MiGetPdeAddress_t)(
    PVOID VirtualAddress
    );

typedef PVOID(*MiGetPteAddress_t)(
    PVOID VirtualAddress
    );