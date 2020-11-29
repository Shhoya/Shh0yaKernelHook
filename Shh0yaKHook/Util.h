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
#include <ntifs.h>
#include "nt_undocu.h"

/*
Byte Patterns
*/
#define MiGetPteAddressP "48 C1 E9 09 48 B8 F8 FF FF FF 7F 00 00 00 48 23 C8 48 B8 00 ?? ?? ?? ?? ?? ?? ?? 48 03 C1 C3"
#define MiGetPdeAddressP "48 C1 E9 12 81 E1 F8 FF FF 3F 48 B8 00 ?? ?? ?? ?? ?? ?? ?? 48 03 C1 C3"

#define Log(...) DbgPrintEx( DPFLTR_SYSTEM_ID,DPFLTR_ERROR_LEVEL, "[Shh0ya] " __VA_ARGS__ )
#define ErrLog(...) DbgPrintEx( DPFLTR_SYSTEM_ID, DPFLTR_ERROR_LEVEL, "[ErrorLevel] " __VA_ARGS__ )

#define STATUS_HELPER(status, flag, function) if (status & flag) Log("%s Success(NTSTATUS : %s)",function,#flag)

VOID InitUnicode(OUT PUNICODE_STRING UnicodeString, IN PCWSTR String);
PVOID GetRoutineAddress(IN PUNICODE_STRING UnicodeString, IN PCWSTR String);
NTSTATUS GetModuleInformation(IN const char* szModuleName, OUT PSYSTEM_MODULE_ENTRY TargetModule);
