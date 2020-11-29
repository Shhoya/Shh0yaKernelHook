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

NTSTATUS DriverEntry(PDRIVER_OBJECT pDriver, PUNICODE_STRING pRegPath);
VOID DriverUnload(PDRIVER_OBJECT pDriver);

NTSTATUS DriverCreate(PDEVICE_OBJECT pDevice, PIRP pIrp);
NTSTATUS DriverRead(PDEVICE_OBJECT pDevice, PIRP pIrp);
NTSTATUS DriverWrite(PDEVICE_OBJECT pDevice, PIRP pIrp);
NTSTATUS DriverClose(PDEVICE_OBJECT pDevice, PIRP pIrp);
NTSTATUS DriverUnsupported(PDEVICE_OBJECT pDevice, PIRP pIrp);
NTSTATUS DriverDeviceControl(PDEVICE_OBJECT pDevice, PIRP pIrp);
