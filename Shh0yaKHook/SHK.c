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

#include "SHK.h"
#include "Scan.h"
#include "Hook.h"

#ifdef ALLOC_PRAGMA
#pragma alloc_text(INIT,DriverEntry)
#pragma alloc_text(PAGE,DriverUnload)
#pragma alloc_text(PAGE,DriverRead)
#pragma alloc_text(PAGE,DriverWrite)
#pragma alloc_text(PAGE,DriverClose)
#pragma alloc_text(PAGE,DriverDeviceControl)
#endif

NTSTATUS DriverEntry(PDRIVER_OBJECT pDriver, PUNICODE_STRING pRegPath)
{
	NTSTATUS Status = STATUS_SUCCESS;
	
	PDEVICE_OBJECT pDevice		= NULL;
	UNICODE_STRING DeviceName	= { 0, };
	UNICODE_STRING SymbolicName = { 0, };

	InitUnicode(&DeviceName, L"\\Device\\Shh0yaKernelHook");

	Status = IoCreateDevice(
		pDriver, 0, &DeviceName, FILE_DEVICE_UNKNOWN, FILE_DEVICE_SECURE_OPEN, FALSE, &pDevice
	);

	if (NT_SUCCESS(Status))
	{
		InitUnicode(&SymbolicName, L"\\DosDevices\\Shh0yaKHook");

		Status = IoCreateSymbolicLink(&SymbolicName, &DeviceName);
		if (NT_SUCCESS(Status))
		{
			for (int i = 0; i < IRP_MJ_MAXIMUM_FUNCTION; i++)
			{
				pDriver->MajorFunction[i] = DriverUnsupported;
			}

			pDriver->DriverUnload = DriverUnload;
			pDriver->MajorFunction[IRP_MJ_CREATE] = DriverCreate;
			pDriver->MajorFunction[IRP_MJ_READ] = DriverRead;
			pDriver->MajorFunction[IRP_MJ_WRITE] = DriverWrite;
			pDriver->MajorFunction[IRP_MJ_CLOSE] = DriverClose;
			pDriver->MajorFunction[IRP_MJ_DEVICE_CONTROL] = DriverDeviceControl;

			Log("Device Setup Complete\n");
		}
		else 
		{
			ErrLog("IoCreateSymbolicLink(0x%X)\n",Status);
			IoDeleteDevice(pDevice);
		}
	}
	else
	{
		ErrLog("IoCreateDevice(0x%X)\n",Status);
	}


	return Status;
}

VOID DriverUnload(PDRIVER_OBJECT pDriver)
{
	UNICODE_STRING SymbolicName = { 0, };
	InitUnicode(&SymbolicName, L"\\DosDevices\\Shh0yaKHook");
	IoDeleteSymbolicLink(&SymbolicName);
	IoDeleteDevice(pDriver->DeviceObject);

	DisableKHook();
	Log("Driver Unload\n");
	return;
}

NTSTATUS DriverCreate(PDEVICE_OBJECT pDevice, PIRP pIrp)
{
	pIrp->IoStatus.Status = STATUS_SUCCESS;
	pIrp->IoStatus.Information = 0;
	IoCompleteRequest(pIrp, IO_NO_INCREMENT);

	return STATUS_SUCCESS;
}

NTSTATUS DriverRead(PDEVICE_OBJECT pDevice, PIRP pIrp)
{
	pIrp->IoStatus.Status = STATUS_SUCCESS;
	pIrp->IoStatus.Information = 0;
	IoCompleteRequest(pIrp, IO_NO_INCREMENT);

	return STATUS_SUCCESS;
}

NTSTATUS DriverWrite(PDEVICE_OBJECT pDevice, PIRP pIrp)
{
	pIrp->IoStatus.Status = STATUS_SUCCESS;
	pIrp->IoStatus.Information = 0;
	IoCompleteRequest(pIrp, IO_NO_INCREMENT);

	return STATUS_SUCCESS;
}

NTSTATUS DriverClose(PDEVICE_OBJECT pDevice, PIRP pIrp)
{
	pIrp->IoStatus.Status = STATUS_SUCCESS;
	pIrp->IoStatus.Information = 0;
	IoCompleteRequest(pIrp, IO_NO_INCREMENT);

	return STATUS_SUCCESS;
}

NTSTATUS DriverUnsupported(PDEVICE_OBJECT pDevice, PIRP pIrp)
{
	pIrp->IoStatus.Status = STATUS_SUCCESS;
	pIrp->IoStatus.Information = 0;
	IoCompleteRequest(pIrp, IO_NO_INCREMENT);

	return STATUS_SUCCESS;
}

NTSTATUS DriverDeviceControl(PDEVICE_OBJECT pDevice, PIRP pIrp)
{
	pIrp->IoStatus.Status = STATUS_SUCCESS;
	PIO_STACK_LOCATION pIrpSp = NULL;
	pIrpSp = IoGetCurrentIrpStackLocation(pIrp);
	
	switch (pIrpSp->Parameters.DeviceIoControl.IoControlCode)
	{
	case 0:
	{

		//InitializeKHook(L"ExAllocatePoolWithTag", ExAllocatePoolWithTagHook, 15);	// need custom
		InitializeKHookEx("44 0F B7 3D A4 9F 34 00", ExAllocatePoolWithTagHook, 15, 0x24); // need custom
		EnableKHook();
		pIrp->IoStatus.Status = STATUS_SUCCESS;
		break;
	}
	default:
	{
		pIrp->IoStatus.Information = 0;
		pIrp->IoStatus.Status = STATUS_INVALID_DEVICE_REQUEST;
		break;
	}
	}

	IoCompleteRequest(pIrp, IO_NO_INCREMENT);

	return STATUS_SUCCESS;
}
