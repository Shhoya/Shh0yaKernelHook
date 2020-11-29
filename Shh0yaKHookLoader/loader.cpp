#include <stdio.h>
#include <Windows.h>
#include <tchar.h>

#define DRIVERNAME _T("\\Shh0yaKHook.sys")
#define SERVICENAME _T("Shh0yaKernelHook")
#define ORDERGROUP _T("Shh0ya")

#define Log(...) printf("[Shh0ya] " __VA_ARGS__ )
#define ErrLog(...) printf("[ErrorLevel] " __VA_ARGS__ )


BOOL DriverLoader()
{
	TCHAR DriverPath[MAX_PATH] = { 0, };
	TCHAR currPath[MAX_PATH] = { 0, };

	lstrcpyW(DriverPath, _T("\\??\\"));
	GetCurrentDirectory(MAX_PATH, currPath);
	lstrcatW(DriverPath, currPath);
	lstrcatW(DriverPath, DRIVERNAME);

	SC_HANDLE hScm = OpenSCManager(NULL, NULL, SC_MANAGER_ALL_ACCESS);
	SC_HANDLE hService = CreateService(
		hScm, SERVICENAME, SERVICENAME, SC_MANAGER_ALL_ACCESS, SERVICE_KERNEL_DRIVER,
		SERVICE_DEMAND_START, SERVICE_ERROR_IGNORE, DriverPath, ORDERGROUP, NULL, NULL, NULL, NULL);

	if (!hService)
	{
		if (GetLastError() != 0x431)
		{
			ErrLog("Error Code : 0x%X(%d)\n", GetLastError(), GetLastError());
			CloseHandle(hScm);
			system("pause");
			return FALSE;
		}
		else
		{
			hService = OpenService(hScm, SERVICENAME, SC_MANAGER_ALL_ACCESS);
			if (!hService)
			{
				ErrLog("Open Service Error : 0x%X(%d)\n", GetLastError(), GetLastError());
				system("pause");
				CloseHandle(hScm);
				return FALSE;
			}
		}
	}

	if (!StartService(hService, 0, NULL))
	{
		ErrLog("Service Start Error : 0x%X(%d)\n", GetLastError(), GetLastError());
		system("pause");
		DeleteService(hService);
		CloseHandle(hService);
		CloseHandle(hScm);
		return FALSE;
	}
	CloseHandle(hService);
	CloseHandle(hScm);
	return TRUE;
}

void StopService()
{
	SERVICE_STATUS Status;
	SC_HANDLE hScm = OpenSCManager(NULL, NULL, SC_MANAGER_ALL_ACCESS);
	SC_HANDLE hService = OpenService(hScm, SERVICENAME, SERVICE_STOP);
	ControlService(hService, SERVICE_CONTROL_STOP, &Status);

	CloseHandle(hScm);
	CloseHandle(hService);

	return;
}

void SendControl()
{
	HANDLE deviceHandle;
	TCHAR linkName[] = _T("\\\\.\\Shh0yaKHook");
	DWORD dwRet = NULL;
	deviceHandle = CreateFile(linkName, GENERIC_READ | GENERIC_WRITE, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);

	if (deviceHandle == INVALID_HANDLE_VALUE)
	{
		printf("[!] Invalid handle error\n");
		return;
	}

	if (!DeviceIoControl(deviceHandle, 0, 0, 0, 0, 0, &dwRet, 0))
	{
		CloseHandle(deviceHandle);
		return;
	}

	CloseHandle(deviceHandle);
	return;
}

int main(int argc, char* argv[])
{
	if (DriverLoader())
	{
		Log("Driver Load Success\n");
		Log("Press any key to activate the Shh0ya Kernel Hook driver\n");
		system("pause");
		SendControl();
	}
	
}