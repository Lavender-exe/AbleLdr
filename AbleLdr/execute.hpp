#ifndef ABLELDR_EXECUTE_HPP
#define ABLELDR_EXECUTE_HPP
#include <Windows.h>

namespace execute {
	VOID CreateRemoteThread(_In_ DWORD PID, _In_ unsigned char Shellcode[]);
	VOID HijackEntryPoint(_In_ HANDLE pHandle, _In_ unsigned char Shellcode[]);
} // End of execute namespace

#endif