#include "enumeration.hpp"

namespace enumeration {
	BOOL GetProcessHandle(_In_ LPCWSTR process_name, _Out_ DWORD* pid, _Out_ HANDLE* process_handle)
	{
		BOOL result = FALSE;

		HMODULE kernel32 = NULL;
		HMODULE ntdll = NULL;

		typeGetLastError get_last_error = NULL;
		typeHeapAlloc heap_alloc = NULL;
		typeGetProcessHeap get_process_heap = NULL;
		typeOpenProcess open_process = NULL;
		typeHeapFree heap_free = NULL;

		typeNtOpenProcess nt_open_process = NULL;
		typeNtQuerySystemInformation nt_query_system_information = NULL;

		ULONG return_length_1 = NULL,
			return_length_2 = NULL;
		PSYSTEM_PROCESS_INFORMATION system_process_information = NULL;
		NTSTATUS status = NULL;
		PVOID value_to_free = NULL;

#pragma region [Kernel32 Functions]

		constexpr ULONG hash_kernel32 = HashString("KERNEL32.DLL");
		kernel32 = memory::GetModuleHandleC(hash_kernel32);
		if (kernel32 == NULL)
		{
			LOG_ERROR("GetModuleHandle Failed to import Kernel32");
		}

		get_last_error = (typeGetLastError)memory::GetProcAddressC(kernel32, HashString("GetLastError"));
		heap_alloc = (typeHeapAlloc)memory::GetProcAddressC(kernel32, HashString("HeapAlloc"));
		heap_free = (typeHeapFree)memory::GetProcAddressC(kernel32, HashString("HeapFree"));
		get_process_heap = (typeGetProcessHeap)memory::GetProcAddressC(kernel32, HashString("GetProcessHeap"));
		open_process = (typeOpenProcess)memory::GetProcAddressC(kernel32, HashString("OpenProcess"));

#pragma endregion

#pragma region [NTDLL Functions]

		constexpr ULONG hash_ntdll = HashString("ntdll.dll");
		ntdll = memory::GetModuleHandleC(hash_ntdll);
		if (ntdll == NULL)
		{
			LOG_ERROR("GetModuleHandle Failed to import NTDLL");
			return FALSE;
		}

		nt_query_system_information = (typeNtQuerySystemInformation)memory::GetProcAddressC(ntdll, HashString("NtQuerySystemInformation"));
		if (nt_query_system_information == NULL)
		{
			LOG_ERROR("Failed to get NtQuerySystemInformation. (Code: %08lX)", get_last_error());
			return FALSE;
		}

#pragma endregion

		nt_query_system_information(SystemProcessInformation, NULL, NULL, &return_length_1);

		system_process_information = (PSYSTEM_PROCESS_INFORMATION)heap_alloc(get_process_heap(), HEAP_ZERO_MEMORY, (SIZE_T)&return_length_1);
		if (system_process_information == NULL)
		{
			LOG_ERROR("HeapAlloc Failed. (Code: %08lX)", get_last_error());
			return FALSE;
		}

		value_to_free = system_process_information;

		status = nt_query_system_information(SystemProcessInformation, system_process_information, return_length_1, &return_length_2);
		if (status != 0x0)
		{
			LOG_ERROR("NtQuerySystemInformation Failed (Code: 0x%0.8X)", status);
			return FALSE;
		}

		while (TRUE)
		{
			if (system_process_information->ImageName.Length && StringCompare(system_process_information->ImageName.Buffer, process_name) == 0)
			{
				*pid = (DWORD)system_process_information->UniqueProcessId;
				*process_handle = open_process(PROCESS_ALL_ACCESS, FALSE, (DWORD)system_process_information->UniqueProcessId);
				LOG_SUCCESS("Got PID: %d", pid);
				LOG_SUCCESS("Got Process Handle: %d", process_handle);

				break;
			}

			if (!system_process_information->NextEntryOffset)
			{
				break;
			}

			system_process_information = (PSYSTEM_PROCESS_INFORMATION)((ULONG_PTR)system_process_information + system_process_information->NextEntryOffset);
		}

		heap_free(get_process_heap(), 0, value_to_free);

		// Check if we successfully got the target process handle
		if (*pid == NULL || *process_handle == NULL)
			result = FALSE;
		else
			result = TRUE;

		return result;
	}
} // End of enumeration namespace