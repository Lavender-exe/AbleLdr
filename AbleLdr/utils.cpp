#include "utils.hpp"

namespace utils {
	// Wide
	BOOL GetProcessId(_In_ PWCHAR process_name)
	{
		HANDLE	process_handle = NULL;

		DWORD	pid_array[1024] = { 0 };
		DWORD	pid_array_size = 0;
		DWORD	bytes_returned = 0;

		BOOL	result = FALSE;
		HMODULE kernel32 = NULL;
		HMODULE ntdll = NULL;

#pragma region [Kernel32 Functions]

		typeGetLastError				get_last_error = NULL;
		typeCreateToolhelp32Snapshot	create_toolhelp32_snapshot = NULL;
		typeProcess32First				process_32_first = NULL;
		typeProcess32Next				process_32_next = NULL;
		typeCloseHandle					close_handle = NULL;
		typeEnumProcesses				enum_processes = NULL;
		typeOpenProcess					open_process = NULL;
		typeGetProcessId				get_process_id = NULL;

		constexpr ULONG hash_kernel32 = HashString("KERNEL32.DLL");
		kernel32 = memory::GetModuleHandleC(hash_kernel32);
		if (kernel32 == NULL)
		{
			LOG_ERROR("GetModuleHandle Failed to import Kernel32");
		}

		get_last_error = (typeGetLastError)memory::GetProcAddressC(kernel32, HashString("GetLastError"));
		create_toolhelp32_snapshot = (typeCreateToolhelp32Snapshot)memory::GetProcAddressC(kernel32, HashString("CreateToolhelp32Snapshot"));
		process_32_first = (typeProcess32First)memory::GetProcAddressC(kernel32, HashString("Process32First"));
		process_32_next = (typeProcess32Next)memory::GetProcAddressC(kernel32, HashString("Process32Next"));
		close_handle = (typeCloseHandle)memory::GetProcAddressC(kernel32, HashString("CloseHandle"));
		enum_processes = (typeEnumProcesses)memory::GetProcAddressC(kernel32, HashString("EnumProcesses"));
		open_process = (typeOpenProcess)memory::GetProcAddressC(kernel32, HashString("OpenProcess"));
		get_process_id = (typeGetProcessId)memory::GetProcAddressC(kernel32, HashString("GetProcessId"));

#pragma endregion

#pragma region [NTDLL Functions]

		// Ntdll
		// typeNtOpenProcess			 nt_open_process = NULL;
		// typeNtQuerySystemInformation nt_query_system_information = NULL;
		// typeRtlAllocateHeap			 rtl_allocate_heap = NULL;
		// typeRtlFreeHeap				 rtl_free_heap = NULL;

		// NtQuerySystemInformation
		// ULONG						return_length = NULL;
		// PSYSTEM_PROCESS_INFORMATION system_process_information = NULL;
		// NTSTATUS					status = NULL;
		// PVOID						value_to_free = NULL;

		// constexpr ULONG hash_ntdll = HashString("ntdll.dll");
		// ntdll = memory::GetModuleHandleC(hash_ntdll);
		// if (ntdll == NULL)
		// {
		// 	LOG_ERROR("GetModuleHandle Failed to import NTDLL");
		// 	return FALSE;
		// }
		//
		// nt_query_system_information = (typeNtQuerySystemInformation)memory::GetProcAddressC(ntdll, HashString("NtQuerySystemInformation"));
		// if (nt_query_system_information == NULL)
		// {
		// 	LOG_ERROR("Failed to get NtQuerySystemInformation. (Code: %08lX)", get_last_error());
		// 	return FALSE;
		// }
		//
		// rtl_allocate_heap = (typeRtlAllocateHeap)memory::GetProcAddressC(ntdll, HashString("RtlAllocateHeap"));
		// if (rtl_allocate_heap == NULL)
		// {
		// 	LOG_ERROR("Failed to get RtlAllocateHeap. (Code: %08lX)", get_last_error());
		// 	return FALSE;
		// }
		//
		// rtl_free_heap = (typeRtlFreeHeap)memory::GetProcAddressC(ntdll, HashString("RtlFreeHeap"));
		// if (rtl_allocate_heap == NULL)
		// {
		// 	LOG_ERROR("Failed to get RtlFreeHeap. (Code: %08lX)", get_last_error());
		// 	return FALSE;
		// }

#pragma endregion

#pragma region [NtQuerySystemInformation]

// nt_query_system_information(SystemProcessInformation, NULL, 0, &return_length);
//
// // Double buffer size to make room for increased process info size
// return_length *= 2;
//
// system_process_information = (PSYSTEM_PROCESS_INFORMATION)rtl_allocate_heap(get_process_heap(), HEAP_ZERO_MEMORY, (SIZE_T)return_length);
// if (system_process_information == NULL)
// {
//     LOG_ERROR("HeapAlloc Failed. (Code: %08lX)", get_last_error());
//     return FALSE;
// }
//
// status = nt_query_system_information(SystemProcessInformation, system_process_information, return_length, &return_length);
// if (!NT_SUCCESS(status))
// {
//     LOG_ERROR("NtQuerySystemInformation Failed to query system information (Code: 0x%0.8X)", status);
//     return FALSE;
// }
//
// while (TRUE)
// {
//     if (system_process_information->ImageName.Length && StringCompare(system_process_information->ImageName.Buffer, process_name) == 0)
//     {
//         *pid = (DWORD)system_process_information->UniqueProcessId;
//         *process_handle = open_process(PROCESS_ALL_ACCESS, FALSE, (DWORD)system_process_information->UniqueProcessId);
//         LOG_SUCCESS("Got PID: %d", pid);
//         LOG_SUCCESS("Got Process Handle: %d", process_handle);
//
//         break;
//     }
//
//     if (!system_process_information->NextEntryOffset)
//     {
//         break;
//     }
//
//     system_process_information = (PSYSTEM_PROCESS_INFORMATION)((ULONG_PTR)system_process_information + system_process_information->NextEntryOffset);
// }
//
// rtl_free_heap(get_process_heap(), 0, system_process_information);
//
// if (*pid == NULL || *process_handle == NULL)
//     result = FALSE;
// else
//     result = TRUE;

		return result;

#pragma endregion

#pragma region [CreateToolHelp32Snapshot]

		// HANDLE           process_snapshot = NULL;
		// PROCESSENTRY32 proc_entry32;
		//
		// process_snapshot = create_toolhelp32_snapshot(TH32CS_SNAPPROCESS, 0);
		// if (process_snapshot == INVALID_HANDLE_VALUE)
		// {
		//     LOG_ERROR("CreateToolhelp32Snapshot Failed. (Code: %08lX)", get_last_error());
		//     result = FALSE;
		// }
		//
		// proc_entry32.dwSize = sizeof(PROCESSENTRY32);
		//
		// if (!process_32_first(process_snapshot, &proc_entry32))
		// {
		//     close_handle(process_snapshot);
		//     result = FALSE;
		// }
		//
		// while (process_32_next(process_snapshot, &proc_entry32))
		// {
		//     if (StringCompare(process_name, proc_entry32.szExeFile) == 0)
		//     {
		//         pid = (DWORD)proc_entry32.th32ProcessID;
		//         result = TRUE;
		//         break;
		//     }
		// }
		//
		// close_handle(process_snapshot);
		//
		// if (pid == NULL)
		// {
		//     LOG_ERROR("Unable to obtain PID of process: %d", process_name);
		//     result = FALSE;
		// }

		return result;

#pragma endregion

#pragma region [EnumProcesses]

		if (!K32EnumProcesses(pid_array, sizeof(pid_array_size), &bytes_returned))
		{
			result = FALSE;
		}

		pid_array_size = bytes_returned / sizeof(DWORD);

		for (DWORD index = 0; index < pid_array_size; index++)
		{
			HMODULE module = NULL;
			DWORD pid = ERROR_SUCCESS;
			WCHAR process_string_name[MAX_PATH * sizeof(WCHAR)] = { 0 };

			if (pid_array[index] == 0)
			{
				continue;
			}

			process_handle = open_process(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pid_array[index]);
			if (process_handle == NULL)
			{
				continue;
			}

			if (!K32EnumProcessModules(process_handle, &module, sizeof(module), &bytes_returned))
			{
				continue;
			}

			if (K32GetModuleBaseNameW(process_handle, module, process_string_name, sizeof(process_string_name) / sizeof(WCHAR)) == 0)
			{
				continue;
			}

			if (StringCompare(process_name, process_string_name) == 0)
			{
				pid = get_process_id(process_handle);
			}

			close_handle(process_handle);

			if (pid != 0)
			{
				return pid;
			}
		}

#pragma endregion

		result = TRUE;

		return result;
	} // https://github.com/vxunderground/VX-API/blob/main/VX-API/GetPidFromEnumProcesses.cpp

	// Ascii
	BOOL GetProcessId(_In_ PCHAR process_name)
	{
		HANDLE	process_handle = NULL;

		DWORD	pid_array[1024] = { 0 };
		DWORD	pid_array_size = 0;
		DWORD	bytes_returned = 0;

		BOOL	result = FALSE;
		HMODULE kernel32 = NULL;
		HMODULE ntdll = NULL;

#pragma region [Kernel32 Functions]

		typeGetLastError				get_last_error = NULL;
		typeCreateToolhelp32Snapshot	create_toolhelp32_snapshot = NULL;
		typeProcess32First				process_32_first = NULL;
		typeProcess32Next				process_32_next = NULL;
		typeCloseHandle					close_handle = NULL;
		typeEnumProcesses				enum_processes = NULL;
		typeOpenProcess					open_process = NULL;
		typeGetProcessId				get_process_id = NULL;

		constexpr ULONG hash_kernel32 = HashString("KERNEL32.DLL");
		kernel32 = memory::GetModuleHandleC(hash_kernel32);
		if (kernel32 == NULL)
		{
			LOG_ERROR("GetModuleHandle Failed to import Kernel32");
		}

		get_last_error = (typeGetLastError)memory::GetProcAddressC(kernel32, HashString("GetLastError"));
		create_toolhelp32_snapshot = (typeCreateToolhelp32Snapshot)memory::GetProcAddressC(kernel32, HashString("CreateToolhelp32Snapshot"));
		process_32_first = (typeProcess32First)memory::GetProcAddressC(kernel32, HashString("Process32First"));
		process_32_next = (typeProcess32Next)memory::GetProcAddressC(kernel32, HashString("Process32Next"));
		close_handle = (typeCloseHandle)memory::GetProcAddressC(kernel32, HashString("CloseHandle"));
		enum_processes = (typeEnumProcesses)memory::GetProcAddressC(kernel32, HashString("EnumProcesses"));
		open_process = (typeOpenProcess)memory::GetProcAddressC(kernel32, HashString("OpenProcess"));
		get_process_id = (typeGetProcessId)memory::GetProcAddressC(kernel32, HashString("GetProcessId"));

#pragma endregion

#pragma region [EnumProcesses]

		if (!K32EnumProcesses(pid_array, sizeof(pid_array_size), &bytes_returned))
		{
			result = FALSE;
		}

		pid_array_size = bytes_returned / sizeof(DWORD);

		for (DWORD index = 0; index < pid_array_size; index++)
		{
			HMODULE module = NULL;
			DWORD pid = ERROR_SUCCESS;
			CHAR process_string_name[MAX_PATH] = { 0 };

			if (pid_array[index] == 0)
			{
				continue;
			}

			process_handle = open_process(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pid_array[index]);
			if (process_handle == NULL)
			{
				continue;
			}

			if (!K32EnumProcessModules(process_handle, &module, sizeof(module), &bytes_returned))
			{
				continue;
			}

			if (K32GetModuleBaseNameW(process_handle, module, process_string_name, sizeof(process_string_name) / sizeof(CHAR)) == 0)
			{
				continue;
			}

			if (StringCompare(process_name, process_string_name) == 0)
			{
				pid = get_process_id(process_handle);
			}

			close_handle(process_handle);

			if (pid != 0)
			{
				return pid;
			}
		}

#pragma endregion

		result = TRUE;

		return result;
	} // https://github.com/vxunderground/VX-API/blob/main/VX-API/GetPidFromEnumProcesses.cpp

	BOOL GetProcessHandle(_In_ DWORD pid)
	{
		BOOL	result = FALSE;
		HMODULE kernel32 = NULL;
		HANDLE	process_handle = NULL;

#pragma region [Kernel32 Functions]

		typeGetLastError	get_last_error = NULL;
		typeOpenProcess		open_process = NULL;
		typeCloseHandle		close_handle = NULL;

		constexpr ULONG hash_kernel32 = HashString("KERNEL32.DLL");
		kernel32 = memory::GetModuleHandleC(hash_kernel32);
		if (kernel32 == NULL)
		{
			LOG_ERROR("GetModuleHandle Failed to import Kernel32");
		}

		get_last_error = (typeGetLastError)memory::GetProcAddressC(kernel32, HashString("GetLastError"));
		open_process = (typeOpenProcess)memory::GetProcAddressC(kernel32, HashString("OpenProcess"));
		close_handle = (typeCloseHandle)memory::GetProcAddressC(kernel32, HashString("CloseHandle"));

#pragma endregion

		process_handle = open_process(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pid);
		if (process_handle == NULL)
		{
			LOG_ERROR("Failed to get process handle. (Code: %08lX)", get_last_error());
			result = FALSE;
		}

		result = TRUE;

		return result;
	}
} // End of utils namespace