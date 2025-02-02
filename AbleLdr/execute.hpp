#ifndef ABLELDR_EXECUTE_HPP
#define ABLELDR_EXECUTE_HPP
#include <Windows.h>
#include "malapi.hpp"

namespace execute
{
	BOOL CreateRemoteThreadInjection(_In_ HANDLE process_handle, _In_ BYTE* shellcode, _In_ SIZE_T shellcode_size); // Process Injection
	BOOL RemoteHijack(_In_ HANDLE process_handle, _In_ BYTE* shellcode, _In_ SIZE_T shellcode_size); // Remote Thread Hijacking
	BOOL Hollowing(_In_ HANDLE process_handle, _In_ BYTE* shellcode, _In_ SIZE_T shellcode_size); // Process Hollowing
	BOOL Doppleganger(_In_ HANDLE process_handle, _In_ BYTE* shellcode, _In_ SIZE_T shellcode_size); // Process Doppleganger
} // End of execute namespace

#endif
