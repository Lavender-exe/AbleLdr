#ifndef ABLELDR_EXECUTE_HPP
#define ABLELDR_EXECUTE_HPP
#include <Windows.h>
#include "malapi.hpp"

namespace execute
{
	BOOL CreateRemoteThreadInjection(_In_ HANDLE process_handle, _In_ BYTE* shellcode, _In_ SIZE_T shellcode_size); // Process Injection
	BOOL HijackEntryPoint(_In_ HANDLE process_handle, _In_ BYTE* shellcode, _In_ SIZE_T shellcode_size); // Thread Hijacking
} // End of execute namespace

#endif