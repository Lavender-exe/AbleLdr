#ifndef ABLELDR_EXECUTE_HPP
#define ABLELDR_EXECUTE_HPP
#include <Windows.h>
#include "typedef.hpp"
#include "debug.hpp"
#include "malapi.hpp"
#include "memory.hpp"

namespace execute {
	BOOL CreateRemoteThread(_In_ DWORD pid, _In_ BYTE* shellcode);
	BOOL HijackEntryPoint(_In_ HANDLE process_handle, _In_ BYTE* shellcode);
} // End of execute namespace

#endif