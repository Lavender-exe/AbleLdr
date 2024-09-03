#ifndef ABLELDR_EXECUTE_HPP
#define ABLELDR_EXECUTE_HPP
#include <Windows.h>
#include "config.hpp"
#include "typedef.hpp"
#include "debug.hpp"
#include "malapi.hpp"
#include "memory.hpp"
#include "utils.hpp"

namespace execute {
	BOOL CreateRemoteThread(_In_ HANDLE process_handle, _In_ BYTE* shellcode);
	BOOL HijackEntryPoint(_In_ HANDLE process_handle, _In_ BYTE* shellcode);
} // End of execute namespace

#endif