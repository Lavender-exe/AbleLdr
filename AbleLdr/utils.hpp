#ifndef ABLELDR_ENUMERATION_HPP
#define ABLELDR_ENUMERATION_HPP
#include <Windows.h>
#include "typedef.hpp"
#include "malapi.hpp"
#include "memory.hpp"
#include "debug.hpp"

namespace utils {
	BOOL GetProcessHandle(_In_ LPCWSTR process_name, _Out_ PDWORD pid, _Out_ PHANDLE process_handle);
	// BOOL GetProcessIdA(_In_ PCHAR process_name);
	// BOOL GetProcessHandle(_In_ DWORD pid);
} // End of utils namespace

#endif