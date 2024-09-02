#ifndef ABLELDR_ENUMERATION_HPP
#define ABLELDR_ENUMERATION_HPP
#include <Windows.h>
#include "typedef.hpp"
#include "malapi.hpp"
#include "memory.hpp"
#include "debug.hpp"

namespace enumerate {
	BOOL GetProcessHandle(_In_ LPCWSTR process_name, _Out_ DWORD* pid, _Out_ HANDLE* process_handle);
} // End of enumerate namespace

#endif