#ifndef ABLELDR_MEMORY_HPP
#define ABLELDR_MEMORY_HPP
#include <Windows.h>
#include "typedef.hpp"
#include "malapi.hpp"

namespace memory {
	HMODULE GetModuleHandleC(_In_ ULONG ModuleHash);
	FARPROC GetProcAddressC(_In_ HMODULE ModuleHandle, _In_ ULONG FunctionHash);
} // End of memory namespace

#endif