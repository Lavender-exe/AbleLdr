#ifndef ABLELDR_MEMORY_HPP
#define ABLELDR_MEMORY_HPP
#include <Windows.h>

namespace memory {
	HMODULE _GetModuleHandle(_In_ LPCWSTR ModuleName);
	FARPROC _GetProcAddress(_In_ HMODULE ModuleHandle, _In_ LPCSTR FunctionName);
} // End of memory namespace

#endif