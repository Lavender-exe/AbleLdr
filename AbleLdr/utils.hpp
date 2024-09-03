#ifndef ABLELDR_ENUMERATION_HPP
#define ABLELDR_ENUMERATION_HPP
#include <Windows.h>
#include "psapi.h"
#include "typedef.hpp"
#include "malapi.hpp"
#include "memory.hpp"
#include "debug.hpp"

namespace utils {
	BOOL GetProcessId(_In_ PWCHAR process_name);
	BOOL GetProcessId(_In_ PCHAR process_name);
	BOOL GetProcessHandle(_In_ int pid);
} // End of utils namespace

#endif