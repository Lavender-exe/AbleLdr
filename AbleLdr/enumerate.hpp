#ifndef ABLELDR_ENUMERATION_HPP
#define ABLELDR_ENUMERATION_HPP
#include <Windows.h>
#include "typedef.hpp"
#include "malapi.hpp"
#include "memory.hpp"
#include "debug.hpp"

namespace enumerate {
	BOOL GetProcessHandle(_In_ LPCSTR process_name);
} // End of enumerate namespace

#endif