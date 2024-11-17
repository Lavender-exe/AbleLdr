#include "encrypt.hpp"

namespace encrypt {
	//
	// NOT FUNCTIONAL
	//
	PBYTE NoEncrypt(_In_ PBYTE shellcode, _In_ PBYTE key, _In_ SIZE_T shellcode_len, _In_ SIZE_T key_len)
	{
		return shellcode;
	}

	PBYTE XorEncrypt(_In_ PBYTE shellcode, _In_ PBYTE key, _In_ SIZE_T shellcode_len, _In_ SIZE_T key_len)
	{
		for (size_t i = 0, j = 0; i < shellcode_len; i++, j++)
		{
			if (j > key_len)
			{
				j = 0;
			}
			shellcode[i] = shellcode[i] ^ key[j];
		}
		return shellcode;
	}

	PBYTE AesEncrypt(_In_ PBYTE shellcode, _In_ PBYTE key, _In_ SIZE_T shellcode_len, _In_ SIZE_T key_len)
	{
		return shellcode;
	}

	PBYTE Rc4Encrypt(_In_ PBYTE shellcode, _In_ PBYTE key, _In_ SIZE_T shellcode_len, _In_ SIZE_T key_len)
	{
		return shellcode;
	}
} // End of encrypt namespace