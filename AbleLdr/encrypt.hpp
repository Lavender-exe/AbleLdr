#ifndef ABLELDR_ENCRYPT_HPP
#define ABLELDR_ENCRYPT_HPP
#include <Windows.h>
#include "malapi.hpp"

namespace encrypt
{
	//
	// NOT FUNCTIONAL
	//
	PBYTE NoEncrypt(_In_ PBYTE shellcode, _In_ PBYTE key, _In_ SIZE_T shellcode_len, _In_ SIZE_T key_len);
	PBYTE XorEncrypt(_In_ PBYTE shellcode, _In_ PBYTE key, _In_ SIZE_T shellcode_len, _In_ SIZE_T key_len);
	PBYTE AesEncrypt(_In_ PBYTE shellcode, _In_ PBYTE key, _In_ SIZE_T shellcode_len, _In_ SIZE_T key_len);
	PBYTE Rc4Encrypt(_In_ PBYTE shellcode, _In_ PBYTE key, _In_ SIZE_T shellcode_len, _In_ SIZE_T key_len);
} // End of encrypt namespace

#endif