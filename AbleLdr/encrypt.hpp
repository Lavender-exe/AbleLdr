#ifndef ABLELDR_ENCRYPT_HPP
#define ABLELDR_ENCRYPT_HPP
#include <Windows.h>
#include "malapi.hpp"

namespace encrypt
{
	//
	// NOT FUNCTIONAL
	//
	VOID NONE(_Inout_ BYTE* Input, _In_ SIZE_T InputLen, _In_ BYTE* Key, _In_ SIZE_T KeyLen);

	//
	// XORs input with a given key, will repeat the key if KeyLen < InputLen.
	//
	VOID XOR(_Inout_ BYTE* Input, _In_ SIZE_T InputLen, _In_ BYTE* Key, _In_ SIZE_T KeyLen);

	VOID AES(_Inout_ BYTE* Input, _In_ SIZE_T InputLen, _In_ BYTE* Key, _In_ SIZE_T KeyLen);

	VOID RC4(_Inout_ BYTE* Input, _In_ SIZE_T InputLen, _In_ BYTE* Key, _In_ SIZE_T KeyLen);
} // End of encrypt namespace

#endif
