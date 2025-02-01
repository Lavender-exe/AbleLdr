#ifndef ABLELDR_ENCRYPT_HPP
#define ABLELDR_ENCRYPT_HPP
#include <Windows.h>
#include "malapi.hpp"

namespace encrypt
{
	//
	// NOT FUNCTIONAL
	//
	VOID NoEncrypt(_Inout_ BYTE* Input, _In_ SIZE_T InputLen, _In_ BYTE* Key, _In_ SIZE_T KeyLen);
	VOID XorEncrypt(_Inout_ BYTE* Input, _In_ SIZE_T InputLen, _In_ BYTE* Key, _In_ SIZE_T KeyLen);
	VOID AesEncrypt(_Inout_ BYTE* Input, _In_ SIZE_T InputLen, _In_ BYTE* Key, _In_ SIZE_T KeyLen);
	VOID Rc4Encrypt(_Inout_ BYTE* Input, _In_ SIZE_T InputLen, _In_ BYTE* Key, _In_ SIZE_T KeyLen);
} // End of encrypt namespace

#endif
