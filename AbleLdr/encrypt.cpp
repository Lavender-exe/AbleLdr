#include "encrypt.hpp"

namespace encrypt {
	//
	// NOT FUNCTIONAL
	//
	VOID NoEncrypt(_Inout_ BYTE* Input, _In_ SIZE_T InputLen, _In_ BYTE* Key, _In_ SIZE_T KeyLen)
	{
		return shellcode;
	}

	VOID XorEncrypt(_Inout_ BYTE* Input, _In_ SIZE_T InputLen, _In_ BYTE* Key, _In_ SIZE_T KeyLen)
	{
		for (SIZE_T i = 0; i < InputLen; i++)
			Input[i] ^= Key[i % KeyLen];
	}

	VOID AesEncrypt(_Inout_ BYTE* Input, _In_ SIZE_T InputLen, _In_ BYTE* Key, _In_ SIZE_T KeyLen)
	{
		return shellcode;
	}

	VOID Rc4Encrypt(_Inout_ BYTE* Input, _In_ SIZE_T InputLen, _In_ BYTE* Key, _In_ SIZE_T KeyLen)
	{
		return shellcode;
	}
} // End of encrypt namespace
