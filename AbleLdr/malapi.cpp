#include "malapi.hpp"

INT StringCompare(_In_ LPCSTR String1, _In_ LPCSTR String2)
{
	for (; *String1 == *String2; String1++, String2++)
	{
		if (*String1 == '\0')
			return 0;
	}

	return ((*(LPCSTR)String1 < *(LPCSTR)String2) ? -1 : +1);
}

//
// String compare implementation (wchar).
//
INT StringCompare(_In_ LPCWSTR String1, _In_ LPCWSTR String2)
{
	for (; *String1 == *String2; String1++, String2++)
	{
		if (*String1 == '\0')
			return 0;
	}

	return ((*(LPCWSTR)String1 < *(LPCWSTR)String2) ? -1 : +1);
}

// https://github.com/iilegacyyii/ThreadlessInject-BOF/blob/main/entry.c
//
// HashString Implementation (Ascii)
//
constexpr ULONG HashStringFowlerNollVoVariant1a(_In_ LPCSTR String)
{
	ULONG Hash = 0x6A6CCC06;

	while (*String)
	{
		Hash ^= (UCHAR)*String++;
		Hash *= 0x25EDE3FB;
	}

	return Hash;
}
//
// HashString Implementation (wChar)
//
constexpr ULONG HashStringFowlerNollVoVariant1a(_In_ LPCWSTR String)
{
	ULONG Hash = 0x6A6CCC06;

	while (*String)
	{
		Hash ^= (UCHAR)*String++;
		Hash *= 0x25EDE3FB;
	}

	return Hash;
}