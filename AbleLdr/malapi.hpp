#ifndef MALAPI_MALAPI_HPP
#define MALAPI_MALAPI_HPP
#include <windows.h>

//
// String compare implementation (ascii).
//
INT StringCompareA(_In_ LPCSTR String1, _In_ LPCSTR String2)
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
INT StringCompareW(_In_ LPCWSTR String1, _In_ LPCWSTR String2)
{
	for (; *String1 == *String2; String1++, String2++)
	{
		if (*String1 == '\0')
			return 0;
	}

	return ((*(LPCWSTR)String1 < *(LPCWSTR)String2) ? -1 : +1);
}

#endif