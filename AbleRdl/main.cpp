#include <Windows.h>

#ifndef _DEBUG
#pragma comment(linker, "/ENTRY:entry")
#endif

VOID entry(void)
{
}

BOOL APIENTRY WINAPI DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpvReserved)
{
	switch (fdwReason)
	{
	case DLL_PROCESS_ATTACH:
	{
		entry();
		break;
	}

	case DLL_PROCESS_DETACH:
	{
		if (lpvReserved != nullptr)
		{
			break;
		}
		break;
	}
	}
	return TRUE;
}
