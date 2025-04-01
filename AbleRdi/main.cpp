#include <Windows.h>

#ifndef _DEBUG
#pragma comment(linker, "/ENTRY:entry")
#endif

VOID entry(void)
{
}

#pragma region alternative entrypoint

int main(void) { entry(); return 0; }

#pragma endregion
