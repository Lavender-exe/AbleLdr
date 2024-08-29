#include "memory.hpp"
#include "malapi.hpp"
#include "typedef.hpp"

namespace memory {
	PPEB GetPeb(void)
	{
		return (PPEB)__readgsqword(0x60);
	}

	HMODULE _GetModuleHandle(_In_ LPCWSTR ModuleName)
	{
		PPEB peb = GetPeb();
		PLIST_ENTRY Head = &peb->Ldr->InMemoryOrderModuleList;
		PLIST_ENTRY Next = Head->Flink;
		PLDR_MODULE Module = NULL;
		HMODULE Result = NULL;

		while (Next != Head) {
			Module = (PLDR_MODULE)((BYTE*)Next - sizeof(LIST_ENTRY));
			if (StringCompareW(Module->BaseDllName.Buffer, ModuleName) == 0) {
				Result = (HMODULE)Module->BaseAddress;
				break;
			}

			Next = Next->Flink;
		}

		return Result;
	}

	FARPROC _GetProcAddress(_In_ HMODULE ModuleHandle, _In_ LPCSTR FunctionName)
	{
		PIMAGE_DOS_HEADER DosHeader = (PIMAGE_DOS_HEADER)(ModuleHandle);
		PIMAGE_NT_HEADERS NtHeader = (PIMAGE_NT_HEADERS)((PBYTE)DosHeader + (DosHeader)->e_lfanew);
		PIMAGE_EXPORT_DIRECTORY Exports = (PIMAGE_EXPORT_DIRECTORY)((PBYTE)DosHeader + (NtHeader)->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);

		if (Exports->AddressOfNames != 0) {
			PWORD NameOrdinals = (PWORD)((UINT_PTR)ModuleHandle + Exports->AddressOfNameOrdinals);
			PDWORD Names = (PDWORD)((UINT_PTR)ModuleHandle + Exports->AddressOfNames);
			PDWORD Functions = (PDWORD)((UINT_PTR)ModuleHandle + Exports->AddressOfFunctions);

			for (DWORD i = 0; i < Exports->NumberOfNames; i++) {
				LPCSTR name = (LPCSTR)((UINT_PTR)ModuleHandle + Names[i]);

				if (StringCompareA(name, FunctionName)) {
					PBYTE function = (PBYTE)((UINT_PTR)ModuleHandle + Functions[NameOrdinals[i]]);
					return (FARPROC)function;
				}
			}
		}
		return NULL;
	}
} // End of memory namespace