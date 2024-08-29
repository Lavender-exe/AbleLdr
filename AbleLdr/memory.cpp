#include "memory.hpp"

namespace memory {
	PPEB GetPeb(void)
	{
		return (PPEB)__readgsqword(0x60);
	}

	HMODULE GetModuleHandleC(_In_ ULONG ModuleHash)
	{
		PPEB peb = GetPeb();
		PLIST_ENTRY Head = &peb->Ldr->InMemoryOrderModuleList;
		PLIST_ENTRY Next = Head->Flink;
		PLDR_MODULE Module = NULL;
		HMODULE Result = NULL;

		while (Next != Head) {
			Module = (PLDR_MODULE)((BYTE*)Next - sizeof(LIST_ENTRY));

			if (Module->BaseDllName.Buffer != NULL) {
				if (ModuleHash - HashString(Module->BaseDllName.Buffer) == 0)
				{
					Result = (HMODULE)Module->BaseAddress;
				}
				break;
			}

			Next = Next->Flink;
		}

		return Result;
	}

	FARPROC GetProcAddressC(_In_ HMODULE ModuleHandle, _In_ ULONG FunctionHash)
	{
		PIMAGE_DOS_HEADER DosHeader = (PIMAGE_DOS_HEADER)(ModuleHandle);
		PIMAGE_NT_HEADERS NtHeader = (PIMAGE_NT_HEADERS)((PBYTE)DosHeader + (DosHeader)->e_lfanew);
		PIMAGE_EXPORT_DIRECTORY Exports = (PIMAGE_EXPORT_DIRECTORY)((PBYTE)DosHeader + (NtHeader)->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);
		PWORD NameOrdinals = NULL;
		PDWORD Names = NULL;
		PDWORD Functions = NULL;
		LPCSTR name = NULL;
		PBYTE function = NULL;

		if (Exports->AddressOfNames != 0) {
			NameOrdinals = (PWORD)((UINT_PTR)ModuleHandle + Exports->AddressOfNameOrdinals);
			Names = (PDWORD)((UINT_PTR)ModuleHandle + Exports->AddressOfNames);
			Functions = (PDWORD)((UINT_PTR)ModuleHandle + Exports->AddressOfFunctions);

			for (DWORD i = 0; i < Exports->NumberOfNames; i++) {
				name = (LPCSTR)((UINT_PTR)ModuleHandle + Names[i]);

				if (HashString(name) == FunctionHash) {
					function = (PBYTE)((UINT_PTR)ModuleHandle + Functions[NameOrdinals[i]]);
					return (FARPROC)function;
				}
			}
		}
		return NULL;
	}
} // End of memory namespace