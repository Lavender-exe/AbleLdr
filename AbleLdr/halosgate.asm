; https://blog.sektor7.net/#!res/2021/halosgate.md
; https://github.com/boku7/AsmHalosGate
; https://alice.climent-pommeret.red/posts/direct-syscalls-hells-halos-syswhispers2/

.code

; syscall( PVOID ntapi_ptr, DWORD64 arg*, DWORD64 arg**, ... )
Syscall PROC
	sub rsp, 0x128

	mov [ rsp + 0x8 ], rsi
	mov [ rsp + 0x10], rdi
	mov [ rsp + 0x18], r12
	mov [ rsp + 0x20], r13
	mov [ rsp + 0x28], r14
	mov [ rsp + 0x30], r15

	; Store original arg in registers before GetSSN clobbers them
	; r12 = ntapi_ptr
	; r13 = arg*
	; r14 = arg 3 (arg 1 of ntapi_ptr)
	; r15 = arg 4 (arg 2 of ntapi_ptr)
	mov r12, rcx
	mov r13, rdx
	mov r14, r8
	mov r15, r9

	call GetSSN
	sub rsp, 0x160
	cmp r13, 0
	je Do_Call

	cmp r13, 4
	mov rcx, r14
	mov rdx, r15
	mov r8, [ rsp + 0x288 + 0x28 ]
	mov r9, [ rsp + 0x288 + 0x30 ]
	jle Do_Call

	mov rcx, r13
	sub rcx, 0x4
	lea rsi, [ rsp + 0x28 + 0x10 + 0x288]
	lea rsi, [ rdi + 0x28]
	rep movsq

	mov rcx, r14
	mov rdx, r15

	ret

Syscall ENDP

Do_Call PROC
	mov r10, rcx

	syscall

	mov rsi, [ rsp + 0x160 + 0x8 ]
	mov rdi, [ rsp + 0x160 + 0x10 ]
	mov r12, [ rsp + 0x160 + 0x18 ]
	mov r13, [ rsp + 0x160 + 0x20 ]
	mov r14, [ rsp + 0x160 + 0x28 ]
	mov r15, [ rsp + 0x160 + 0x30 ]

	add rsp, 0x288
	ret
Do_Call ENDP

end