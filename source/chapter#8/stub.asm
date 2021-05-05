bits 32
; yasm.exe -fwin32 stub.asm && gcc -m32 stub.obj
%include "hldr32.inc"


    section .text
_main:
    pushad
    call decompress_image
    call recover_ntHdr
    call lookup_oep
    push eax
    lea esp, [esp + 0x04]
    popad
    jmp dword [esp - 0x24]

recover_ntHdr:
    ; lookup kernel32.dll imageBase
    fs mov  ebp, dword [tebProcessEnvironmentBlock]
    mov     eax, dword [ebp + pebLdr]
    mov     esi, dword [eax + ldrInLoadOrderModuleList]
    lodsd
    xchg eax, esi
    lodsd
    mov ecx, dword [eax + mlDllBase] ; push kernel32.dll on stack. 

    ; locate VirtualProtect addr
    push 0x00007463
    push 0x65746f72
    push 0x506c6175
    push 0x74726956 ; "VirtualProtect"
    mov edx, esp
    call find_addr ; fastcall calling convention
    mov esi, eax
    add esp, 16

    call fetch_ntHdr
    push eax ; keep "ntHdr" section VA
    push ebx ; keep "ntHdr" section Size

    mov edi, dword [ebp + imageBaseAddr]
    add edi, dword [edi + lfanew]
    push 0xdeadbeef ; reserved for lpflOldProtect

    push esp
    push PAGE_READWRITE
    push ebx
    push edi
    call esi;  invoke VirtualProtect()
    add esp, 0x04
    
    ; memcpy NtHeaders
    pop ecx ; set memory copy count = "ntHdr" Size
    pop esi ; set copy from "ntHdr" VA
    rep movsb
    ret

decompress_image:
    ; ==== push exe imagebase on stack ==== 
    fs mov  eax, dword [tebProcessEnvironmentBlock]
    push dword [eax + imageBaseAddr]

    ; ==== push ntdll.dll & kernel32.dll base to stack ====
    mov     eax, dword [eax + pebLdr]
    mov     esi, dword [eax + ldrInLoadOrderModuleList]
    lodsd
    push dword [eax + mlDllBase]

    xchg eax, esi
    lodsd
    mov eax, dword [eax + mlDllBase] ; push kernel32.dll on stack.
    push eax
    mov ebp, esp
    nop
    nop 

    ; ==== push all win32 api addr on stack ====
    ; lookup API addr LoadLibraryA
    push 0x00000000
    push 0x41797261
    push 0x7262694c
    push 0x64616f4c ; LoadLibraryA
    mov edx, esp
    mov ecx, dword [ebp+0x00] ; kernel32 base
    call find_addr ; fastcall calling convention
    add esp, 16
    push eax
    nop
    ; lookup API addr GetProcAddress
    push 0x00007373
    push 0x65726464
    push 0x41636f72
    push 0x50746547 ; "GetProcAddress"
    mov edx, esp
    mov ecx, dword [ebp+0x00] ; kernel32 base
    call find_addr ; fastcall calling convention
    add esp, 16
    push eax
    nop
    ; lookup API addr RtlDecompressBuffer
    push 0x726566
    push 0x66754273
    push 0x73657270
    push 0x6d6f6365
    push 0x446c7452
    mov edx, esp
    mov ecx, dword [ebp+0x04] ; ntdll base
    call find_addr ; fastcall calling convention
    add esp, 20
    push eax
    mov ebp, esp

    ; ==== decompress and spraying image data ====
    push 0xdeadbeef
    push esp

    mov edx, 0x61746164 ;"data"
    mov ecx, dword [ebp+0x14]; exe base
    call lookupSectInfo
    add eax, [ebp+20]
    push ebx
    push eax
    
    mov edx, 0x74786574 ;"text"
    mov ecx, dword [ebp+0x14]; exe base
    call lookupSectInfo
    add eax, [ebp+20]
    push ebx
    push eax
    push COMPRESSION_FORMAT_LZNT1
    call dword [ebp + 0x00]
    lea esp, [esp+0x04]
    call fetch_ntHdr
    mov ebx, eax ; let ebx keep the virtual address of NtHeaders record
    nop

fix_iat:
    lea ecx, [ebx + IMAGE_DIRECTORY_ENTRY_IMPORT]
    mov ecx, dword [ecx]
    add ecx, [ebp + 20]; ecx point to the current IMAGE_IMPORT_DESCRIPTOR 

import_dll:
    mov eax, dword [ecx + _IMAGE_IMPORT_DESCRIPTOR.idName]
    test eax, eax
    jz iatfix_done
    add eax, [ebp + 20]; eax point to the imported API name (char array)
    push eax
    call dword [ebp + 0x08]; LoadLibraryA
    mov ebx, eax; let ebx keep the imageBase of the imported dll
    mov edi, dword [ecx + _IMAGE_IMPORT_DESCRIPTOR.idFirstThunk]
    add edi, dword [ebp + 20] ; set destination point to IMAGE_THUNK_DATA array
    mov esi, edi
    nop

import_callVia:
    lodsd
    test eax, eax
    jz import_next
    add eax, dword [ebp + 20]; eax point to PIMAGE_IMPORT_BY_NAME struct
    lea eax, [eax + 2]; PIMAGE_IMPORT_BY_NAME->Name
    push ecx
    push eax
    push ebx
    call dword [ebp + 0x04]; GetProcAddress
    stosd
    pop ecx
    jmp import_callVia
    
import_next:
    lea ecx, [ecx + _IMAGE_IMPORT_DESCRIPTOR_size]
    jmp import_dll

iatfix_done:
    lea esp, [esp + 24]
    ret

fetch_ntHdr: ; set eax and ebx to NtHeaders old record on ntHdr section.
    fs mov  ecx, dword [tebProcessEnvironmentBlock]
    mov ecx, dword [ecx + imageBaseAddr]
    mov edx, 0x6448746e ;"ntHdr"
    push ecx
    call lookupSectInfo
    pop ecx
    add eax, ecx; IMAGE_NT_HEADERS record from ntHdr section
    ret
    
lookup_oep:
    fs mov  ecx, dword [tebProcessEnvironmentBlock]
    mov ecx, dword [ecx + imageBaseAddr]
    mov edx, 0x6448746e ;"ntHdr"
    push ecx
    call lookupSectInfo
    pop ecx
    add eax, ecx; IMAGE_NT_HEADERS record from ntHdr section
    lea eax, [eax + _IMAGE_NT_HEADERS.nthOptionalHeader]
    mov eax, dword [eax + _IMAGE_OPTIONAL_HEADER.ohAddressOfEntryPoint]   
    add eax, ecx ; virtual address of OEP (orginal entry point)
    ret

lookupSectInfo:
    push ebp
    mov ebp, ecx
    nop

    mov eax, dword [ebp + lfanew]
    add eax, ebp ; eax point to NtHdr
    movzx ecx, word [ eax + _IMAGE_NT_HEADERS.nthFileHeader + _IMAGE_FILE_HEADER.fhSizeOfOptionalHeader]
    lea ecx, dword [eax + ecx +  _IMAGE_NT_HEADERS.nthOptionalHeader]

chkSectName:
    mov ebx, dword [ecx + _IMAGE_SECTION_HEADER.shName]
    add ecx, _IMAGE_SECTION_HEADER_size
    cmp ebx, edx
    jne chkSectName
    
    sub ecx, _IMAGE_SECTION_HEADER_size
    mov eax, dword [ecx + _IMAGE_SECTION_HEADER.shVirtualAddress] ; keep section va in eax
    mov ebx, dword [ecx + _IMAGE_SECTION_HEADER.shVirtualSize]    ; keep section size in ebx
    pop ebp
    ret
; ==============================================================
find_addr:
    push ebp
parse_eat:
    mov     ebp, ecx ; set ebp = current dll module base
    mov     ecx, edx ; let ecx keep API name 
    nop
    mov     ebx, ebp
    mov     eax, dword [ebp + lfanew]
    add     ebx, dword [ebp + eax + IMAGE_DIRECTORY_ENTRY_EXPORT]; ebx = Export Table addr
    cdq ; edx = counter.
walk_names:
    mov     eax, ebp
    mov     edi, ebp
    inc     edx
    add     eax, dword [ebx + _IMAGE_EXPORT_DIRECTORY.edAddressOfNames]; addrOfName Addr
    add     edi, dword [eax + edx * 4]
    xor     esi, esi ; esi = counter for strcmp
strcmp_apiName:
    mov al, byte [ecx + esi]
    cmp al, 0x00
    je found_apiName
    sub al, byte [edi + esi]
    jnz walk_names
    inc esi
    jmp strcmp_apiName
found_apiName:
    mov     edi, ebp
    mov     eax, ebp
    add     edi, dword [ebx + _IMAGE_EXPORT_DIRECTORY.edAddressOfNameOrdinals]
    movzx   edi, word [edi + edx * 2]
    add     eax, dword [ebx + _IMAGE_EXPORT_DIRECTORY.edAddressOfFunctions]
    mov     eax, dword [eax + edi * 4]
    add     eax, ebp
    pop     ebp
    ret
