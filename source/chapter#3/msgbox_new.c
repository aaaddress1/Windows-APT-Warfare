/**
 * msgbox_new.c
 * $ gcc -static msgbox_new.c -o msgbox_new.exe 
 * Windows APT Warfare
 * by aaaddress1@chroot.org
 */
#include <stdio.h>
#include <windows.h>
typedef int(WINAPI* def_MessageBoxA)(HWND, char*, char*, UINT);

int main(void) {
    
    size_t get_MessageBoxA = (size_t)GetProcAddress( LoadLibraryA("USER32.dll"), "MessageBoxA" );
    printf("[+] imp_MessageBoxA: %p\n", MessageBoxA);
    printf("[+] get_MessageBoxA: %p\n", get_MessageBoxA);

    def_MessageBoxA msgbox_a = (def_MessageBoxA) get_MessageBoxA;
    msgbox_a(0, "hi there", "info", 0);
    return 0;
}
