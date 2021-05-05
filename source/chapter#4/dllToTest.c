/*
 * dllToTest.c
 * $ gcc -static --shared dllToTest.c -o demo.dll
 * Windows APT Warfare
 * by aaaddress1@chroot.org
 */
#include <windows.h>
char sz_Message[256] = "Top Secret";

__declspec(dllexport) void func01() { MessageBoxA(0, sz_Message, "func_1", 0); }
__declspec(dllexport) void func02() { MessageBoxA(0, sz_Message, "func_2", 0); }
__declspec(dllexport) void func03() { MessageBoxA(0, sz_Message, "func_3", 0); }

BOOL WINAPI DllMain( HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpReserved ) {
    if ( fdwReason == DLL_PROCESS_ATTACH )
        strcpy(sz_Message, "Hello Hackers!");
    return TRUE;
}

void testHello() { /* dummy function */ Sleep(1000); }
__declspec(dllexport) void func04() { MessageBoxA(0, sz_Message, "func_4", 0); }
__declspec(dllexport) void func05() { MessageBoxA(0, sz_Message, "func_5", 0); }