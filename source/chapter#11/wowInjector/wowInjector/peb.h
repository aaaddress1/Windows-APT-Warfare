#pragma once
#include <Windows.h>
#include <stdio.h>

typedef LONG PROCESSINFOCLASS;

typedef NTSTATUS(NTAPI* pfnNtQueryInformationProcess)(
	IN  HANDLE ProcessHandle,
	IN  PROCESSINFOCLASS ProcessInformationClass,
	OUT PVOID ProcessInformation,
	IN  ULONG ProcessInformationLength,
	OUT PULONG ReturnLength    OPTIONAL
	);
typedef struct _PEB* PPEB;

typedef struct _PROCESS_BASIC_INFORMATION {
	PVOID Reserved1;
	PPEB PebBaseAddress;
	PVOID Reserved2[2];
	ULONG_PTR UniqueProcessId;
	PVOID Reserved3;
} PROCESS_BASIC_INFORMATION;

PVOID QueryProcessInformation(
	IN HANDLE Process,
	IN PROCESSINFOCLASS ProcessInformationClass,
	IN DWORD ProcessInformationLength
) {
	PROCESS_BASIC_INFORMATION* pProcessInformation = NULL;
	pfnNtQueryInformationProcess gNtQueryInformationProcess;
	ULONG ReturnLength = 0;
	NTSTATUS Status;
	HMODULE hNtDll;

	if (!(hNtDll = LoadLibraryA("ntdll.dll"))) {
		wprintf(L"Cannot load ntdll.dll.\n");
		return NULL;
	}

	if (!(gNtQueryInformationProcess = (pfnNtQueryInformationProcess)GetProcAddress(hNtDll, "NtQueryInformationProcess"))) {
		wprintf(L"Cannot load NtQueryInformationProcess.\n");
		return NULL;
	}

	// Allocate the memory for the requested structure
	if ((pProcessInformation = (PROCESS_BASIC_INFORMATION*)malloc(ProcessInformationLength)) == NULL) {
		wprintf(L"ExAllocatePoolWithTag failed.\n");
		return NULL;
	}

	// Fill the requested structure
	if ((Status = gNtQueryInformationProcess(Process, ProcessInformationClass, pProcessInformation, ProcessInformationLength, &ReturnLength))) {
		wprintf(L"NtQueryInformationProcess should return NT_SUCCESS (Status = %#x).\n", Status);
		free(pProcessInformation);
		return NULL;
	}

	// Check the requested structure size with the one returned by NtQueryInformationProcess
	if (ReturnLength != ProcessInformationLength) {
		wprintf(L"Warning : NtQueryInformationProcess ReturnLength is different than ProcessInformationLength\n");
		return NULL;
	}

	return pProcessInformation;
}
