/**
 * Ldr Parser
 * Windows APT Warfare
 * by aaaddress1@chroot.org
 */
#include <stdio.h>
#include <Shlwapi.h>
#include <windows.h>

typedef struct _PEB_LDR_DATA {
	ULONG Length;
	UCHAR Initialized;
	PVOID SsHandle;
	LIST_ENTRY InLoadOrderModuleList;
	LIST_ENTRY InMemoryOrderModuleList;
	LIST_ENTRY InInitializationOrderModuleList;
	PVOID EntryInProgress;
} PEB_LDR_DATA, *PPEB_LDR_DATA;

typedef struct _UNICODE_STRING32 {
	USHORT Length;
	USHORT MaximumLength;
	PWSTR Buffer;
} UNICODE_STRING32, *PUNICODE_STRING32;

typedef struct _PEB32
{
	UCHAR InheritedAddressSpace;
	UCHAR ReadImageFileExecOptions;
	UCHAR BeingDebugged;
	UCHAR BitField;
	ULONG Mutant;
	ULONG ImageBaseAddress;
	PPEB_LDR_DATA Ldr;
	ULONG ProcessParameters;
	ULONG SubSystemData;
	ULONG ProcessHeap;
	ULONG FastPebLock;
	ULONG AtlThunkSListPtr;
	ULONG IFEOKey;
	ULONG CrossProcessFlags;
	ULONG UserSharedInfoPtr;
	ULONG SystemReserved;
	ULONG AtlThunkSListPtr32;
	ULONG ApiSetMap;
} PEB32, *PPEB32;

typedef struct _PEB_LDR_DATA32
{
	ULONG Length;
	BOOLEAN Initialized;
	ULONG SsHandle;
	LIST_ENTRY32 InLoadOrderModuleList;
	LIST_ENTRY32 InMemoryOrderModuleList;
	LIST_ENTRY32 InInitializationOrderModuleList;
	ULONG EntryInProgress;
} PEB_LDR_DATA32, *PPEB_LDR_DATA32;

typedef struct _LDR_DATA_TABLE_ENTRY32
{
	LIST_ENTRY32 InLoadOrderLinks;
	LIST_ENTRY32 InMemoryOrderLinks;
	LIST_ENTRY32 InInitializationOrderLinks;
	ULONG DllBase;
	ULONG EntryPoint;
	ULONG SizeOfImage;
	UNICODE_STRING32 FullDllName;
	UNICODE_STRING32 BaseDllName;
	ULONG Flags;
	USHORT LoadCount;
	USHORT TlsIndex;
	union
	{
		LIST_ENTRY32 HashLinks;
		ULONG SectionPointer;
	};
	ULONG CheckSum;
	union
	{
		ULONG TimeDateStamp;
		ULONG LoadedImports;
	};
	ULONG EntryPointActivationContext;
	ULONG PatchInformation;
} LDR_DATA_TABLE_ENTRY32, *PLDR_DATA_TABLE_ENTRY32;

size_t GetModHandle(wchar_t *libName) {
	PEB32 *pPEB = (PEB32 *)__readfsdword(0x30); // ds: fs[0x30]
	PLIST_ENTRY header = &(pPEB->Ldr->InMemoryOrderModuleList);

	for (PLIST_ENTRY curr = header->Flink; curr != header; curr = curr->Flink) {
		LDR_DATA_TABLE_ENTRY32 *data = CONTAINING_RECORD(
			curr, LDR_DATA_TABLE_ENTRY32, InMemoryOrderLinks
		);
		printf("current node: %ls\n", data->BaseDllName.Buffer);
		if (StrStrIW(libName, data->BaseDllName.Buffer))
			return data->DllBase;
	}
	return 0;
}

int main(int argc, char** argv, char* envp) {
	HMODULE kernelBase = (HMODULE)GetModHandle(L"kernel32.dll");
	printf("kernel32.dll base @ %p\n", kernelBase);
	
	size_t ptr_WinExec = (size_t)GetProcAddress(kernelBase, "WinExec");
	((UINT(WINAPI*)(LPCSTR, UINT))ptr_WinExec)("calc", SW_SHOW);

	return 0;
}
