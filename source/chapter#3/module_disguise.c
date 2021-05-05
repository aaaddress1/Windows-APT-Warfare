/**
 * module_disguise.c
 * Windows APT Warfare
 * by aaaddress1@chroot.org
 */
#include <stdio.h>
#include <Shlwapi.h>
#include <Windows.h>


typedef struct _PEB_LDR_DATA
{
	ULONG Length;
	UCHAR Initialized;
	PVOID SsHandle;
	LIST_ENTRY InLoadOrderModuleList;
	LIST_ENTRY InMemoryOrderModuleList;
	LIST_ENTRY InInitializationOrderModuleList;
	PVOID EntryInProgress;
} PEB_LDR_DATA, *PPEB_LDR_DATA;

typedef struct _UNICODE_STRING32
{
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

void renameDynModule(const wchar_t *libName) {
	typedef void(WINAPI *RtlInitUnicodeString)(PUNICODE_STRING32, PCWSTR);
	RtlInitUnicodeString pfnRtlInitUnicodeString = (RtlInitUnicodeString)(
		GetProcAddress(LoadLibraryA("ntdll"), "RtlInitUnicodeString")
	);

	PPEB32 pPEB = (PPEB32)__readfsdword(0x30);
	PLIST_ENTRY header = &(pPEB->Ldr->InLoadOrderModuleList);
	for (PLIST_ENTRY curr = header->Flink; curr != header; curr = curr->Flink) {
		LDR_DATA_TABLE_ENTRY32 *data = (LDR_DATA_TABLE_ENTRY32 *)curr;
		if (StrStrIW(libName, data->BaseDllName.Buffer)) {
			printf("[+] disguise module %ls @ %p\n", data->BaseDllName.Buffer, data->DllBase);
			pfnRtlInitUnicodeString(&data->BaseDllName, L"exploit.dll");
			pfnRtlInitUnicodeString(&data->FullDllName, L"C:\\Windows\\System32\\exploit.dll");
			break;
		}
	}
}


void HideModule(const wchar_t *libName) {
	PPEB32 pPEB = (PPEB32)__readfsdword(0x30);
	PLIST_ENTRY header = &(pPEB->Ldr->InMemoryOrderModuleList);
	for (PLIST_ENTRY curr = header->Flink; curr != header; curr = curr->Flink) {

		LDR_DATA_TABLE_ENTRY32 *inMem_List = CONTAINING_RECORD(
			curr, LDR_DATA_TABLE_ENTRY32, InMemoryOrderLinks
		);

		if (StrStrIW(libName, inMem_List->BaseDllName.Buffer)) {
			printf("[+] strip node %ls @ %p\n", libName, inMem_List->DllBase);

			LIST_ENTRY32* prev = (LIST_ENTRY32 *)inMem_List->InMemoryOrderLinks.Blink;
			LIST_ENTRY32* next = (LIST_ENTRY32 *)inMem_List->InMemoryOrderLinks.Flink;
			if (prev) prev->Flink = (DWORD)next;
			if (next) next->Blink = (DWORD)prev;

			 prev = (LIST_ENTRY32 *)inMem_List->InLoadOrderLinks.Blink;
			 next = (LIST_ENTRY32 *)inMem_List->InLoadOrderLinks.Flink;
			if (prev) prev->Flink = (DWORD)next;
			if (next) next->Blink = (DWORD)prev;

			prev = (LIST_ENTRY32 *)inMem_List->InInitializationOrderLinks.Blink;
			next = (LIST_ENTRY32 *)inMem_List->InInitializationOrderLinks.Flink;
			if (prev) prev->Flink = (DWORD)next;
			if (next) next->Blink = (DWORD)prev;
			break;
		}
	}
}

int main(void) {
	renameDynModule(L"KERNEL32.DLL");
	HideModule(L"USER32.dll");
	MessageBoxA(0, "msgbox() from somewhere?", "info", 0);
	return 0;
}
