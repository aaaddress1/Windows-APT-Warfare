// fetch current EXE path from 64 bit PEB->Ldr (In 32 bit mode)
// by aaaddress1@chroot.org
#include <stdint.h>
#include <stdio.h>
#include <windows.h>
typedef struct _PEB_LDR_DATA64
{
    ULONG Length;
    BOOLEAN Initialized;
    ULONG64 SsHandle;
    LIST_ENTRY64 InLoadOrderModuleList;
    LIST_ENTRY64 InMemoryOrderModuleList;
    LIST_ENTRY64 InInitializationOrderModuleList;
    ULONG64 EntryInProgress;
} PEB_LDR_DATA64, *PPEB_LDR_DATA64;

typedef struct _UNICODE_STRING64
{
    USHORT Length;
    USHORT MaximumLength;
    PWSTR Buffer;
} UNICODE_STRING64, *PUNICODE_STRING64;

typedef struct _LDR_DATA_TABLE_ENTRY64
{
    LIST_ENTRY64 InLoadOrderLinks;
    LIST_ENTRY64 InMemoryOrderModuleList;
    LIST_ENTRY64 InInitializationOrderModuleList;
    ULONG64 DllBase;
    ULONG64 EntryPoint;
    ULONG SizeOfImage;
    UNICODE_STRING64 FullDllName;
    UNICODE_STRING64 BaseDllName;
    ULONG Flags;
    USHORT LoadCount;
    USHORT TlsIndex;
    union
    {
        LIST_ENTRY64 HashLinks;
        ULONG64 SectionPointer;
    };
    ULONG CheckSum;
    union
    {
        ULONG TimeDateStamp;
        ULONG64 LoadedImports;
    };
    ULONG64 EntryPointActivationContext;
    ULONG64 PatchInformation;
} LDR_DATA_TABLE_ENTRY64, *PLDR_DATA_TABLE_ENTRY64;
typedef struct _PEB64
{
    UCHAR InheritedAddressSpace;
    UCHAR ReadImageFileExecOptions;
    UCHAR BeingDebugged;
    UCHAR BitField;
    ULONG64 Mutant;
    ULONG64 ImageBaseAddress;
    ULONG64 Ldr;
    ULONG64 ProcessParameters;
    ULONG64 SubSystemData;
    ULONG64 ProcessHeap;
    ULONG64 FastPebLock;
    ULONG64 AtlThunkSListPtr;
    ULONG64 IFEOKey;
    ULONG64 CrossProcessFlags;
    ULONG64 UserSharedInfoPtr;
    ULONG SystemReserved;
    ULONG AtlThunkSListPtr32;
    ULONG64 ApiSetMap;
} PEB64, *PPEB64;

auto memcpy64 = ((void(cdecl *)(ULONG64, ULONG64, ULONG64))((PCSTR){
    // enter 64 bit mode
    "\x6a\x33\xe8\x00\x00\x00\x00\x83\x04\x24\x05\xcb"
    // memcpy for 64 bit
    "\x67\x48\x8b\x7c\x24\x04\x67\x48\x8b\x74\x24\x0c\x67\x48\x8b\x4c\x24\x14\xf3\xa4"
    // exit 64 bit mode
    "\xe8\x00\x00\x00\x00\xc7\x44\x24\x04\x23\x00\x00\x00\x83\x04\x24\x0d\xcb\xc3"
}));

int main(void) {
    // mov eax,gs:[00000060]; ret
    auto peb64 = (PPEB64)((DWORD(*)()) "\x65\xA1\x60\x00\x00\x00\xC3")();

    // fetch ldr head node
    PEB_LDR_DATA64 ldrNode = {};
    memcpy64((ULONG64)&ldrNode, (ULONG64)peb64->Ldr, sizeof(ldrNode));

    // read the first ldr node (should be the current EXE module)
    LDR_DATA_TABLE_ENTRY64 currNode = {};
    memcpy64((ULONG64)&currNode, (ULONG64)ldrNode.InLoadOrderModuleList.Flink, sizeof(currNode));

    // display the result ;)
    printf("image base @ %llp\n",currNode.DllBase);
    printf("%ls\n", currNode.BaseDllName.Buffer);
    return 0;
}