/**
 * Tiny Linker
 * Windows APT Warfare
 * by aaaddress1@chroot.org
 */
#include <iostream>
#include <Windows.h>
#pragma warning(disable : 4996)
#define file_align 0x200
#define sect_align 0x1000

#define P2ALIGNUP(size, align) ((((size) / align) + 1) * (align))

char x86_nullfree_msgbox[] =
	"\x31\xd2\xb2\x30\x64\x8b\x12\x8b\x52\x0c\x8b\x52\x1c\x8b\x42"
	"\x08\x8b\x72\x20\x8b\x12\x80\x7e\x0c\x33\x75\xf2\x89\xc7\x03"
	"\x78\x3c\x8b\x57\x78\x01\xc2\x8b\x7a\x20\x01\xc7\x31\xed\x8b"
	"\x34\xaf\x01\xc6\x45\x81\x3e\x46\x61\x74\x61\x75\xf2\x81\x7e"
	"\x08\x45\x78\x69\x74\x75\xe9\x8b\x7a\x24\x01\xc7\x66\x8b\x2c"
	"\x6f\x8b\x7a\x1c\x01\xc7\x8b\x7c\xaf\xfc\x01\xc7\x68\x79\x74"
	"\x65\x01\x68\x6b\x65\x6e\x42\x68\x20\x42\x72\x6f\x89\xe1\xfe"
	"\x49\x0b\x31\xc0\x51\x50\xff\xd7";

int main() {
	size_t peHeaderSize = P2ALIGNUP(sizeof(IMAGE_DOS_HEADER) + sizeof(IMAGE_NT_HEADERS) + sizeof(IMAGE_SECTION_HEADER), file_align);
	size_t sectionDataSize = P2ALIGNUP(sizeof(x86_nullfree_msgbox), file_align);
	char *peData = (char *)calloc(peHeaderSize + sectionDataSize, 1);

	// DOS
	PIMAGE_DOS_HEADER dosHdr = (PIMAGE_DOS_HEADER)peData;
	dosHdr->e_magic = IMAGE_DOS_SIGNATURE; // MZ
	dosHdr->e_lfanew = sizeof(IMAGE_DOS_HEADER);

	// NT
	PIMAGE_NT_HEADERS ntHdr = (PIMAGE_NT_HEADERS)(peData + dosHdr->e_lfanew);
	ntHdr->Signature = IMAGE_NT_SIGNATURE; // PE
	ntHdr->FileHeader.Machine = IMAGE_FILE_MACHINE_I386;
	ntHdr->FileHeader.Characteristics = IMAGE_FILE_EXECUTABLE_IMAGE | IMAGE_FILE_32BIT_MACHINE;
	ntHdr->FileHeader.SizeOfOptionalHeader = sizeof(IMAGE_OPTIONAL_HEADER);
	ntHdr->FileHeader.NumberOfSections = 1;

	// Section
	PIMAGE_SECTION_HEADER sectHdr = (PIMAGE_SECTION_HEADER)((char *)ntHdr + sizeof(IMAGE_NT_HEADERS));
	memcpy(&(sectHdr->Name), "30cm.tw", 8);
	sectHdr->VirtualAddress = 0x1000;
	sectHdr->Misc.VirtualSize = P2ALIGNUP(sizeof(x86_nullfree_msgbox), sect_align);
	sectHdr->SizeOfRawData = sizeof(x86_nullfree_msgbox);
	sectHdr->PointerToRawData = peHeaderSize;
	memcpy(peData + peHeaderSize, x86_nullfree_msgbox, sizeof(x86_nullfree_msgbox));
	sectHdr->Characteristics = IMAGE_SCN_MEM_EXECUTE | IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_WRITE;
	ntHdr->OptionalHeader.AddressOfEntryPoint = sectHdr->VirtualAddress;


	ntHdr->OptionalHeader.Magic = IMAGE_NT_OPTIONAL_HDR32_MAGIC;
	ntHdr->OptionalHeader.BaseOfCode = sectHdr->VirtualAddress; // .text RVA
	ntHdr->OptionalHeader.BaseOfData = 0x0000;                  // .data RVA
	ntHdr->OptionalHeader.ImageBase = 0x400000;
	ntHdr->OptionalHeader.FileAlignment = file_align;
	ntHdr->OptionalHeader.SectionAlignment = sect_align;
	ntHdr->OptionalHeader.Subsystem = IMAGE_SUBSYSTEM_WINDOWS_GUI;
	ntHdr->OptionalHeader.SizeOfImage = sectHdr->VirtualAddress + sectHdr->Misc.VirtualSize;
	ntHdr->OptionalHeader.SizeOfHeaders = peHeaderSize;
	ntHdr->OptionalHeader.MajorSubsystemVersion = 5;
	ntHdr->OptionalHeader.MinorSubsystemVersion = 1;


	FILE *fp = fopen("poc.exe", "wb");
	fwrite(peData, peHeaderSize + sectionDataSize, 1, fp);
}
