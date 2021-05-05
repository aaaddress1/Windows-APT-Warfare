/**
 * iat_parser.cpp
 * Windows APT Warfare
 * by aaaddress1@chroot.org
 */
#include <stdio.h>
#include <windows.h>
#pragma warning(disable : 4996)
#define getNtHdr(buf) ((IMAGE_NT_HEADERS *)((size_t)buf + ((IMAGE_DOS_HEADER *)buf)->e_lfanew))
#define getSectionArr(buf) ((IMAGE_SECTION_HEADER *)((size_t)buf + ((IMAGE_DOS_HEADER *)buf)->e_lfanew + sizeof(IMAGE_NT_HEADERS)))

bool readBinFile(const char fileName[], char **bufPtr, size_t &length)
{
	if (FILE *fp = fopen(fileName, "rb"))
	{
		fseek(fp, 0, SEEK_END);
		length = ftell(fp);
		*bufPtr = (char *)malloc(length + 1);
		fseek(fp, 0, SEEK_SET);
		fread(*bufPtr, sizeof(char), length, fp);
		return true;
	}
	else
		return false;
}

size_t rvaToOffset(char *exeData, size_t RVA)
{
	for (size_t i = 0; i < getNtHdr(exeData)->FileHeader.NumberOfSections; i++)
	{
		auto currSection = getSectionArr(exeData)[i];
		if (RVA >= currSection.VirtualAddress &&
			RVA <= currSection.VirtualAddress + currSection.Misc.VirtualSize)
			return currSection.PointerToRawData + (RVA - currSection.VirtualAddress);
	}
	return 0;
}

int main(int argc, char **argv)
{
	char *exeBuf;
	size_t exeSize;
	if (argc != 2)
		puts("usage: ./iat_parser [path/to/exe]");
	else if (readBinFile(argv[1], &exeBuf, exeSize))
	{
		// lookup RVA of IAT (Import Address Table)
		IMAGE_OPTIONAL_HEADER optHdr = getNtHdr(exeBuf)->OptionalHeader;
		IMAGE_DATA_DIRECTORY iatDir = optHdr.DataDirectory[IMAGE_DIRECTORY_ENTRY_IAT];
		size_t offset_impAddrArr = rvaToOffset(exeBuf, iatDir.VirtualAddress);
		size_t len_iatCallVia = iatDir.Size / sizeof(DWORD);

		// parse table
		auto iatArr = (IMAGE_THUNK_DATA *)(exeBuf + offset_impAddrArr);
		for (int i = 0; i < len_iatCallVia; iatArr++, i++)
			if (auto nameRVA = iatArr->u1.Function)
			{
				PIMAGE_IMPORT_BY_NAME k = (PIMAGE_IMPORT_BY_NAME)(exeBuf + rvaToOffset(exeBuf, nameRVA));
				printf("[+] imported API -- %s (hint = %i)\n", &k->Name, k->Hint);
			}
	}
	else
		puts("[!] dll file not found.");
	return 0;
}