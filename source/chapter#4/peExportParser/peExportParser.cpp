/**
 * peExportParser.cpp
 * Windows APT Warfare
 * by aaaddress1@chroot.org
 */
#include <iostream>
#include <windows.h>
#pragma warning(disable:4996)
#define getNtHdr(buf) ((IMAGE_NT_HEADERS *)((size_t)buf + ((IMAGE_DOS_HEADER *)buf)->e_lfanew))
#define getSectionArr(buf) ((IMAGE_SECTION_HEADER *)((size_t)buf + ((IMAGE_DOS_HEADER *)buf)->e_lfanew + sizeof(IMAGE_NT_HEADERS)))

bool readBinFile(const char fileName[], char** bufPtr, size_t& length)
{
	if (FILE* fp = fopen(fileName, "rb"))
	{
		fseek(fp, 0, SEEK_END);
		length = ftell(fp);
		*bufPtr = new char[length + 1];
		fseek(fp, 0, SEEK_SET);
		fread(*bufPtr, sizeof(char), length, fp);
		return true;
	}
	else
		return false;
}

size_t rvaToOffset(char* exeData, size_t RVA) {
	for (size_t i = 0; i < getNtHdr(exeData)->FileHeader.NumberOfSections; i++) {
		auto currSection = getSectionArr(exeData)[i];
		if (RVA >= currSection.VirtualAddress &&
			RVA <= currSection.VirtualAddress + currSection.Misc.VirtualSize)
			return currSection.PointerToRawData + (RVA - currSection.VirtualAddress);
	}
	return 0;
}

int main(int argc, char**argv)
{
	if (argc != 2) {
		puts("usage: ./peExportParser [path/to/dll]");
		return 0;
	}
	char* exeBuf; size_t exeSize;
	if (readBinFile(argv[1], &exeBuf, exeSize))
	{
		// lookup RVA of PIMAGE_EXPORT_DIRECTORY (from DataDirectory)
		IMAGE_OPTIONAL_HEADER optHdr = getNtHdr(exeBuf)->OptionalHeader;
		IMAGE_DATA_DIRECTORY dataDir_exportDir = optHdr.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
		size_t offset_exportDir = rvaToOffset(exeBuf, dataDir_exportDir.VirtualAddress);

		// Parse IMAGE_EXPORT_DIRECTORY struct
		PIMAGE_EXPORT_DIRECTORY exportTable = (PIMAGE_EXPORT_DIRECTORY)(exeBuf + offset_exportDir);
		printf("[+] detect module : %s\n", exeBuf + rvaToOffset(exeBuf, exportTable->Name));

		// Enumerate Exported Function Name
		printf("[+] list exported functions (total %i api):\n", exportTable->NumberOfNames);
		uint32_t* arr_rvaOfNames = (uint32_t*)(exeBuf + rvaToOffset(exeBuf, exportTable->AddressOfNames));
		for (size_t i = 0; i < exportTable->NumberOfNames; i++)
			printf("\t#%.2i - %s\n", i, exeBuf + rvaToOffset(exeBuf, arr_rvaOfNames[i]));
	}
	else puts("[!] dll file not found.");
	return 0;
}