/**
 * PE Parser
 * Windows APT Warfare
 * by aaaddress1@chroot.org
 */
#include <stdio.h>
#include <windows.h>
#pragma warning( disable:4996 )
bool readBinFile(const char fileName[], char*& bufPtr, DWORD& length) {
	if (FILE* fp = fopen(fileName, "rb")) {
		fseek(fp, 0, SEEK_END);
		length = ftell(fp);
		bufPtr = new char[length + 1];
		fseek(fp, 0, SEEK_SET);
		fread(bufPtr, sizeof(char), length, fp);
		return true;
	}
	else return false;
}

void peParser(char* ptrToPeBinary) {
	IMAGE_DOS_HEADER* dosHdr = (IMAGE_DOS_HEADER *)ptrToPeBinary;
	IMAGE_NT_HEADERS* ntHdrs = (IMAGE_NT_HEADERS *)((size_t)dosHdr + dosHdr->e_lfanew);
	if (dosHdr->e_magic != IMAGE_DOS_SIGNATURE || ntHdrs->Signature != IMAGE_NT_SIGNATURE) {
		puts("[!] PE binary broken or invalid?");
		return;
	}

	// display infornamtion of optional header
	if (auto optHdr = &ntHdrs->OptionalHeader) {
		printf("[+] ImageBase prefer @ %p\n", optHdr->ImageBase);
		printf("[+] Dynamic Memory Usage: %x bytes.\n", optHdr->SizeOfImage);
		printf("[+] Dynamic EntryPoint @ %p\n", optHdr->ImageBase + optHdr->AddressOfEntryPoint);
	}

	// enumerate section data
	puts("[+] Section Info");
	IMAGE_SECTION_HEADER* sectHdr = (IMAGE_SECTION_HEADER *)((size_t)ntHdrs + sizeof(*ntHdrs));
	for (size_t i = 0; i < ntHdrs->FileHeader.NumberOfSections; i++)
		printf("\t#%.2x - %8s - %.8x - %.8x \n", i, sectHdr[i].Name, sectHdr[i].PointerToRawData, sectHdr[i].SizeOfRawData);
}

int main(int argc, char** argv) {
	char* binaryData; DWORD binarySize;
	if (argc != 2)
		puts("[!] usage: peParser.exe [path/to/exe]");
	else if (readBinFile(argv[1], binaryData, binarySize)) {
		printf("[+] try to parse PE binary @ %s\n", argv[1]);
		peParser(binaryData);
	}
	else puts("[!] read file failure.");
	return 0;	
}


