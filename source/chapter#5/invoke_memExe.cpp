/**
 * invoke_memExe.cpp
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

void fixIat(char *peImage)
{
	auto dir_ImportTable = getNtHdr(peImage)->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
	auto impModuleList = (IMAGE_IMPORT_DESCRIPTOR *)&peImage[dir_ImportTable.VirtualAddress];
	for (HMODULE currMod; impModuleList->Name; impModuleList++)
	{
		printf("\timport module : %s\n", &peImage[impModuleList->Name]);
		currMod = LoadLibraryA(&peImage[impModuleList->Name]);

		auto arr_callVia = (IMAGE_THUNK_DATA *)&peImage[impModuleList->FirstThunk];
		for (int count = 0; arr_callVia->u1.Function; count++, arr_callVia++)
		{
			auto curr_impApi = (PIMAGE_IMPORT_BY_NAME)&peImage[arr_callVia->u1.Function];
			arr_callVia->u1.Function = (size_t)GetProcAddress(currMod, (char *)curr_impApi->Name);
			if (count < 5)
				printf("\t\t- fix imp_%s\n", curr_impApi->Name);
		}
	}
}
void invoke_memExe(char *exeData)
{
	auto imgBaseAt = (void *)getNtHdr(exeData)->OptionalHeader.ImageBase;
	auto imgSize = getNtHdr(exeData)->OptionalHeader.SizeOfImage;
	if (char *peImage = (char *)VirtualAlloc(imgBaseAt, imgSize, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE))
	{
		printf("[v] exe file mapped @ %p\n", peImage);
		memcpy(peImage, exeData, getNtHdr(exeData)->OptionalHeader.SizeOfHeaders);
		for (int i = 0; i < getNtHdr(exeData)->FileHeader.NumberOfSections; i++)
		{
			auto curr_section = getSectionArr(exeData)[i];
			memcpy(
				&peImage[curr_section.VirtualAddress],
				&exeData[curr_section.PointerToRawData],
				curr_section.SizeOfRawData);
		}
		printf("[v] file mapping ok\n");

		fixIat(peImage);
		printf("[v] fix iat.\n");

		auto addrOfEntry = getNtHdr(exeData)->OptionalHeader.AddressOfEntryPoint;
		printf("[v] invoke entry @ %p ...\n", &peImage[addrOfEntry]);
		((void (*)()) & peImage[addrOfEntry])();
	}
	else
		printf("[x] alloc memory for exe @ %p failure.\n", imgBaseAt);
}

int main(int argc, char **argv)
{
	char *exeBuf;
	size_t exeSize;
	if (argc != 2)
		puts("usage: ./invoke_memExe [path/to/exe]");
	else if (readBinFile(argv[1], &exeBuf, exeSize))
		invoke_memExe(exeBuf);
	else
		puts("[!] exe file not found.");
	return 0;
}