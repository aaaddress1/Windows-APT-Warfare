
#include <iostream>
#include <Windows.h>
#pragma warning(disable : 4996)

char logo[] = {
	"  dP   dP                MMP\"\"\"\"\"\"\"MM          dP      \n"
	"  88   88                M' .mmmm  MM          88      \n"
	"d8888P 88d888b. .d8888b. M         `M 88d888b. 88  .dP \n"
	"  88   88'  `88 88ooood8 M  MMMMM  MM 88'  `88 88888\"  \n"
	"  88   88    88 88.  ... M  MMMMM  MM 88       88  `8b.\n"
	"  dP   dP    dP `88888P' M  MMMMM  MM dP       dP   `YP\n"
	"                         MMMMMMMMMMMM\n"
	"                 theArk [x86] by aaaddress1@chroot.org\n"
	" >>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>> \n\n"};

bool readBinFile(const char fileName[], char **bufPtr, DWORD &length)
{
	if (FILE *fp = fopen(fileName, "rb"))
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

#define getNtHdr(buf) ((IMAGE_NT_HEADERS *)((size_t)buf + ((IMAGE_DOS_HEADER *)buf)->e_lfanew))
#define getSectionArr(buf) ((IMAGE_SECTION_HEADER *)((size_t)buf + ((IMAGE_DOS_HEADER *)buf)->e_lfanew + sizeof(IMAGE_NT_HEADERS)))
typedef NTSTATUS(WINAPI *XRtlCompressBuffer)(USHORT CompressionFormatAndEngine, PUCHAR UncompressedBuffer, ULONG UncompressedBufferSize, PUCHAR CompressedBuffer,
											 ULONG CompressedBufferSize, ULONG UncompressedChunkSize, PULONG FinalCompressedSize, PVOID WorkSpace);
typedef NTSTATUS(WINAPI *XRtlGetCompressionWorkSpaceSize)(USHORT CompressionFormatAndEngine, PULONG CompressBufferWorkSpaceSize, PULONG CompressFragmentWorkSpaceSize);

#define P2ALIGNUP(size, align) ((((size) / (align)) + 1) * (align))

LPVOID compressData(LPVOID img, size_t imgSize, DWORD &outSize)
{
	DWORD(WINAPI * fnRtlGetCompressionWorkSpaceSize)
	(USHORT, PULONG, PULONG) =
		(DWORD(WINAPI *)(USHORT, PULONG, PULONG))(
			GetProcAddress(LoadLibraryA("ntdll"), "RtlGetCompressionWorkSpaceSize"));

	DWORD(WINAPI * fnRtlCompressBuffer)
	(USHORT, PUCHAR, ULONG, PUCHAR, ULONG, ULONG, PULONG, PVOID) =
		(DWORD(WINAPI *)(USHORT, PUCHAR, ULONG, PUCHAR, ULONG, ULONG, PULONG, PVOID))(
			GetProcAddress(LoadLibraryA("ntdll"), "RtlCompressBuffer"));

	ULONG uCompressBufferWorkSpaceSize, uCompressFragmentWorkSpaceSize;
	if (fnRtlGetCompressionWorkSpaceSize(
			COMPRESSION_FORMAT_LZNT1,
			&uCompressBufferWorkSpaceSize,
			&uCompressFragmentWorkSpaceSize))
	{
		return 0;
	}

	PUCHAR pWorkSpace = new UCHAR[uCompressBufferWorkSpaceSize];
	UCHAR *out = new UCHAR[imgSize];
	memset(out, 0, imgSize);
	if (fnRtlCompressBuffer(
			COMPRESSION_FORMAT_LZNT1 | COMPRESSION_ENGINE_MAXIMUM,
			(PUCHAR)img,
			imgSize,
			out,
			imgSize,
			4096,
			&outSize,
			pWorkSpace))
		return 0;
	else
		return out;
}

bool dumpMappedImgBin(char *buf, BYTE *&mappedImg, size_t *imgSize)
{
	PIMAGE_SECTION_HEADER stectionArr = getSectionArr(buf);
	*imgSize = getNtHdr(buf)->OptionalHeader.SizeOfImage - stectionArr[0].VirtualAddress; // start with the first section data.
	mappedImg = new BYTE[*imgSize];
	memset(mappedImg, 0, *imgSize);

	for (size_t i = 0; i < getNtHdr(buf)->FileHeader.NumberOfSections; i++)
		memcpy(mappedImg + stectionArr[i].VirtualAddress - stectionArr[0].VirtualAddress, buf + stectionArr[i].PointerToRawData, stectionArr[i].SizeOfRawData);
	return true;
}

void linkBin(char *buf, char *stub, size_t stubSize, BYTE *compressedImgData, size_t compressedDataSize)
{
	WORD sizeOfOptionalHeader = getNtHdr(buf)->FileHeader.SizeOfOptionalHeader;
	DWORD sectionAlignment = getNtHdr(buf)->OptionalHeader.SectionAlignment;
	DWORD fileAlignment = getNtHdr(buf)->OptionalHeader.FileAlignment;

	// deal with the first section
	PIMAGE_SECTION_HEADER sectionArr = getSectionArr(buf);
	// -------------------------------- Mapping RWX memory section --------
	memcpy(&(sectionArr[0].Name), "text_rwx", 8);
	sectionArr[0].Misc.VirtualSize = (getNtHdr(buf)->OptionalHeader.SizeOfImage - getNtHdr(buf)->OptionalHeader.SizeOfHeaders);
	sectionArr[0].VirtualAddress = 0x1000;
	sectionArr[0].SizeOfRawData = 0;
	sectionArr[0].PointerToRawData = 0;
	sectionArr[0].Characteristics = IMAGE_SCN_MEM_EXECUTE | IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_WRITE;

	//---------------------------------- Stub -----------------------------
	memcpy(&(sectionArr[1].Name), "stub", 8);
	sectionArr[1].Misc.VirtualSize = stubSize;
	sectionArr[1].VirtualAddress = P2ALIGNUP((sectionArr[0].VirtualAddress + sectionArr[0].Misc.VirtualSize), sectionAlignment);
	sectionArr[1].SizeOfRawData = P2ALIGNUP(stubSize, fileAlignment);
	sectionArr[1].PointerToRawData = getNtHdr(buf)->OptionalHeader.SizeOfHeaders;
	sectionArr[1].Characteristics = IMAGE_SCN_MEM_EXECUTE | IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_WRITE;
	memcpy((PVOID)((UINT_PTR)buf + sectionArr[1].PointerToRawData), stub, stubSize);

	//---------------------------------- Compressed Data Section ----------
	memcpy(&(sectionArr[2].Name), "data", 8);
	sectionArr[2].Misc.VirtualSize = compressedDataSize;
	sectionArr[2].VirtualAddress = P2ALIGNUP(sectionArr[1].VirtualAddress + sectionArr[1].Misc.VirtualSize, sectionAlignment);
	sectionArr[2].SizeOfRawData = P2ALIGNUP(compressedDataSize, fileAlignment);
	sectionArr[2].PointerToRawData = sectionArr[1].PointerToRawData + sectionArr[1].SizeOfRawData;
	sectionArr[2].Characteristics = IMAGE_SCN_MEM_READ;
	memcpy((PVOID)((UINT_PTR)buf + sectionArr[2].PointerToRawData), compressedImgData, compressedDataSize);

	//---------------------------------- Packing Record -----------------------------
	memcpy(&(sectionArr[3].Name), "ntHdr", 8);
	auto len_ntTable = sizeof(IMAGE_NT_HEADERS32);
	sectionArr[3].Misc.VirtualSize = len_ntTable;
	sectionArr[3].VirtualAddress = P2ALIGNUP(sectionArr[2].VirtualAddress + sectionArr[2].Misc.VirtualSize, sectionAlignment);
	sectionArr[3].SizeOfRawData = P2ALIGNUP(len_ntTable, fileAlignment);
	sectionArr[3].PointerToRawData = sectionArr[2].PointerToRawData + sectionArr[2].SizeOfRawData;
	sectionArr[3].Characteristics = IMAGE_SCN_MEM_READ;
	memcpy((PVOID)((UINT_PTR)buf + sectionArr[3].PointerToRawData), getNtHdr(buf), len_ntTable);
	memset(getNtHdr(buf)->OptionalHeader.DataDirectory, 0, sizeof(IMAGE_DATA_DIRECTORY) * 15);
	getNtHdr(buf)->OptionalHeader.AddressOfEntryPoint = sectionArr[1].VirtualAddress;

	//------------------------- Fix SizeOfImage for Application Loader -------------------------
	getNtHdr(buf)->OptionalHeader.DllCharacteristics &= ~(IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE);
	getNtHdr(buf)->FileHeader.NumberOfSections = 4;
	getNtHdr(buf)->OptionalHeader.SizeOfImage =
		sectionArr[getNtHdr(buf)->FileHeader.NumberOfSections - 1].VirtualAddress +
		sectionArr[getNtHdr(buf)->FileHeader.NumberOfSections - 1].Misc.VirtualSize;
}

int main(int argc, char **argv)
{
	printf(logo);
	if (argc != 2)
	{
		printf("[!] usage: %s [TARGET_PE_FILE]",
			   strrchr(argv[0], '\\') ? strrchr(argv[0], '\\') + 1 : argv[0]);
		return 0;
	}
	// --------------------------------------------------------------------
	char *in_peFilePath = argv[1];
	char *outputFileName = new char[strlen(in_peFilePath) + 0xff];
	strcpy(outputFileName, in_peFilePath);
	strcpy(strrchr(outputFileName, '.'), "_protected.exe\x00");
	printf("[+] detect input PE file: %s\n", in_peFilePath);
	printf("    - output PE file at %s\n", outputFileName);
	char *buf;
	DWORD filesize;
	if (!readBinFile(in_peFilePath, &buf, filesize))
	{
		puts("    - fail to read input PE binary.");
		return 0;
	}
	else
		puts("    - read PE file... done.");
	puts("");
	// --------------------------------------------------------------------
	printf("[+] dump dynamic image.\n");
	BYTE *mappedImg = NULL;
	size_t imgSize = -1;
	if (dumpMappedImgBin(buf, mappedImg, &imgSize))
		puts("    - file mapping emulating... done.");
	puts("");
	// --------------------------------------------------------------------
	printf("[+] dump dynamic image.\n");
	DWORD zipedSize = -1;
	BYTE *compressImg = (BYTE *)compressData(mappedImg, imgSize, zipedSize);
	if (compressImg)
		puts("    - compressing image... done.");
	else
		puts("    - fail to do compress.");
	puts("");
	// --------------------------------------------------------------------
	printf("[+] linking & repack whole PE file. \n");

	char *x86_Stub;
	DWORD len_x86Stub;
	if (!readBinFile("stub.bin", &x86_Stub, len_x86Stub))
	{
		puts("[x] stub binary not found. haven't compile it yet?");
		return 0;
	}

	size_t newSectionSize = P2ALIGNUP(len_x86Stub, getNtHdr(buf)->OptionalHeader.FileAlignment);
	char *newOutBuf = new char[filesize + newSectionSize];
	memcpy(newOutBuf, buf, getNtHdr(buf)->OptionalHeader.SizeOfHeaders);
	linkBin(newOutBuf, x86_Stub, len_x86Stub, compressImg, zipedSize);

	size_t finallySize = getSectionArr(newOutBuf)[getNtHdr(newOutBuf)->FileHeader.NumberOfSections - 1].PointerToRawData +
						 getSectionArr(newOutBuf)[getNtHdr(newOutBuf)->FileHeader.NumberOfSections - 1].SizeOfRawData;
	puts("");

	// --------------------------------------------------------------------
	printf("[+] generating finally packed PE file.\n");
	fwrite(newOutBuf, sizeof(char), finallySize, fopen(outputFileName, "wb"));
	printf("[+] output PE file saved as %s\n", outputFileName);
	puts("[+] done.");
}
