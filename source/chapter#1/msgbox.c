/**
 * msgbox.c
 * $ gcc -static msgbox.c -o msgbox.exe 
 * Windows APT Warfare:
 * by aaaddress1@chroot.org
 */
#include <stdio.h>
#include <windows.h>
int main(void) {

	MessageBoxA(0, "hi there", "info", 0);
	getchar();

	return 0;
}
