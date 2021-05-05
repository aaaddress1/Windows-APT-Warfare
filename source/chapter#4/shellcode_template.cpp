/**
 * Shellcode Template for ShellDev.py
 * Windows APT Warfare
 * by aaaddress1@chroot.org
 */
#include <shellDev>

void shellFunc shellEntry(void)
{
	PVOID addr;
	fetchAPI(msgBye, FatalAppExitA);
	msgBye(0, "30cm.tw");
}
