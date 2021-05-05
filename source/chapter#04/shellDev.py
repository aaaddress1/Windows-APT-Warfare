title = \
"""
      _          _ _ _____
     | |        | | |  __ \\
  ___| |__   ___| | | |  | | _____   __
 / __| '_ \ / _ \ | | |  | |/ _ \ \ / /
 \__ \ | | |  __/ | | |__| |  __/\ V /
 |___/_| |_|\___|_|_|_____/ \___| \_/

v1.2 by aaaddress1@chroot.org
"""

# -------------------- Injection ------------------- #
from ctypes import *
import ctypes
import ctypes.wintypes

from ctypes.wintypes import BOOL
from ctypes.wintypes import DWORD
from ctypes.wintypes import HANDLE
from ctypes.wintypes import LPVOID
from ctypes.wintypes import LPCVOID
import win32process
LPCSTR = LPCTSTR = ctypes.c_char_p
LPDWORD = PDWORD = ctypes.POINTER(DWORD)
class _SECURITY_ATTRIBUTES(ctypes.Structure):
    _fields_ = [('nLength', DWORD),
                ('lpSecurityDescriptor', LPVOID),
                ('bInheritHandle', BOOL),]
SECURITY_ATTRIBUTES = _SECURITY_ATTRIBUTES
LPSECURITY_ATTRIBUTES = ctypes.POINTER(_SECURITY_ATTRIBUTES)
LPTHREAD_START_ROUTINE = LPVOID


def jitInject(path, shellcode):
	info = win32process.CreateProcess(None, path, None, None, False, 0x04, None, None, win32process.STARTUPINFO())  
	page_rwx_value = 0x40
	process_all = 0x1F0FFF
	memcommit = 0x00001000

	shellcode_length = len(shellcode)
	process_handle = info[0].handle # phandle

	VirtualAllocEx = windll.kernel32.VirtualAllocEx
	VirtualAllocEx.restype = LPVOID
	VirtualAllocEx.argtypes = (HANDLE, LPVOID, DWORD, DWORD, DWORD)

	WriteProcessMemory = ctypes.windll.kernel32.WriteProcessMemory
	WriteProcessMemory.restype = BOOL
	WriteProcessMemory.argtypes = (HANDLE, LPVOID, LPCVOID, DWORD, DWORD)

	CreateRemoteThread = ctypes.windll.kernel32.CreateRemoteThread
	CreateRemoteThread.restype = HANDLE
	CreateRemoteThread.argtypes = (HANDLE, LPSECURITY_ATTRIBUTES, DWORD, LPTHREAD_START_ROUTINE, LPVOID, DWORD, DWORD)

	lpBuffer = VirtualAllocEx(process_handle, 0, shellcode_length, memcommit, page_rwx_value)
	print(hex(lpBuffer))
	WriteProcessMemory(process_handle, lpBuffer, shellcode, shellcode_length, 0)
	CreateRemoteThread(process_handle, None, 0, lpBuffer, 0, 0, 0)
	print('JIT Injection, done.')
# -------------------------------------------------- #


import subprocess
import re
import os
import sys
from optparse import OptionParser
import hashlib

shellDevHpp = \
"""
#include <Windows.h>
#include <stdio.h>
#include <stdint.h>

typedef struct _PEB_LDR_DATA
{
	ULONG Length;
	UCHAR Initialized;
	PVOID SsHandle;
	LIST_ENTRY InLoadOrderModuleList;
	LIST_ENTRY InMemoryOrderModuleList;
	LIST_ENTRY InInitializationOrderModuleList;
	PVOID EntryInProgress;
} PEB_LDR_DATA, *PPEB_LDR_DATA;
typedef struct _UNICODE_STRING32
{
	USHORT Length;
	USHORT MaximumLength;
	PWSTR Buffer;
} UNICODE_STRING32, *PUNICODE_STRING32;
typedef struct _PEB32
{
	UCHAR InheritedAddressSpace;
	UCHAR ReadImageFileExecOptions;
	UCHAR BeingDebugged;
	UCHAR BitField;
	ULONG Mutant;
	ULONG ImageBaseAddress;
	PPEB_LDR_DATA Ldr;
	ULONG ProcessParameters;
	ULONG SubSystemData;
	ULONG ProcessHeap;
	ULONG FastPebLock;
	ULONG AtlThunkSListPtr;
	ULONG IFEOKey;
	ULONG CrossProcessFlags;
	ULONG UserSharedInfoPtr;
	ULONG SystemReserved;
	ULONG AtlThunkSListPtr32;
	ULONG ApiSetMap;
} PEB32, *PPEB32;
typedef struct _PEB_LDR_DATA32
{
	ULONG Length;
	BOOLEAN Initialized;
	ULONG SsHandle;
	LIST_ENTRY32 InLoadOrderModuleList;
	LIST_ENTRY32 InMemoryOrderModuleList;
	LIST_ENTRY32 InInitializationOrderModuleList;
	ULONG EntryInProgress;
} PEB_LDR_DATA32, *PPEB_LDR_DATA32;
typedef struct _LDR_DATA_TABLE_ENTRY32
{
	LIST_ENTRY32 InLoadOrderLinks;
	LIST_ENTRY32 InMemoryOrderModuleList;
	LIST_ENTRY32 InInitializationOrderModuleList;
	ULONG DllBase;
	ULONG EntryPoint;
	ULONG SizeOfImage;
	UNICODE_STRING32 FullDllName;
	UNICODE_STRING32 BaseDllName;
	ULONG Flags;
	USHORT LoadCount;
	USHORT TlsIndex;
	union
	{
		LIST_ENTRY32 HashLinks;
		ULONG SectionPointer;
	};
	ULONG CheckSum;
	union
	{
		ULONG TimeDateStamp;
		ULONG LoadedImports;
	};
	ULONG EntryPointActivationContext;
	ULONG PatchInformation;
} LDR_DATA_TABLE_ENTRY32, *PLDR_DATA_TABLE_ENTRY32;
typedef struct _PROCESS_BASIC_INFORMATION64 {
	ULONG64 ExitStatus;
	ULONG64 PebBaseAddress;
	ULONG64 AffinityMask;
	ULONG64 BasePriority;
	ULONG64 UniqueProcessId;
	ULONG64 InheritedFromUniqueProcessId;
} PROCESS_BASIC_INFORMATION64, *PPROCESS_BASIC_INFORMATION64;
typedef struct _PEB64
{
	UCHAR InheritedAddressSpace;
	UCHAR ReadImageFileExecOptions;
	UCHAR BeingDebugged;
	UCHAR BitField;
	ULONG64 Mutant;
	ULONG64 ImageBaseAddress;
	PPEB_LDR_DATA Ldr;
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

# define FORCE_INLINE __attribute__((always_inline)) inline
# define NOINLINE __declspec(noinline)
# define shellFunc __attribute__((fastcall)) __attribute__((section("shell"))) NOINLINE

void shellFunc shellEntry(void);

template<class T> struct func {
	explicit func(FARPROC ptr) : _ptr(ptr) {}
	operator T() { return reinterpret_cast<T>(_ptr); }
	FARPROC _ptr;
};

uint32_t shellFunc modHash(wchar_t *modName) {
	uint32_t buf = 0;
	while (*(modName++)) {
		buf += (*modName | 0x20);
		buf = (buf << 24 | buf >> (sizeof(uint32_t) * 8 - 24)); /* rotl */
	}
	return buf;
}

uint32_t shellFunc modHash(char *modName) {
	uint32_t buf = 0;
	while (*(modName++)) {
		buf += (*modName | 0x20);
		buf = (buf << 24 | buf >> (sizeof(uint32_t) * 8 - 24)); /* rotl */
	}
	return buf;
}

PVOID shellFunc getModAddrByHash(uint32_t targetHash)
{
#ifdef _WIN64
	PPEB64 pPEB = (PPEB64)__readgsqword(0x60);
	PLIST_ENTRY header = &(pPEB->Ldr->InMemoryOrderModuleList);
	PLIST_ENTRY curr = header->Flink;
	for (; curr != header; curr = curr->Flink) {
		LDR_DATA_TABLE_ENTRY64 *data = CONTAINING_RECORD(curr, LDR_DATA_TABLE_ENTRY64, InMemoryOrderModuleList);
		if (modHash(data->BaseDllName.Buffer) == targetHash)
			return (PVOID)data->DllBase;
	}
#else
	PPEB32 pPEB = (PPEB32)__readfsdword(0x30);
	PLIST_ENTRY header = &(pPEB->Ldr->InMemoryOrderModuleList);
	PLIST_ENTRY curr = header->Flink;
	for (; curr != header; curr = curr->Flink) {
		LDR_DATA_TABLE_ENTRY32 *data = CONTAINING_RECORD(curr, LDR_DATA_TABLE_ENTRY32, InMemoryOrderModuleList);
		if (modHash(data->BaseDllName.Buffer) == targetHash)
			return (PVOID)data->DllBase;
	}
#endif
	return 0;
}

PVOID shellFunc getFuncAddrByHash(HMODULE module, uint32_t targetHash)
{
#if defined _WIN64
	PIMAGE_NT_HEADERS64 ntHeaders = (PIMAGE_NT_HEADERS64)((LPBYTE)module + ((PIMAGE_DOS_HEADER)module)->e_lfanew);
#else
	PIMAGE_NT_HEADERS32 ntHeaders = (PIMAGE_NT_HEADERS32)((LPBYTE)module + ((PIMAGE_DOS_HEADER)module)->e_lfanew);
#endif
	PIMAGE_DATA_DIRECTORY impDir = &ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
	if (impDir->VirtualAddress == 0) return (size_t)0;

	PIMAGE_EXPORT_DIRECTORY ied = (PIMAGE_EXPORT_DIRECTORY)((LPBYTE)module + impDir->VirtualAddress);
	if (ied->NumberOfNames == 0) return (size_t)0;

	for (DWORD i = 0; i < ied->NumberOfNames; i++)
	{
		LPDWORD curName = (LPDWORD)(((LPBYTE)module) + ied->AddressOfNames + i * sizeof(DWORD));
		if (curName && (modHash((LPSTR)((LPBYTE)module + *curName)) == targetHash))
		{
			LPWORD pw = (LPWORD)(((LPBYTE)module) + ied->AddressOfNameOrdinals + i * sizeof(WORD));
			curName = (LPDWORD)(((LPBYTE)module) + ied->AddressOfFunctions + (*pw) * sizeof(DWORD));
			return (PVOID)((size_t)module + *curName);
		}
	}
	return (size_t)0;
}

PVOID blindFindFunc(uint32_t funcNameHash)
{
	PVOID retAddr = (size_t)0;
#ifdef _WIN64
	PPEB64 pPEB = (PPEB64)__readgsqword(0x60);
	PLIST_ENTRY header = &(pPEB->Ldr->InMemoryOrderModuleList);
	PLIST_ENTRY curr = header->Flink;
	for (; curr != header; curr = curr->Flink) {
		LDR_DATA_TABLE_ENTRY64 *data = CONTAINING_RECORD(curr, LDR_DATA_TABLE_ENTRY64, InMemoryOrderModuleList);
		retAddr = getFuncAddrByHash((HMODULE)data->DllBase, funcNameHash);
		if (retAddr) return retAddr;
	}
#else
	PPEB32 pPEB = (PPEB32)__readfsdword(0x30);
	PLIST_ENTRY header = &(pPEB->Ldr->InMemoryOrderModuleList);
	PLIST_ENTRY curr = header->Flink;

	for (; curr != header; curr = curr->Flink) {
		LDR_DATA_TABLE_ENTRY32 *data = CONTAINING_RECORD(curr, LDR_DATA_TABLE_ENTRY32, InMemoryOrderModuleList);
		retAddr = getFuncAddrByHash((HMODULE)data->DllBase, funcNameHash);
		if (retAddr) return retAddr;
	}
#endif
	return (size_t)0;
}

#define getModAddr(libraryName) (HMODULE)( \
	getModAddrByHash(modHash(libraryName)) \
	)

#define getFuncAddr(libraryAddress, functionName) (PVOID)( \
	getFuncAddrByHash(libraryAddress, modHash(functionName)) \
	)
"""

def compileCtoAsmFile(cPath, asmPath):
	global mingwPath
	subprocess.call([
		os.path.join(mingwPath, 'gcc'),
		'-fno-asynchronous-unwind-tables',
		'-s',
		'-O3',
		'-ffunction-sections',
		'-S',
		'-Wa,-R',
		'-Wa,-mintel',
		'-falign-functions=1',
		'-c', cPath,
		'-o', asmPath
	], cwd=mingwPath)

def jmpShellCodeEntry(inAsmPath, outAsmPath):
	with open(inAsmPath, 'r') as r:
		src = r.read()
		# src = src.replace('.rdata', 'shell')
		if src.count(".rdata") > 0:
			print '[!] Detect global variables !! It\'dangerous !! Take Care!!'

		funcNameArr = re.findall(r'.globl[\t\x20]+(.+)', src, re.IGNORECASE)
		entryFunc = ''
		for eachFunc in funcNameArr:
			if 'shellEntry' in eachFunc:
				entryFunc = eachFunc

		with open(outAsmPath, 'w') as w:
			w.write('.section shell,"x"\r\njmp %s\r\nnop\r\n' % entryFunc + src)

def genObjAsmBinary(inAsmPath, outObjectFilePath, outAsmRawBinPath):
	global mingwPath
	subprocess.call([
		os.path.join(mingwPath, 'as'),
		'-c', inAsmPath,
		'-o', outObjectFilePath
	], cwd=mingwPath)
	subprocess.call([
		os.path.join(mingwPath, 'objcopy'),
		'-O', 'binary',
		outObjectFilePath,
		'-j', 'shell',
		outAsmRawBinPath
	], cwd=mingwPath)

def arrayifyBinaryRawFile(asmRawBinPath):
	with open(asmRawBinPath, 'rb') as binary_file:
		data =binary_file.read()
		dataHexArr = ', '.join(['0x%02X' % ord(i) for i in data])
		dataHexArr = re.sub('(' + '0x\w\w, '*12 +')', r'\1\n', dataHexArr)
		retn = 'unsigned char shellcode[] = {\n%s };\r\n' % dataHexArr
		retn += 'unsigned int shellcode_size = %i;\n' % len(data)
		return retn

def genShellcode(cppPath, clearAfterRun, jitInj = None):
	dir = os.getcwd()

	if len(os.path.dirname(cppPath)) == 0:
		cppPath = os.path.join(dir, cppPath)
		if not os.path.exists(cppPath):
			print('shellDev script not found at %s\n' % cppPath)
			sys.exit(1)

	print('[v] shellDev script at %s' % cppPath)
	preScriptPath = os.path.splitext(cppPath)[0]
	postScriptPath = os.path.splitext(cppPath)[1]

	cpp = preScriptPath + postScriptPath
	tmpcpp = preScriptPath + '_tmp' + postScriptPath
	asm = preScriptPath + 's'
	shellAsm = preScriptPath + '_shell.s'
	obj = preScriptPath + '.o'
	binraw = preScriptPath + '.bin'
	shelltxtOut = preScriptPath + '_shellcode.txt'
	with open(cpp, 'r') as i:
		script = i.read()
		#script = re.sub(r'\x22([^\x22]+)\x22', '')
		tmpscript = ''
		for line in script.splitlines():

			additionData = ''
			if 'fetchAPI' in line:
				m = re.compile(r'.*fetchAPI\([\x20]*([^,)]+)[\x20]*,[\x20]*([^\)]+)[\x20]*\)').match(line)
				replaceData = '''
char str_%(definedFuncName)s[] = "%(WinApiName)s";
func<decltype(&%(WinApiName)s)> %(definedFuncName)s( (FARPROC) blindFindFunc( modHash(str_%(definedFuncName)s) ) );
''' % { 'definedFuncName' : m.group(1).replace('\x20', ''), 'WinApiName' : m.group(2).replace('\x20', '')}
				print '[+] Detect fetchAPI() from %s -> %s' % ( m.group(2).replace('\x20', ''), m.group(1).replace('\x20', ''))
				line = line.replace(m.group(0), replaceData)

			for argStr in re.findall(r'[(\x20,]+(\x22[^\x22]+\x22)[\x20,)]', line):
				argStrNewName = 'str_' + hashlib.md5(argStr).hexdigest();
				additionData += 'char %s[] = %s;\n' % (argStrNewName, argStr);
				line = line.replace(argStr, argStrNewName);
			tmpscript += additionData + line + '\n'

		tmpscript = tmpscript.replace('#include <shellDev>', shellDevHpp)
		with open(tmpcpp, 'w') as w: w.write(tmpscript)

	compileCtoAsmFile(tmpcpp, asm)
	jmpShellCodeEntry(asm, shellAsm)
	genObjAsmBinary(shellAsm, obj, binraw)

	if   jitInj == 'x86':
		print('[+] jit mode: 32bit')
		with open(binraw, 'rb') as binary_file:
			data = binary_file.read()
			jitInject('C:\\Windows\\SysWoW64\\notepad.exe', data)
	elif jitInj == 'x64':
		print('[+] jit mode: 64bit')
		with open(binraw, 'rb') as binary_file:
			data = binary_file.read()
			jitInject('C:\\Windows\\System32\\notepad.exe', data)
	else:
		with open(shelltxtOut, 'w') as w:
			w.write(arrayifyBinaryRawFile(binraw))
			print('shellcode saved at %s' % shelltxtOut)

	if clearAfterRun:
		os.remove(asm)
		os.remove(shellAsm)
		os.remove(obj)
		os.remove(tmpcpp)
		os.remove(binraw)

def chkExeExist(name, path):
	if os.path.exists(path):
		print '\t[v] %s exists!' % name
	else:
		print '\t[x] %s not found at %s' % (name, path)
		sys.exit(1)

def chkMinGwToolkit(usrInputMinGWPath):
	global mingwPath
	mingwPath = usrInputMinGWPath
	if not 'bin' in mingwPath:
		mingwPath = os.path.join(mingwPath, 'bin')
		if os.path.exists(mingwPath):
			print '[v] check mingw tool path: %s ' % mingwPath
		else:
			print '[x] sorry, mingw toolkit not found in %s' % mingwPath
	chkExeExist('gcc', os.path.join(mingwPath, 'gcc.exe'))
	chkExeExist('as', os.path.join(mingwPath, 'as.exe'))
	chkExeExist('objcopy', os.path.join(mingwPath, 'objcopy.exe'))
	print('')

if __name__ == "__main__":
	print(title)
	parser = OptionParser()
	parser.add_option("-s", "--src", dest="source",
	      help="shelldev c/c++ script path.", metavar="PATH")
	parser.add_option("-m", "--mgw", dest="mingwPath",
	      help="set mingw path, mingw path you select determine payload is 32bit or 64bit.", metavar="PATH")
	parser.add_option("--noclear",
	      action="store_true", dest="dontclear", default=False,
	      help="don't clear junk file after generate shellcode.")

	parser.add_option("--jit32",
	      action="store_true", dest="jit32", default=False,
	      help="Just In Time Compile and Run Shellcode (as x86 Shellcode & Inject to Notepad for test, require run as admin.)")

	parser.add_option("--jit64",
	      action="store_true", dest="jit64", default=False,
	      help="Just In Time Compile and Run Shellcode (as x64 Shellcode & Inject to Notepad for test, require run as admin.)")

	(options, args) = parser.parse_args()
	if options.source is None or options.mingwPath is None:
		parser.print_help()
	else:
		jitArch = None
		if options.jit32: jitArch = 'x86'
		if options.jit64: jitArch = 'x64'
		chkMinGwToolkit(options.mingwPath)
		genShellcode(options.source, not options.dontclear, jitArch)
