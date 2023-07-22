#pragma once
#include <windows.h>
#include <Winhttp.h>
#pragma comment(lib, "winhttp.lib")
#include <fstream>
vector<char>* httpRecv(PWSTR url) {
	vector<char>* binaryData = new vector<char>();
	WCHAR sz_hostName[MAX_PATH], sz_reqPath[MAX_PATH]; int port = 0;

	// parse url.
	if (swscanf(wcsstr(url, L"//") + 2, L"%[^:]:%d%s", sz_hostName, &port, sz_reqPath) == 3);
	else if (swscanf(wcsstr(url, L"//") + 2, L"%[^/]%s", sz_hostName, sz_reqPath) == 2)
		port = wcsstr(url, L"https") ? INTERNET_DEFAULT_HTTPS_PORT : INTERNET_DEFAULT_HTTP_PORT;
	else return binaryData;

	wprintf(L"[v] send request -> %s:%i [Path = %s]\n", sz_hostName, port, sz_reqPath);

	// launch a http request.
	HINTERNET  hSession = NULL, hConnect = NULL, hRequest = NULL;
	hSession = WinHttpOpen(L"WinHTTP Example/1.0", WINHTTP_ACCESS_TYPE_DEFAULT_PROXY, WINHTTP_NO_PROXY_NAME, WINHTTP_NO_PROXY_BYPASS, 0);
	hConnect = WinHttpConnect(hSession, sz_hostName, port, 0);
	hRequest = WinHttpOpenRequest(hConnect, L"GET", sz_reqPath, NULL, WINHTTP_NO_REFERER, NULL, NULL);
	if (!hRequest) return binaryData;

	if (!WinHttpSendRequest(hRequest, WINHTTP_NO_ADDITIONAL_HEADERS, 0, WINHTTP_NO_REQUEST_DATA, 0, 0, 0) or !WinHttpReceiveResponse(hRequest, NULL))
		return binaryData;
	
	// recv binary data.
	char byteCache[4096] = { 0 };
	for (DWORD dwRead(sizeof(byteCache)); dwRead == sizeof(byteCache); ) {
		if (!WinHttpReadData(hRequest, byteCache, sizeof(byteCache), &dwRead)) return binaryData;
		for (size_t x = 0; x < dwRead; x++) binaryData->push_back(byteCache[x]);
	}

	// clean up.
	if (hRequest) WinHttpCloseHandle(hRequest);
	if (hConnect) WinHttpCloseHandle(hConnect);
	if (hSession) WinHttpCloseHandle(hSession);

	wprintf(L"[v] recv payload [size = %i] done.\n", binaryData->size());
	return binaryData;
}
