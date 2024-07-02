#include <windows.h>
#include <wininet.h>
#include "structs.h"
#pragma comment(lib, "wininet.lib")
#pragma once

char* DownloadFile(const char* url, DWORD* size);
void XORWithKey(char* data, DWORD size, const char* key);
BOOL ReadDllFile(char* FileInput);
