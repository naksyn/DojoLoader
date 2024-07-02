#include <windows.h>
#include "structs.h"

#ifndef MEMLOADER_H
#define SIZE_ARRAY 32
#endif


//global variable offset
extern int offset;// 0x30000;



extern PVOID lpBaseArray[SIZE_ARRAY]; //save addresses that we wrote to, so that we can free
extern SIZE_T TSizeArray[SIZE_ARRAY]; //save sizes of the memory pages we allocated
extern int index; 


void FreeRawModule(PVOID pDllBytes);

//--------------------------------------------------------------------------------------------------------------//
// the following 2 functions, are made to add elements in the arrays we have
void AppendTSizeArray(SIZE_T Value);
void AppendlpBaseArray(PVOID Value);

BOOL LoadModuleInt(PMEM_MODULE pMemModule, LPVOID PEdata, BOOL CallEntryPoint);

HMEMMODULE LoadMod(LPVOID PEdata, BOOL CallEntryPoint, DWORD* pdwError);

// Tests the return value and jump to exit label if false.
#define IfFalseGoExitWithError(x, exp)                                                                                 \
  do {                                                                                                                 \
    if (!(br = (x)) && (exp))                                                                                          \
      goto _Exit;                                                                                                      \
  } while (0)

// Create a pointer value.
#define MakePointer(t, p, offset) ((t)((PBYTE)(p) + offset))

/// <returns>True if the data is valid PE format.</returns>
BOOL IsPEValid(PMEM_MODULE pMemModule, LPVOID PEdata);


// this function here is used to map all the sections
BOOL MapModule(PMEM_MODULE pMemModule, LPVOID PEdata);

// Relocates the module.
BOOL doRelocations(PMEM_MODULE pMemModule);

BOOL check_hook(const char* functionName);

BOOL ResolveImports(PMEM_MODULE pMemModule);
BOOL SetPermissions(PMEM_MODULE pMemModule);


// Processes TLS data
BOOL HandleTLS(PMEM_MODULE pMemModule);


// Calls the module entry.
BOOL CallModuleEntry(PMEM_MODULE pMemModule, DWORD dwReason);

//--------------------------------------------------------------------------------------------------------------//
// Unmaps all the sections.
VOID UnmapModule(PMEM_MODULE pMemModule);
// Gets the CRC32 of the data.
UINT32 GetCRC32(UINT32 uInit, void* pBuf, UINT32 nBufSize);
