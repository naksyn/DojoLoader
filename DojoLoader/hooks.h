#pragma once

void WINAPI SleepHookMemoryBouncing(DWORD dwMilliseconds);
void WINAPI SleepHookMemoryHopping(DWORD dwMilliseconds);
void WINAPI SleepHookRWRX(DWORD dwMilliseconds);
BOOL SetRWonSection(LPVOID lpBase, DWORD size);
BOOL SetRXonSection(LPVOID lpBase, DWORD size);

BOOL check_hook(const char* functionName);