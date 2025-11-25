#include <windows.h>
#include <stdio.h>
#include <fltuser.h>

#pragma comment( lib, "FltLib.lib" )

// extract MINIFILTER information
int printMiniFilterData(FILTER_AGGREGATE_STANDARD_INFORMATION * lpFilterInfo) {

	FILTER_AGGREGATE_STANDARD_INFORMATION * fltInfo = NULL;
	char * fltName, * fltAlt;
	
	fltInfo = (FILTER_AGGREGATE_STANDARD_INFORMATION *) lpFilterInfo;

	// convert Filter name
	int fltName_size = fltInfo->Type.MiniFilter.FilterNameLength;
	LONGLONG src = ((LONGLONG) lpFilterInfo) + fltInfo->Type.MiniFilter.FilterNameBufferOffset;
	fltName = (char *) malloc(fltName_size + 2);
	memset(fltName, 0, fltName_size + 2);
	memcpy(fltName, (void *) src, fltName_size);
	
	// convert Filter altitude
	int fltAlt_size = fltInfo->Type.MiniFilter.FilterAltitudeLength;
	src = ((LONGLONG) lpFilterInfo) + fltInfo->Type.MiniFilter.FilterAltitudeBufferOffset;
	fltAlt = (char *) malloc(fltAlt_size + 2);
	memset(fltAlt, 0, fltAlt_size + 2);
	memcpy(fltAlt, (void *) src, fltAlt_size);	

	// print only data about minifilters
	if (fltInfo->Flags == FLTFL_ASI_IS_MINIFILTER) {
		wprintf(L"Next: %3d | Frame ID: %3d | No. of Instances: %3d | Name: %15s | Altitude: %15s\n",
					fltInfo->NextEntryOffset,
					fltInfo->Type.MiniFilter.FrameID,
					fltInfo->Type.MiniFilter.NumberOfInstances,
					fltName, fltAlt);
	}
	
	free(fltName);
	free(fltAlt);	
	
	return 0;
}

int main(int argc, char * argv[])
{
	HRESULT res;
	DWORD dwBytesReturned;
	HANDLE hFilterFind;
	DWORD dwFilterInfoSize = 1024;
	LPVOID lpFilterInfo = HeapAlloc(GetProcessHeap(), NULL, dwFilterInfoSize);

	res = FilterFindFirst(FilterAggregateStandardInformation, lpFilterInfo, dwFilterInfoSize, &dwBytesReturned, &hFilterFind);
	if (res == HRESULT_FROM_WIN32(ERROR_NO_MORE_ITEMS)) {
		printf("No data found!\n");
		return 0;
	}
	if (res != S_OK) {
		printf("Error! code = 0x%x\n", GetLastError());
		return -1;
	}
	printMiniFilterData((FILTER_AGGREGATE_STANDARD_INFORMATION *) lpFilterInfo);

	while(true) {
		// enumerate all minifilters
		res = FilterFindNext(hFilterFind, FilterAggregateStandardInformation, lpFilterInfo, dwFilterInfoSize, &dwBytesReturned);
		if (res == HRESULT_FROM_WIN32(ERROR_NO_MORE_ITEMS)) {
			break;
		}
		if (res != S_OK) {
			printf("Error! code = 0x%x\n", GetLastError());
			return -1;
		}
		// and print relevant information
		printMiniFilterData((FILTER_AGGREGATE_STANDARD_INFORMATION *) lpFilterInfo);		
	}

	HeapFree(GetProcessHeap(), NULL, lpFilterInfo);

    return 0;
}


