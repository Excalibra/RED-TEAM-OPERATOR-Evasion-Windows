#define _WIN32_DCOM
#include <comdef.h>
#include <Wbemidl.h>

#pragma comment(lib, "wbemuuid.lib")

//int WINAPI WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, LPSTR lpCmdLine, int nCmdShow) {
int main(int argc, char ** argv) {
    HRESULT hres;

    // initialize COM library
    hres =  CoInitializeEx(0, COINIT_MULTITHREADED); 
    if (FAILED(hres)) {
		printf("Failed to initialize COM library. Error code = 0x%x\n", hres);
        return 1;
    }

    // set COM security levels
    hres =  CoInitializeSecurity(
								NULL, 
								-1,                          // COM negotiates service
								NULL,                        // Authentication services
								NULL,                        // Reserved
								RPC_C_AUTHN_LEVEL_DEFAULT,   // Default authentication 
								RPC_C_IMP_LEVEL_IMPERSONATE, // Default Impersonation
								NULL,                        // Authentication info
								EOAC_NONE,                   // Additional capabilities 
								NULL                         // Reserved
								);

    if (FAILED(hres)) {
		printf("Failed to initialize security. Error code = 0x%x\n", hres);
        CoUninitialize();
        return 1;
    }

    // get the initial locator to WMI
    IWbemLocator * pLoc = NULL;
    hres = CoCreateInstance(
							CLSID_WbemLocator,
							0, 
							CLSCTX_INPROC_SERVER, 
							IID_IWbemLocator, (LPVOID *) &pLoc);
 
    if (FAILED(hres)) {
		printf("Failed to create IWbemLocator object. Error code = 0x%x\n", hres);
        CoUninitialize();
        return 1;
    }

    // connect to the local root\cimv2 namespace
    // and obtain pointer pSvc to make IWbemServices calls.
    IWbemServices * pSvc = NULL;
    hres = pLoc->ConnectServer(
							_bstr_t(L"ROOT\\StandardCIMV2"), 
							NULL,
							NULL, 
							0, 
							NULL, 
							0, 
							0, 
							&pSvc
							);
							
    if (FAILED(hres)) {
		printf("Could not connect. Error code = 0x%x\n", hres);
        pLoc->Release();
        CoUninitialize();
        return 1;
    }

	printf("Connected to ROOT\\StandardCIMV2 namespace\n");

    // set security levels for the proxy
    hres = CoSetProxyBlanket(
							pSvc,                        // Indicates the proxy to set
							RPC_C_AUTHN_WINNT,           // RPC_C_AUTHN_xxx 
							RPC_C_AUTHZ_NONE,            // RPC_C_AUTHZ_xxx 
							NULL,                        // Server principal name 
							RPC_C_AUTHN_LEVEL_CALL,      // RPC_C_AUTHN_LEVEL_xxx 
							RPC_C_IMP_LEVEL_IMPERSONATE, // RPC_C_IMP_LEVEL_xxx
							NULL,                        // client identity
							EOAC_NONE                    // proxy capabilities 
							);

    if (FAILED(hres)) {
		printf("Could not set proxy blanket. Error code = 0x%x\n", hres);
        pSvc->Release();
        pLoc->Release();
        CoUninitialize();
        return 1;
    }

	// class to target: MSFT_NetTCPConnection
    BSTR ClassName = SysAllocString(L"MSFT_NetTCPConnection");

    // create an Enumerator object to list of instances of MSFT_NetTCPConnection
    IEnumWbemClassObject * pEnumerator = NULL;
	
	hres = pSvc->CreateInstanceEnum(ClassName,
								WBEM_FLAG_FORWARD_ONLY | WBEM_FLAG_RETURN_IMMEDIATELY, 
								NULL,
								&pEnumerator);

    if (FAILED(hres)) {
		printf("Query for connections failed. Error code = 0x%x\n", hres);
        pSvc->Release();
        pLoc->Release();     
        CoUninitialize();
        return 1;               
    }
    else { 
        IWbemClassObject * pclsObj;
        ULONG uReturn = 0;
   
		printf("+=======+=================+===========+=================+============+\n");
		printf("|  PID  |  LocalAddress   | LocalPort |  RemoteAddress  | RemotePort |\n");
		printf("+-------+-----------------+-----------+-----------------+------------+\n");
        
		// list the connections
		while (pEnumerator) {
            hres = pEnumerator->Next(WBEM_INFINITE, 1, &pclsObj, &uReturn);

            if(uReturn == 0)
                break;

			// data we want to print
			VARIANT vtPropOwningProc;
            VARIANT vtPropLocAddr;
			VARIANT vtPropLocPort;
			VARIANT vtPropRemAddr;
			VARIANT vtPropRemPort;

            // Get the network-related values from an object
			hres = pclsObj->Get(L"OwningProcess", 0, &vtPropOwningProc, 0, 0);
			hres = pclsObj->Get(L"LocalAddress", 0, &vtPropLocAddr, 0, 0);
			hres = pclsObj->Get(L"LocalPort", 0, &vtPropLocPort, 0, 0);
			hres = pclsObj->Get(L"RemoteAddress", 0, &vtPropRemAddr, 0, 0);
			hres = pclsObj->Get(L"RemotePort", 0, &vtPropRemPort, 0, 0);
			printf("|%6d | ", vtPropOwningProc.ulVal);
			printf("%15S | ", vtPropLocAddr.bstrVal);
			printf("%9d | ", vtPropLocPort.uintVal);
			printf("%15S | ", vtPropRemAddr.bstrVal);
			printf("%10d |\n", vtPropRemPort.uintVal);

			// clean up before we tear up the next object
			VariantClear(&vtPropOwningProc);
            VariantClear(&vtPropLocAddr);
			VariantClear(&vtPropLocPort);
			VariantClear(&vtPropRemAddr);
			VariantClear(&vtPropRemPort);
            pclsObj->Release();
            pclsObj = NULL;
        }
		printf("+=======+=================+===========+=================+============+\n");
		
    }

	// go home
    pLoc->Release();
    pSvc->Release();
    CoUninitialize();
    return 0;
}
