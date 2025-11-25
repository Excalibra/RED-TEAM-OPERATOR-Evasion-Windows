#include <winsock2.h>
#include <ws2tcpip.h>
#include <iphlpapi.h>
#include <stdio.h>

#pragma comment(lib, "iphlpapi.lib")
#pragma comment(lib, "ws2_32.lib")

#define IPCONV(a,b,c,d) ((a) | ((b)&0xff)<<8 | ((c)&0xff)<<16 | ((d)&0xff)<<24)

int main(int argc, char ** argv) {

	DWORD dwStatus = 0;

	PMIB_IPFORWARDROW pRow = (PMIB_IPFORWARDROW) malloc(sizeof (MIB_IPFORWARDROW));
	
	// DESTINATION ADDRESS
	pRow->dwForwardDest = (DWORD) IPCONV(8,8,8,8);		//0x08080808;	// 8.8.8.8    		<- Google DNS
	//pRow->dwForwardDest = (DWORD) IPCONV(52,0,0,0);	//0x00000034;	// 52.0.0.0
	//pRow->dwForwardDest = (DWORD) IPCONV(54,0,0,0);	//0x00000036;	// 54.0.0.0
	//pRow->dwForwardDest = (DWORD) IPCONV(18,0,0,0);	//0x00000012;	// 18.0.0.0
	//pRow->dwForwardDest = (DWORD) IPCONV(3,0,0,0);	//0x00000003;	// 3.0.0.0

	// DESTINATION MASK
	pRow->dwForwardMask = 0xFFFFFFFF;					// 255.255.255.255		<- unicast
	//pRow->dwForwardMask = 0x00ffffff;					// 255.255.255.0		<- /24
	//pRow->dwForwardMask = 0x0000ffff;					// 255.255.0.0			<- /16
	//pRow->dwForwardMask = 0x000000ff;					// 255.0.0.0			<- /8
	
	// NEXT HOP
	pRow->dwForwardNextHop = (DWORD) IPCONV(10,2,2,20);	//0x1402020A;	// 10.2.2.20  		<- some bogus host
	
	// IFACE INDEX: 1 == loopback
	pRow->dwForwardIfIndex = 1;
	pRow->dwForwardProto = MIB_IPPROTO_NETMGMT;
	
	// throw it into routing table
	dwStatus = CreateIpForwardEntry(pRow);

    if (dwStatus == NO_ERROR)
        printf("New route successfully injected\n");
    else if (dwStatus == ERROR_INVALID_PARAMETER)
        printf("Invalid parameter.\n");
    else
        printf("Error: %d\n", dwStatus);

	return 0;
}
