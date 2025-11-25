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
jmp 00007FFC20A72B33        ; Jump to injected code
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
