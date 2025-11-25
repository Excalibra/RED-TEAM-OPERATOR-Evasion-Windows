# Essentials

<details>
<summary>01 - Modern Detection Technology </summary>

<img width="917" height="517" alt="image" src="https://github.com/user-attachments/assets/90169b7e-5fc0-44d1-99cf-70d4809f4dda" />

## Overview

Modern endpoint security solutions encompass a range of technologies designed to prevent, detect, and stop malicious software from persisting on disk or executing in system memory. This includes traditional antivirus solutions, Endpoint Protection Platforms (EPP), and Endpoint Detection and Response (EDR) systems, along with monitoring tools like Sysmon.

## Architecture of Detection Systems

### Dual-Component Design

Modern detection solutions typically employ a two-component architecture:

- **Userland Component**: Runs as a dedicated service monitoring application-level activities
- **Kernel Component**: Comprises one or more kernel drivers with privileged system access

### Kernel Monitoring Mechanisms

#### Kernel Callbacks
Security solutions register callback functions in system tables to monitor specific events:
- Process and thread creation/termination
- Image loading from disk into memory
- Registry access operations
- Memory object activities

When monitored events occur, the kernel executes registered callbacks, allowing security drivers to inspect and potentially block the activity.

#### Mini-Filter Drivers
Specialized drivers that monitor:
- Disk operations
- Network communications
- Other system-level actions

### Process Monitoring

#### Code Injection
EDR/EPP solutions inject monitoring DLLs into target processes to:
- Set API hooks on critical functions
- Log function call data (timing, calling module, arguments)
- Monitor behavior within the process context

Hooks are typically placed in ntdll.dll, as it represents the final user-space code before kernel transition.

### Event Tracing for Windows (ETW)
Leverages Windows' built-in logging and tracing capabilities to consume detailed system event data for analysis.

## Extended Detection and Response (XDR)

XDR solutions aggregate data from multiple sources:
- Endpoint security logs
- Network infrastructure (firewalls, routers, switches)
- Network flow data
- Proxy logs
- Other security components

This enables correlation-based detection across the entire network environment rather than isolated endpoint analysis.

## Evolution of Detection Technologies

<img width="935" height="525" alt="image" src="https://github.com/user-attachments/assets/42b928f3-a1b6-460a-a1d0-5e32e52de4ba" />

### Traditional Antivirus (AV)
- **Primary Focus**: Malware at rest (on disk) and at launch time
- **Techniques**: Static analysis, dynamic analysis, heuristic detection
- **Scope**: Primarily file-based detection

### Modern EDR Systems
- **Primary Focus**: Runtime anomaly detection and post-exploitation activities
- **Techniques**: Behavioral analysis, machine learning, deep learning
- **Scope**: Comprehensive system monitoring and response capabilities

### Convergence
The distinction between AV and EDR has blurred, with modern solutions incorporating capabilities from both approaches:
- AV solutions now detect runtime attacks (e.g., code injection)
- EDR systems include static analysis and heuristic detection
- Overlapping functionality with enhanced alerting and response in EDR

## Attack Surface Analysis

Red team operators can target multiple components of detection systems:

### Evasion Opportunities
- **Process Hooks**: Remove or bypass API hooks within processes
- **Signature Evasion**: Avoid static detection signatures
- **Analysis Evasion**: Bypass both static and dynamic analysis
- **Component Targeting**: Attack userland and kernel components
- **Event Monitoring**: Disrupt system event logging capabilities
- **Communication Channels**: Interrupt external logging and cloud communication

### Privilege Considerations
Effectiveness of evasion techniques depends on:
- Access level within the system (disk vs. memory)
- Process privileges and security context
- Specific security solution architecture

## Technical Implementation

This repository provides practical implementations targeting these detection system components, with techniques organized by required privilege level and attack vector.

---
</details>


<details>
<summary>02 - Evasion Development Rules </summary>

## Attacking assumptions:
- Data availability
- Data Consistency
- Data communication

by:
- Disabling agent
- disrupting comms
- Exploiting blind spots
- Blending in

Considerations:
- Offline VMs/infrastructure
- Software access (local vs cloud)
- Bypass development vs testing
- Performing attacks vs observable detections
- Privileged access vs non-admin
- Decision paths

## Core Principles

### Privilege-Based Strategy
Evasion capabilities are directly tied to privilege levels:

- **High Privileges (HiPrivs)**: Enable agent disablement, removal, or communication disruption
- **Low Privileges**: Require exploitation of security solution blind spots and benign process mimicry

### Fundamental Assumptions
Evasion techniques target core assumptions made by EPP/EDR solutions:
- **Data Availability**: Security solutions require access to system data
- **Data Consistency**: Reliance on predictable system behavior and data structures
- **Inter-Component Communication**: Dependence on internal and external communication channels

## Testing Methodology

### Environment Setup

#### Isolation Requirements
- **Primary Rule**: Maintain offline testing environments to prevent accidental data exfiltration to vendors
- **Exception**: Cloud security solution testing requires controlled online access
- **Communication Testing**: Specific scenarios may require network connectivity for disruption testing

#### Infrastructure Recommendations
- **Development VM**: For creating and compiling evasion techniques
- **Testing VM**: For executing and evaluating evasion effectiveness
- **Single-Machine Alternative**: Possible with proper security solution exceptions configured

### Security Product Selection

#### Bitdefender as AV Example
- **Industry Prevalence**: Engine used by multiple third-party AV products
- **Technique Coverage**: Implements typical AV/EDR methods including post-exploitation detection
- **Research Focus**: Not product-specific bypassing, but technique development and validation

#### Sysmon as EDR Simulator
- **Wide Adoption**: Popular free solution with extensive logging capabilities
- **Configurable Stealth**: Capable of hiding artifacts through renaming and configuration
- **Realistic Methods**: Employs techniques used by commercial EDR solutions

### Testing Process
1. **Execute Evasion Techniques**: Implement developed methods in controlled environment
2. **Observe Detection Impact**: Monitor security solution behavior and alerting
3. **Validate Effectiveness**: Confirm whether targeted detections are successfully bypassed
4. **Privilege Assessment**: Evaluate which methods are operationally feasible based on access level

## Operational Considerations

### EDR Hardening Challenges
Commercial EDR solutions implement additional protection measures:

- **Protected Processes (PPL)**: Restrict user-space access to security processes
- **Secure Installation**: Require tokens or passwords for agent deployment
- **Kernel-Level Protections**: Some defenses require kernel access to bypass

### Realism Limitations
Testing environment acknowledges certain gaps:

- **Machine Learning Components**: Cloud-based EDR ML detection not fully replicated
- **Advanced Protections**: Commercial EDR hardening features not present in test tools
- **Adaptability**: Techniques require adjustment for specific target environments

## Development Resources

### Reference Material
- **Jackson T's EDR Testing Series**: Comprehensive methodology for security solution evaluation
- **Vendor Documentation**: Product-specific capabilities and limitations
- **Community Research**: Ongoing evasion technique development and sharing

## Implementation Strategy

### Decision Framework
- **Privilege-Based Pathing**: Select techniques based on available access levels
- **Progressive Testing**: Build from basic to advanced evasion methods
- **Environment-Specific Adaptation**: Tailor techniques to target security stack

### Long-Term Development
- **Technique Generalization**: Focus on concepts applicable across multiple security products
- **Continuous Validation**: Regular testing against updated security solutions
- **Operational Integration**: Bridge between research and practical engagement use

---
</details>

<details>
<summary>03 - Binary Entropy in Malware Detection</summary>

## Overview

Binary entropy analysis is a fundamental technique used by security products to detect obfuscated or encrypted malware through statistical analysis of file randomness patterns.

## Understanding Entropy

*"A measurement of randomness"*

### Definition and Context
- **Entropy Measurement**: Quantifies the randomness or disorder within data
- **Multiple Disciplines**: Concepts from information theory (Shannon entropy), cryptography, and data analysis
- **Visual Analysis**: Structured data (PE headers, strings) vs. random data (encrypted payloads) show distinct patterns in hex editors

### Entropy in Security Detection
Security products employ entropy analysis to:
- Identify encrypted or compressed data sections
- Detect obfuscated code patterns
- Trigger heuristic alerts based on abnormal entropy profiles
- Complement traditional signature-based detection

## Development Environment Setup

[implant.cpp File](https://github.com/Excalibra/RED-TEAM-OPERATOR-Evasion-Windows/blob/main/Files%20Windows%20Evasion/01.Essentials/01.Entropy/implant.cpp)


## Development Environment Setup

### Required Tools
- **Compiler**: Microsoft Visual Studio Build Tools
- **Helium Hex Editor**: Helium for entropy analysis
- **Debugger**: x64dbg for runtime analysis
- **String Analysis**: Strings utility from Sysinternals

## Step-by-Step Implementation

### 1. Initial Code Compilation

#### Source Code Structure

```cpp
	unsigned char sKernel32[] = { 'k','e','r','n','e','l','3','2','.','d','l','l', 0x0 };
	unsigned char sVirtualProtect[] = { 'V','i','r','t','u','a','l','P','r','o','t','e','c','t', 0x0 };
```

#### Compilation Command

Open x64 Native Tools Command Prompt for VS

```batch
\01.Essentials\01.entropy>compile.bat

\01.Essentials\01.entropy>implant.exe
```

### 2. Functional Testing

#### Execution Verification
```batch
# Run the compiled binary
implant.exe
# Verify expected behavior (e.g., MessageBox appears)
```

<img width="532" height="271" alt="image" src="https://github.com/user-attachments/assets/a63b22a1-9b73-42f6-bcc4-829a4f7c91c2" />

### 3. String Obfuscation Analysis

#### Debugging Process
1. **Load in Debugger**:
   ```batch
   x64dbg implant.exe
   # or import file from x64dbg
   ```
<img width="1680" height="817" alt="image" src="https://github.com/user-attachments/assets/7fc5b2fc-6d32-4d94-bfbd-eb9a505a70fb" />

2. **Set Breakpoints**:
   - Set breakpoint at `GetModuleHandle` call
     <img width="882" height="142" alt="image" src="https://github.com/user-attachments/assets/9c38e836-4831-4d18-9e52-96bcd8eb2381" />
   - Use F2 to toggle breakpoints
     <img width="1680" height="815" alt="image" src="https://github.com/user-attachments/assets/1c9cae4d-ac99-4bac-b75d-d6b3cad1826d" />
	 <img width="1611" height="794" alt="image" src="https://github.com/user-attachments/assets/3fd2681a-6762-4c73-9894-f1e688d46a86" />
	 <img width="1606" height="791" alt="image" src="https://github.com/user-attachments/assets/f675f13c-e408-4ced-9947-8f6b6ba4d770" />

3. **Stack Analysis**:
   - Navigate to Call Stack view after breakpoint hit
     <img width="1612" height="485" alt="image" src="https://github.com/user-attachments/assets/4eec4bf3-3211-4c57-bb3d-47d4ec095c9b" />

   - Examine RBP register and stack addresses
   - Locate obfuscated strings on stack:
     - `RBP-30` → "kernel32.dll"
     - `RBP-20` → "VirtualProtect"
       <img width="1615" height="795" alt="image" src="https://github.com/user-attachments/assets/5fcc0dbe-04ba-4167-9acf-5849f0b87a93" />


#### Strings Utility Check


```batch
# Check for visible strings in binary
C: \rto\Tools\si\strings.exe -accepteula implant.exe | findstr /i kernel32.dll
C: \rto\Tools\si\strings.exe -accepteula implant.exe | findstr /i Virt
```

<img width="1186" height="398" alt="image" src="https://github.com/user-attachments/assets/eff06dcf-a90f-442f-934a-0da7379cca45" />


### 4. Entropy Analysis

#### Initial Entropy Assessment
1. **Open in Helium**:
   ```batch
   # Load binary in hex editor
   HxD.exe implant.exe
   ```

   <img width="937" height="465" alt="image" src="https://github.com/user-attachments/assets/c1dffda6-1396-4a8a-ba12-8390b130d24e" />

2. **Visual Analysis**:
   - Examine PE headers (structured data, lower entropy)
     <img width="933" height="462" alt="image" src="https://github.com/user-attachments/assets/4f29d868-eefb-4e4c-b41d-14a3c83d3e0a" />

   - Identify .text section (code, moderate entropy)
   - Locate encrypted payload (high entropy, random patterns)

3. **Generate Entropy Chart**:
   - Set block size to 256 bytes
   - Use 32-bit entropy computation
     <img width="937" height="461" alt="image" src="https://github.com/user-attachments/assets/0ccecb4d-bffa-4062-9c48-0ffd25c173fc" />

   - Observe entropy spikes indicating encrypted regions
     <img width="839" height="495" alt="image" src="https://github.com/user-attachments/assets/a8d008f9-c034-4788-a760-60e3a93b6071" />
	 
	 So from this, we actually don't see our encrypted payloads. So let's rename implant.exe as implant-small.exe and let's change our payload to something bigger.

### 5. Payload Optimization

There's a sample encrypted message shellcode, but compiled and encrypted as a reflective DLL:

<img width="932" height="318" alt="image" src="https://github.com/user-attachments/assets/15e43612-af1a-40ff-9401-d105f7cfda1d" />

```cpp
// MessageBox shellcode - 64-bit
// unsigned char payload[] = { 0x23, 0xe5, 0x84...};
// unsigned char key[] = { 0xc0, 0xa6, 0x8b... };

// reflective DLL launching MessageBox shellcode
unsigned char payload[] = { 0x3e, 0x50, 0xe6...};
unsigned char key[] = { 0xd, 0x66, 0xb9, 0x3c...};

```

<img width="941" height="304" alt="image" src="https://github.com/user-attachments/assets/c0453a5a-de8f-406d-b876-38a63a2596c8" />


#### Recompilation
```batch
# Recompile with modified payload placement
compile.bat
```
<img width="495" height="210" alt="image" src="https://github.com/user-attachments/assets/91daea48-9bf3-493e-a037-04d702c4dd46" />

Let's rename the file to implant-data.exe:

<img width="179" height="121" alt="image" src="https://github.com/user-attachments/assets/49c01054-fea1-4105-bd9b-75b2fa301370" />

Entropy chart of implant-data.exe:

<img width="933" height="467" alt="image" src="https://github.com/user-attachments/assets/011f1bf9-02e8-4dec-90d6-939a021b1940" />

The horizontal line on the chart shows our payload, as it stands out very clearly here:

<img width="746" height="497" alt="image" src="https://github.com/user-attachments/assets/0988184b-b7b1-4257-ad97-d21a9d48af85" />

What can be done? We can try to move that payload into the text section, so the easiest way is just to put it on stack.  

#### Moving Payload to Text Section

Move this section:
```batch
unsigned char payload[] = {...};
unsigned char key[] = {...};

unsigned int payload_len = sizeof(payload);
```

Place it on stack under `int main(void)	{`:

<img width="1658" height="728" alt="image" src="https://github.com/user-attachments/assets/1ca611f7-67b7-4487-a98a-797ece9b56e5" />

Compile it again using `compile.bat`:

<img width="290" height="166" alt="image" src="https://github.com/user-attachments/assets/ffb6f0c3-9f51-4bd6-a277-3b0eacd9164a" />

Check to see if it works:

<img width="454" height="215" alt="image" src="https://github.com/user-attachments/assets/2a3c6b3a-b30d-4b1c-99d2-92a15720ef1f" />

Rename it to `implant-text.exe`:

<img width="169" height="109" alt="image" src="https://github.com/user-attachments/assets/bc66c569-079a-4f32-aed6-53e6de1c2df1" />

<img width="843" height="501" alt="image" src="https://github.com/user-attachments/assets/474a7dc6-cbfb-4d86-80e3-f83def7d883e" />
<img width="885" height="262" alt="image" src="https://github.com/user-attachments/assets/17c5bd72-285d-4728-a5db-203a74cd6d81" />


Now at least it looks random and not a constant line. It's a little bit better but there is something else we can do.  

### 6. Advanced Entropy Camouflage

#### File Concatenation Methods

**Option 1: Image Concatenation**

This depends on the image:

<img width="940" height="465" alt="image" src="https://github.com/user-attachments/assets/2709fb95-2ecb-43f6-ba79-677bdcfbc742" />
<img width="587" height="463" alt="image" src="https://github.com/user-attachments/assets/7ee2a3db-2619-4bcf-b3ec-9f62aede41d0" />

Modern.IE is just a blue background and the chart is very different and nothing random here, with blue colour as the entire image:

<img width="932" height="460" alt="image" src="https://github.com/user-attachments/assets/afc1c564-9df7-470c-ae01-99a63b936fcd" />
<img width="588" height="464" alt="image" src="https://github.com/user-attachments/assets/b7d47a47-3cab-4534-81fd-5f636ad9cac7" />

Image No.3 `s7bg.jpg` we see there is almost super high enthropy through the whole file, which is from an image that has a lot more visual:

<img width="778" height="499" alt="image" src="https://github.com/user-attachments/assets/a0710d88-eda1-4c98-8caf-6a3c78798bf6" />

```batch
copy c: \BGinfo\s7bg.jpg a.jpg

# Combine with JPEG image
type implant-text.exe >> a.jpg

# Verify combined file
a.jpg
```

<img width="393" height="116" alt="image" src="https://github.com/user-attachments/assets/ca58e2dc-7690-45a3-83c6-48b2c64c13c9" />

<img width="179" height="156" alt="image" src="https://github.com/user-attachments/assets/d557f096-1ee7-4c04-a688-5b01ad24f312" />

<img width="859" height="498" alt="image" src="https://github.com/user-attachments/assets/754dba06-2d6a-49d5-a781-d19931e589a9" />

The large dip in the chart are the PE headers, and it looks better than what we had previously.


**Option 2: Binary Concatenation**
```batch
# Combine with legitimate binary
copy implant-data.exe bin.exe

type c:\windows\system32\kernel32.dll >> bin.exe

# Test functionality
bin.exe
```

<img width="489" height="298" alt="image" src="https://github.com/user-attachments/assets/3e2ce6d2-7870-4d82-aaf0-8e632d1ed8cd" />

<img width="920" height="464" alt="image" src="https://github.com/user-attachments/assets/de205398-0c82-4c64-8c00-358f91f13089" />

This is very effective way as a quick fix for any detection based on entropy. This is really effective against some EDRs.

#### Resource Section Embedding
```cpp
// Alternative: Embed in resources (referenced from Essentials course)
// Resource script (.rc) definition
Payload RCDATA "encrypted.bin"
```

### 7. Validation Steps

#### Functional Testing
1. Execute modified binaries
2. Verify payload execution integrity
3. Check for any behavioral changes

#### Entropy Verification
1. Re-analyze in HxD with entropy charts
2. Compare before/after entropy profiles
3. Ensure high-entropy regions are less conspicuous

#### Detection Testing
1. Test against target security products
2. Validate entropy-based detection evasion
3. Monitor for any new detection triggers

## Complete Workflow Example

### Initial Setup
```batch
# 1. Compile original version
cl /Fe:implant_v1.exe implant.cpp

# 2. Test execution
implant_v1.exe

# 3. Analyze strings
strings64.exe implant_v1.exe > strings_before.txt

# 4. Check entropy in HxD
```

### Optimization Phase
```batch
# 1. Modify payload placement in code
# 2. Recompile optimized version
cl /Fe:implant_v2.exe implant_optimized.cpp

# 3. Create camouflaged versions
copy /b implant_v2.exe + legit_image.jpg final.jpg
copy /b implant_v2.exe + system_dll.dll hybrid.exe
```

### Final Validation
```batch
# Test all variants
final.jpg
hybrid.exe

# Verify evasion effectiveness
# - Entropy analysis
# - Security product testing
# - Functional requirements met
```

## Key Technical Points

### Compilation Notes
- Use release builds for final versions
- Consider optimization flags (/O2) for smaller size
- Test debug vs release behavior differences

### String Obfuscation Benefits
- Avoids clear-text strings in binary
- Bypasses basic string scanning
- Maintains functionality through stack construction

### Entropy Management
- Distribute high-entropy data across sections
- Use legitimate files to normalize overall entropy
- Balance between evasion and operational reliability

## Troubleshooting Common Issues

### Compilation Errors
- Ensure Windows SDK and build tools are installed
- Check for missing dependencies or includes
- Verify x64/x86 architecture consistency

### Functional Issues
- Validate payload decryption logic
- Check memory protection changes (VirtualProtect)
- Verify thread creation parameters

### Evasion Effectiveness
- Test against multiple security products
- Consider target environment specifics
- Iterate based on detection results

---

</details>


<details>
<summary>04 - Module Details </summary>

</details>
