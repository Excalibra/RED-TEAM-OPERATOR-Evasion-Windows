# Essentials

<details>
<summary>1. Modern Detection Technology </summary>

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
<summary>2. Evasion Development Rules </summary>

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
