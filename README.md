# RED TEAM OPERATOR Evasion Windows

![image jpg](https://github.com/user-attachments/assets/9499d5de-257b-450e-9c38-026e647ef014)


A comprehensive repository covering modern evasion techniques in Windows environments, focusing on bypassing detection technologies and enhancing operational security.

## Overview

This repository contains research and implementations related to Windows evasion methodologies used in red team operations. The material explores detection technology weaknesses and practical techniques to avoid detection while maintaining payload execution capabilities.

## Contents

[Files Windows Evasion](https://github.com/Excalibra/RED-TEAM-OPERATOR-Evasion-Windows/tree/main/Files%20Windows%20Evasion)
- A structured guide to evasion techniques

[01.Essentials](https://github.com/Excalibra/RED-TEAM-OPERATOR-Evasion-Windows/tree/main/Files%20Windows%20Evasion/01.Essentials)
- 01 - Modern Detection Technology
- 02 - Evasion Development Rules
- 03 - Binary Entropy in Malware Detection
- 04 - Module Details Obfuscation
- 05 - Binary Signature

[02.Usage Guide for Non-privileged User Vector (Non-admin)](https://github.com/Excalibra/RED-TEAM-OPERATOR-Evasion-Windows/tree/main/Files%20Windows%20Evasion/02.Non-admin)
- 01 - Process Unhooking - Introduction
- 02 - Hooks vs Code Injections
- 03 - Process Unhooking Classic Method
- 04 - Hooks vs Hells Gate
- 05 - Hooks vs Halo Gate
- 06 - Process Unhooking Peruns Fart
- 07 - Silencing Process Event Tracing
- 08 - Module Stomping
- 09 - No-New-Thread Payload Execution
- 10 - Classic PPID Spoofing
- 11 - Changing Parents Scheduler
- 12 - Changing Parents Emotet Method
- 13 - Cmdline Arguments Spoofing
- Assignment #1 - Hooks
- Assignment #2 - Module Stomping


[03.Usage Guide for High-privileged user vector (Local-admin)](https://github.com/Excalibra/RED-TEAM-OPERATOR-Evasion-Windows/tree/main/Files%20Windows%20Evasion/03.Local-admin)
- 01 - Blinding Eventlog 2
- 02 - Blocking EPP Comms-Listing Connections
- 03 - Blocking EPP Comms-Firewall
- 04 - Blocking EPP Comms-Routing Table(P1)
- 05 - Blocking EPP Comms-Routing Table(P2)
- 06 - Dancing with Sysmon-Detection
- 07 - Dancing with Sysmon-Killem
- 08 - Dancing with Sysmon-Silent Gag
- Assignment#3-Sysmon
- Assignment#4-Sysmon


## Techniques

### Core Evasion Concepts
- **Detection Technology Analysis**: Understanding modern detection systems, their structure, and vulnerabilities
- **Evasion Development Principles**: Foundational rules for creating effective evasion techniques

### Binary Obfuscation
- **Digital Signature Spoofing**: Making binaries appear as legitimate signed applications
- **Module Information Manipulation**: Modifying binary metadata to resemble ordinary images
- **Entropy Management**: Comprehensive analysis of entropy and its application in evasion

### API Hooking & System Calls
- **API Hook Detection and Removal**: Identifying and eliminating process hooks
- **Direct System Calls**: Bypassing user-mode hooks through direct system call invocation
- **Event Tracing for Windows (ETW)**: Techniques for evading ETW monitoring
- **Process Patching**: Modifying running processes to remove monitoring capabilities

### Code Execution Techniques
- **Module Stomping**: Advanced code injection without creating new modules
- **Threadless Execution**: Launching payloads without spawning new threads
- **Process Spoofing**: Manipulating parent process identification
- **Dynamic Argument Modification**: Altering process arguments during execution

### Privileged Operations
- **Event Log Manipulation**: Techniques for blinding Windows event logs
- **Security Agent Communication Disruption**: Breaking network channels between local security agents and external logging systems
- **Sysmon Evasion**: Advanced techniques for avoiding Microsoft Sysmon detection

### Operational Guidance
- **Evasion Decision Making**: Strategic considerations for implementing evasion during engagements


## Technical Approach

### Payload Agnostic Design
All techniques are demonstrated using simple payloads (e.g., MessageBox shellcode) rather than specific C2 frameworks like Meterpreter or Empire. This approach ensures:

- Focus on core evasion methodology rather than specific implementation details
- Techniques remain applicable across various offensive security frameworks
- Easy adaptation to different command and control channels
- Clear separation of evasion principles from payload delivery mechanisms


## Usage

Each directory contains specific implementations and documentation for the corresponding evasion technique. Refer to individual module documentation for build instructions and usage examples.

## Legal Notice

This material is provided for educational and authorized penetration testing purposes only. Users are responsible for ensuring they have proper authorization before employing these techniques in any environment.

## Contributing

Please refer to the contribution guidelines for information on adding new techniques or improving existing implementations.

---

*For educational use in authorized security testing and research contexts.*
