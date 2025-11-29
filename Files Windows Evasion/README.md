# Evasion Decision Tree

<img width="1606" height="633" alt="image" src="https://github.com/user-attachments/assets/6fb70af1-6d14-4cc9-86db-a01bba1bd236" />


A structured guide to evasion techniques, organized by execution context and privilege level, to help security professionals and red team operators navigate defensive measures.

## Overview

This decision tree provides a systematic approach to evasion, considering factors such as disk interaction, privilege level, and execution phase. The techniques are categorized to help you make informed decisions during security assessments.

## Pre-Execution Considerations

### Disk-Based Evasion

When your payload touches the disk, it must appear as an ordinary binary to avoid detection:

- **String Obfuscation**: Remove or encrypt identifiable strings that could trigger signature detection
- **Byte Pattern Randomization**: Alter recognizable code patterns that antivirus solutions may flag
- **Entropy Management**: Balance encryption complexity to avoid high entropy detection
- **Image Details**: Add legitimate-looking metadata, version information, and resources
- **Digital Signatures**: Apply valid digital signatures to increase trustworthiness

## Runtime Evasion Techniques

### Memory Execution Strategies

Once your payload is running in memory, regardless of privileges:

- **Process Cleaning**: Remove instrumentation hooks and traces
- **Direct System Calls**: Bypass user-mode API monitoring by calling kernel functions directly
- **ETW Patching**: Patch local Event Tracing for Windows functions to prevent telemetry collection
- **AMSI Bypass**: Patch Antimalware Scan Interface for scripting engines and .NET processes
- **DLL Unloading**: Research and utilize exported functions to unload security product DLLs from your process

## Privilege-Based Strategies

### High-Privilege Context

With administrative rights, your options expand significantly:

- **Communication Disruption**: Block outgoing logs and telemetry before tampering with local agents
- **Agent Manipulation**: Disable or remove EDR, AV, or Sysmon agents
- **Log Prevention**: Stop local security products from reporting to central monitoring systems

**Important Consideration**: Always obtain explicit permission before performing disruptive actions that violate security policies, as these actions create additional organizational risk.

### Low-Privilege Context

Without administrative rights, exercise caution and focus on stealth:

#### Detection Bypass Methods

1. **Avoid Dangerous Events**: Steer clear of commonly detected actions like LoadLibrary calls
2. **Behavioral Blending**: Mimic normal process behavior to avoid standing out

The key principle: **Be invisible by being common**. Security products act as watchers looking for anomalous behavior - your goal is to appear as ordinary as any legitimate process.

#### Policy Analysis

- **Rule Set Examination**: Study available detection rules (e.g., Sysmon XML configurations) to identify blind spots
- **Security Research**: Follow established detection avoidance recommendations from industry experts
- **Common Techniques**:
  - Module stomping
  - Threadless code execution
  - Parent process ID spoofing
  - Process argument spoofing

## Process Migration Considerations

When moving between processes:

- **Hook Removal**: Always clear instrumentation hooks before injecting payloads
- **Environment Sanitization**: Clean target processes of monitoring components
- **Stealth Injection**: Use techniques that minimize behavioral anomalies

## The Critical First Step: Reconnaissance

Regardless of your position in the evasion tree, comprehensive reconnaissance is fundamental:

- **Initial Assessment**: Gather maximum information before taking action
- **Analysis Phase**: Thoroughly examine collected data to identify weaknesses
- **Testing**: Validate tools and hypotheses in controlled environments
- **Methodical Execution**: Proceed only after careful planning and verification

**Remember**: Successful evasion is not a race - it's a methodical process where thorough preparation and intelligent execution determine success. The "low and slow" approach consistently outperforms rushed operations.

## Additional Resources

For advanced sandbox evasion techniques and additional defensive bypass methods, consult the linked research materials in the repository documentation.
