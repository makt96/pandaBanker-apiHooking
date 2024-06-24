# PandaBanker Malware Analysis

This repository contains a comprehensive analysis of the PandaBanker malware. The analysis includes examining various techniques employed by the malware such as API Hooking, Process Hijacking, and Memory Dumping. The investigation also involves practical steps using various tools to understand the malware's behavior and persistence mechanisms.

## Table of Contents

- [Introduction](#introduction)
- [Analysis Techniques](#analysis-techniques)
  - [API Hooking](#api-hooking)
  - [Process Hijacking](#process-hijacking)
  - [Memory Dumping](#memory-dumping)
- [Breakpoints and Tools Used](#breakpoints-and-tools-used)
- [Session Hijacking Analysis](#session-hijacking-analysis)
- [Memory Dump Correction and Analysis](#memory-dump-correction-and-analysis)
- [Conclusion](#conclusion)

## Introduction

PandaBanker is a sophisticated banking Trojan designed to steal sensitive financial information from users. This analysis provides an in-depth look at the malware's methods, including how it hooks into APIs, hijacks processes, and manipulates memory. The goal is to uncover the inner workings of PandaBanker and develop effective countermeasures.

## Analysis Techniques

### API Hooking

API Hooking is a technique used by malware to intercept and modify API calls made by a program. By hooking into the APIs, PandaBanker can capture sensitive information such as login credentials and financial data, operating covertly within legitimate applications.

### Process Hijacking

Process Hijacking involves taking over a legitimate process to execute malicious code. PandaBanker uses this technique to run its payload within trusted applications, bypassing security mechanisms that might detect standalone malware.

### Memory Dumping

Memory Dumping allows malware to extract sensitive information from a process's memory. PandaBanker uses this technique to capture passwords, encryption keys, and other confidential data stored in memory.

## Breakpoints and Tools Used

To analyze PandaBanker, we set breakpoints on critical API functions using xdbg debugger and other tools:

- `Process32First`
- `VirtualAlloc`
- `VirtualProtect`
- `IsDebuggerPresent`
- `CreateFileA`
- `CreateFileW`
- `CreateToolhelp32Snapshot`
- `CreateProcessInternalW`
- `NtCreateVirtualMemory`
- `WriteProcessMemory`
- `CreateProcessW`
- `CreateRemoteThread`

These breakpoints helped us monitor the malware's actions and understand its manipulation of system processes and memory.

## Session Hijacking Analysis

We analyzed how PandaBanker hijacks a session from another process. Using `ConstantPropagator.exe`, we observed the creation of `svghost.exe` with RWX permissions and the writing of an executable header into its memory. This demonstrated how the malware injects code into legitimate processes to maintain control.

## Memory Dump Correction and Analysis

After dumping the memory, we used PE Bear to identify and correct header discrepancies. By manually editing the memory dump with a hex editor and performing unmapping calculations, we prepared the file for analysis with IDA Pro. This allowed us to disassemble the malware and understand its structure and API call patterns.

## Conclusion

This analysis of PandaBanker malware revealed its sophisticated methods for infection, persistence, and evasion. By examining API Hooking, Process Hijacking, and Memory Dumping, we gained insights into the malware's capabilities. Understanding these techniques is crucial for developing robust security measures to protect against such threats.
