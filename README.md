# Obscure - Thread-level Stealth Execution

---

## Table of Contents

- [Introduction](#introduction)  
- [Origin & Motivation](#origin--motivation)  
- [What is Obscure?](#what-is-obscure)  
- [Why Does It Matter?](#why-does-it-matter)  
- [How Does It Work?](#how-does-it-work)  
- [Building and Testing](#building-and-testing)  
- [Limitations & Future Directions](#limitations--future-directions)  
- [Personal Notes](#personal-notes)  

---

## Introduction

Obscure is a research-focused C++20 project aimed at enhancing stealth and anti-debugging capabilities at the thread level on Windows. It provides mechanisms to create and inject fake Thread Environment Blocks (TEB) and Process Environment Blocks (PEB) to mislead reverse engineering and forensic tools. This can help protect sensitive processes from detection and analysis.

---

## Origin & Motivation

The idea for Obscure came from a practical challenge: typical anti-debug methods often work at the process level or rely on straightforward API hooks that are easily bypassed. Threads, however, provide a more granular attack surface. By manipulating thread-level environment data, such as TEB and PEB, we can create a stronger layer of obfuscation. This project started as a personal exploration into stealth techniques that go beyond standard approaches.

---

## What is Obscure?

At its core, Obscure:

- Creates *fake* TEB and PEB structures in memory.
- Hooks critical Windows APIs that query thread and process information.
- Returns crafted data from these hooks to confuse or mislead analysis tools.
- Includes supporting modules like fake call stacks and fake executable regions to reinforce the illusion.
- Is designed to be modular, extensible, and relatively easy to integrate or expand.

---

## Why Does It Matter?

Reverse engineering and forensic analysis tools often rely on thread and process environment data to understand what’s running in memory. By injecting fake environment data and intercepting queries, Obscure raises the bar for detection. It is particularly useful for researchers or developers who want to experiment with stealth techniques or protect sensitive applications with a more sophisticated approach.

---

## How Does It Work?

Obscure hooks key APIs like `NtQueryInformationThread`, `GetThreadContext`, `ZwQueryVirtualMemory`, and `NtQueryInformationProcess`. When these functions are called, Obscure’s hooks provide fake yet plausible data structures instead of the real ones.

- **Fake TEB/PEB:** Obscure allocates memory for fake thread and process environment blocks and fills them with realistic data.
- **Fake Call Stack & Executable Region:** It also sets up fake call stacks and executable regions so stack traces and memory queries appear consistent.
- **API Hooks:** Using MinHook, it intercepts calls to critical Windows APIs and substitutes real pointers and data with fake ones.
- **Thread-level Precision:** Because it works at the thread API level, Obscure can target stealth precisely where many tools look for clues.

---

## Building and Testing

The project uses C++20 and CMake for building on Windows 11 (x64 and x86).

- **Requirements:** Visual Studio 2022 or compatible C++ compiler, CMake, and MinHook library.
- **Build:** `cmake` + `msbuild` or via VSCode tasks.
- **Testing:** The `exampleSpoof.exe` demonstrates the core features and runs comprehensive tests of all hooks and fake data. It verifies TEB/PEB spoofing, stack context manipulation, and virtual memory query interception.

Run `exampleSpoof.exe` to see detailed outputs confirming the hooks are active and returning the fake data as expected.

---

## Limitations & Future Directions

Obscure is a research project and a work in progress:

- Currently supports a limited set of APIs and focuses on Windows 11 64-bit primarily.
- The fake data is plausible but minimal; future work could include more realistic PEB/TEB structures, multi-thread and multi-process support.
- Integration with advanced anti-debug or anti-forensic methods is planned but not yet implemented.
- Documentation and modular interfaces will improve as the project matures.

---

## Personal Notes

This project is my exploration of stealth and evasion at a thread level — an area that feels under-explored compared to traditional process-level protections. It’s not about foolproof anti-reversing but about raising complexity and delay for casual inspection tools. I kept the implementation clean and modular, so anyone curious can extend or adapt it.

I hope Obscure sparks ideas or serves as a foundation for more advanced stealth solutions. If you find it useful or want to collaborate, I’m happy to hear your thoughts.

---

*Created by a developer passionate about low-level Windows internals and stealth techniques.*
