# AbleLdr

>[!caution]
>This is a learning project and under active development, expect things to break

---

## Introduction

AbleLdr is a project created to learn C++ and malware development. The main idea is to create a modular/scalable loader that can have features added and removed easily.

## Features

### Execution Methods

- [x] Remote Process Injection
- [x] Thread Hijacking
- [x] AddressOfEntryPoint Injection
- [x] QueueUserAPC Injection
- [x] NtMapViewOfSection Injection

### Anti Debugging

- [x] Local Debugging Check (Exit on Detection)
- [x] Hide from Debugger
- [x] Remote Debugging Check

### Anti Sandboxing

- [x] Sleeping
- [x] Timeskip Checking

### Compilation

- [x] Executable
- [x] DLL

### Misc

- [x] Compile Time Signing
- [x] Custom Metadata

## Roadmap

### Execution Methods

- [ ] Early Bird APC Injection
- [ ] Process Doppleganger

### Guardrails

- [ ] AD Domain Checks
- [ ] IP Address Checks
- [ ] Integrity Checks

### Anti Debugging

- [ ] Local Debugging Check (Wait till debugger is removed)
- [ ] Local Debugging Check (Self Delete Loader after Wait Period)

### Anti Sandboxing

- [ ] Sandbox Detection

### Compilation

- [ ] Service Binary

### Misc

- [ ] x86 Compatibility
- [ ] Reflective Loader

## Special Thanks

- [Bakki](https://github.com/xrombar)
- [Legacyy](https://github.com/iilegacyyii/)
- [Maldev Academy](https://maldev.com)
- [IRed Team](https://ired.team)