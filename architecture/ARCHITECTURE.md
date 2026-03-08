# Security Research Platform — Architecture

## Component Overview

```
┌──────────────────────────────────────────────────────────────────────────┐
│                     SECURITY RESEARCH PLATFORM                            │
│                                                                           │
│  ┌───────────────────┐          ┌───────────────────────────────────────┐ │
│  │   SANDBOX VM      │          │         ANALYST VM                    │ │
│  │   10.10.30.10     │          │         10.10.30.20                   │ │
│  │                   │          │                                       │ │
│  │  CAPE Sandbox ──────────────►│  Ghidra / Radare2 (static)           │ │
│  │  Cuckoo3          │  reports │  Volatility3 (memory)                 │ │
│  │  INetSim (fake    │          │  GDB + pwndbg (debugging)             │ │
│  │    internet)      │          │  pwntools / ROPgadget (exploit dev)   │ │
│  │  Docker (isolated)│          │  YARA / pefile (triage)               │ │
│  └───────────────────┘          └───────────────────────────────────────┘ │
│           ▲                                                               │ │
│  Samples ─┘                                                               │ │
│                                                                           │ │
│  ┌───────────────────┐          ┌───────────────────────────────────────┐ │
│  │  THREAT INTEL VM  │          │     VULN RESEARCH VM                  │ │
│  │  10.10.30.30      │          │     10.10.30.40                       │ │
│  │                   │          │                                       │ │
│  │  MISP             │          │  AFL++ (coverage-guided fuzzing)      │ │
│  │  OpenCTI          │          │  libFuzzer (in-process fuzzing)       │ │
│  │  TheHive          │          │  AddressSanitizer                     │ │
│  │  Cortex           │          │  Valgrind (memcheck)                  │ │
│  │  Feed automation  │          │  pwndbg + GEF                         │ │
│  └───────────────────┘          │  Crash triage automation              │ │
│                                 └───────────────────────────────────────┘ │
│                                                                           │ │
│  ┌───────────────────────────────────────────────────────────────────────┐ │
│  │             Isolated Research Network — 10.10.30.0/24                 │ │
│  │   Sandbox outbound → INetSim only (NOT real internet)                 │ │
│  └───────────────────────────────────────────────────────────────────────┘ │
└──────────────────────────────────────────────────────────────────────────┘
```

## VM Specifications

| VM           | IP           | OS           | CPUs | RAM   | Key Tools                      |
|--------------|--------------|--------------|------|-------|--------------------------------|
| sandbox      | 10.10.30.10  | Ubuntu 22.04 | 4    | 6 GB  | CAPE, Cuckoo3, INetSim         |
| analyst      | 10.10.30.20  | Ubuntu 22.04 | 4    | 6 GB  | Ghidra, r2, GDB, pwntools      |
| threat-intel | 10.10.30.30  | Ubuntu 22.04 | 2    | 4 GB  | MISP, TheHive, Cortex, OpenCTI |
| vuln-research| 10.10.30.40  | Ubuntu 22.04 | 4    | 4 GB  | AFL++, libFuzzer, ASan         |

**Total RAM required:** ~20 GB (run subsets with `vagrant up <vmname>`)

## Security Isolation

```
Internet ────────────── BLOCKED ──────────────── Sandbox
Internet ──────────────── OK ─────────────────── Other VMs (for tool download)

Sandbox ──────────────── OK ──────────────────── INetSim (fake internet)
Sandbox ─────────── NO ROUTE ──────────────────── Internet
```

## Port Reference

| Service      | Port  | VM           | URL                          |
|--------------|-------|--------------|------------------------------|
| CAPE Web UI  | 8000  | sandbox      | http://10.10.30.10:8000      |
| MISP         | 443   | threat-intel | https://10.10.30.30          |
| TheHive      | 9000  | threat-intel | http://10.10.30.30:9000      |
| Cortex       | 9001  | threat-intel | http://10.10.30.30:9001      |
| OpenCTI      | 8080  | threat-intel | http://10.10.30.30:8080      |
