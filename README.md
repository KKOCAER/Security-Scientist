# 🔬 Security Research Platform

> A modular, automated security research environment for malware analysis, vulnerability research, threat intelligence, and reverse engineering — all provisioned as code.

---

## 📐 Architecture

```
┌──────────────────────────────────────────────────────────────────────┐
│                      HOST MACHINE (8+ GB RAM)                         │
│                                                                       │
│  ┌───────────────┐  ┌────────────────┐  ┌────────────────────────┐  │
│  │  SANDBOX      │  │   ANALYST      │  │   THREAT INTEL         │  │
│  │  Ubuntu 22.04 │  │   Ubuntu 22.04 │  │   Ubuntu 22.04         │  │
│  │ 10.10.30.10   │  │  10.10.30.20   │  │  10.10.30.30           │  │
│  │               │  │                │  │                        │  │
│  │ CAPE Sandbox  │  │ Ghidra         │  │ MISP                   │  │
│  │ Docker        │  │ Cutter/r2      │  │ OpenCTI                │  │
│  │ Cuckoo3       │  │ Binary Ninja   │  │ TheHive                │  │
│  │ inetsim       │  │ GDB / pwndbg   │  │ Cortex                 │  │
│  │ FakeNet-NG    │  │ pwntools       │  │ TAXII feeds            │  │
│  └───────────────┘  │ ROPgadget      │  └────────────────────────┘  │
│                     │ Volatility3    │                               │
│                     │ YARA           │  ┌────────────────────────┐  │
│                     └────────────────┘  │   VULN RESEARCH        │  │
│                                         │   Ubuntu 22.04         │  │
│                                         │  10.10.30.40           │  │
│                                         │                        │  │
│                                         │ AFL++ / libFuzzer      │  │
│                                         │ AddressSanitizer       │  │
│                                         │ Valgrind               │  │
│                                         │ pwndbg / GEF           │  │
│                                         └────────────────────────┘  │
│                                                                       │
│         ┌───────────────────────────────────────────┐                │
│         │       Isolated Network: 10.10.30.0/24      │                │
│         │    + Inetsim (fake internet for sandbox)   │                │
│         └───────────────────────────────────────────┘                │
└──────────────────────────────────────────────────────────────────────┘
```

---

## 🧰 Stack

| Domain                | Tool                              | Role                           |
|-----------------------|-----------------------------------|--------------------------------|
| Malware Sandbox       | CAPE / Cuckoo3                    | Dynamic analysis automation    |
| Fake Network          | INetSim + FakeNet-NG              | Safe C2 simulation             |
| Reverse Engineering   | Ghidra 11.x, Radare2/Cutter       | Static binary analysis         |
| Debugger              | GDB + pwndbg / peda / GEF         | Dynamic debugging              |
| Exploitation Dev      | pwntools, ROPgadget, checksec     | Exploit development            |
| Memory Forensics      | Volatility3                       | RAM artefact extraction        |
| Threat Intel          | MISP + OpenCTI                    | IOC management & sharing       |
| Case Management       | TheHive + Cortex                  | Investigation tracking         |
| Fuzzing               | AFL++ + libFuzzer                 | Vulnerability discovery        |
| OSINT                 | theHarvester, Maltego CE          | Reconnaissance                 |
| Reporting             | Markdown + Pandoc                 | Research documentation         |

---

## ⚡ Quick Start

```bash
git clone https://github.com/youruser/security-research-platform
cd security-research-platform

# Full lab (requires ~16 GB RAM)
vagrant up

# Selective provisioning
vagrant up sandbox
vagrant up analyst
vagrant up threat-intel
vagrant up vuln-research
```

---

## 📁 Repository Structure

```
security-research-platform/
├── README.md
├── architecture/
├── vagrant/
├── ansible/
│   ├── inventory
│   ├── playbooks/
│   │   ├── sandbox.yml
│   │   ├── analyst-workstation.yml
│   │   ├── threat-intel.yml
│   │   └── vuln-research.yml
│   └── roles/
│       ├── malware-analysis/
│       ├── vuln-research/
│       ├── threat-intel/
│       └── sandbox/
├── malware-analysis/
│   ├── static/          # Static analysis scripts & checklists
│   ├── dynamic/         # CAPE rules, behavioral analysis
│   ├── memory/          # Volatility3 plugins & profiles
│   └── reports/templates/
├── vulnerability-research/
│   ├── fuzzing/         # AFL++ harnesses & configs
│   ├── exploit-dev/     # Exploit templates & helpers
│   ├── cve-analysis/    # CVE research templates
│   └── pocs/            # Proof-of-concept directory
├── threat-intelligence/
│   ├── feeds/           # Feed configurations
│   ├── ioc-management/  # IOC enrichment scripts
│   ├── misp/            # MISP configs & taxonomies
│   └── scripts/         # TI automation scripts
├── reverse-engineering/
│   ├── tools-config/    # Ghidra, r2 profiles
│   ├── scripts/         # Analysis scripts (Python, JS)
│   └── samples/         # Reference binaries (benign)
├── sandboxing/
│   ├── cape/            # CAPE configuration
│   ├── cuckoo/          # Cuckoo3 configuration
│   └── configs/
├── osint/
│   ├── scripts/
│   ├── templates/
│   └── tools/
├── reporting/
│   ├── templates/       # Malware report, vuln report templates
│   └── findings/
└── datasets/
    ├── malware-samples/ # (NEVER push real malware to Git — use LFS or external)
    ├── pcaps/
    └── firmware/
```

---

## 🔬 Research Workflows

### Malware Analysis
```bash
# 1. Static triage
make analyze-static SAMPLE=/datasets/malware-samples/sample.exe

# 2. Submit to CAPE sandbox
make sandbox-submit SAMPLE=/datasets/malware-samples/sample.exe

# 3. Memory analysis (post-execution dump)
make analyze-memory DUMP=/datasets/memory.raw

# 4. Generate report
make report SAMPLE=sample TEMPLATE=malware
```

### Vulnerability Research
```bash
# Start fuzzing campaign
make fuzz TARGET=./target CORPUS=./corpus/ DURATION=24h

# Triage crashes
make triage-crashes CRASHES=./crashes/

# Generate PoC scaffold
make poc-scaffold CVE=CVE-2024-XXXX
```

### Threat Intelligence
```bash
# Ingest IOC feed
make ingest-feed FEED=otx

# Enrich IOCs
make enrich-iocs FILE=iocs.txt

# Sync to MISP
make misp-sync
```

---

## ⚠️ Safety Rules

> **NEVER** connect the sandbox VM to the internet directly.  
> All sandbox outbound traffic must route through INetSim/FakeNet-NG.  
> **NEVER** commit real malware samples to Git. Use Git LFS + password-protected archives or an external object store.

---

## 📜 License

MIT
