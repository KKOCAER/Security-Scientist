# =============================================================
#  Security Research Platform — Makefile
# =============================================================

SANDBOX_IP      := 10.10.30.10
ANALYST_IP      := 10.10.30.20
TI_IP           := 10.10.30.30
VULN_IP         := 10.10.30.40

REPORTS_DIR     := malware-analysis/reports
SAMPLES_DIR     := datasets/malware-samples
CRASHES_DIR     := /opt/fuzzing/crashes

.PHONY: all help analyze-static analyze-dynamic sandbox-submit \
        analyze-memory fuzz triage-crashes poc-scaffold \
        ingest-feed enrich-iocs misp-sync report ti-status

# ── Default ───────────────────────────────────────────────────
all: help

# ── Malware Analysis ──────────────────────────────────────────
analyze-static:
ifndef SAMPLE
	$(error Usage: make analyze-static SAMPLE=/path/to/sample)
endif
	@echo "🔬 Running static triage on $(SAMPLE)..."
	@ssh vagrant@$(ANALYST_IP) \
	  "python3 /vagrant/malware-analysis/static/static_triage.py $(SAMPLE)" \
	  | tee $(REPORTS_DIR)/$(shell basename $(SAMPLE)).json
	@echo "✅ Report: $(REPORTS_DIR)/$(shell basename $(SAMPLE)).json"

sandbox-submit:
ifndef SAMPLE
	$(error Usage: make sandbox-submit SAMPLE=/path/to/sample)
endif
	@echo "📦 Submitting $(SAMPLE) to CAPE sandbox..."
	@curl -s -X POST http://$(SANDBOX_IP):8000/tasks/create/file \
	  -F file=@$(SAMPLE) \
	  -F timeout=120 \
	  -F options="procmemdump=1,network=1"
	@echo "\n✅ Sample submitted — check http://$(SANDBOX_IP):8000"

analyze-memory:
ifndef DUMP
	$(error Usage: make analyze-memory DUMP=/path/to/memory.raw)
endif
	@echo "🧠 Running Volatility3 on $(DUMP)..."
	@ssh vagrant@$(ANALYST_IP) "bash -c '\
	  echo === Process List ===; vol3 -f $(DUMP) windows.pslist; \
	  echo === Network ===;      vol3 -f $(DUMP) windows.netstat; \
	  echo === Malfind ===;      vol3 -f $(DUMP) windows.malfind \
	'"

# ── Vulnerability Research ────────────────────────────────────
fuzz:
ifndef TARGET
	$(error Usage: make fuzz TARGET=./binary CORPUS=./corpus DURATION=24h)
endif
	@echo "💥 Starting AFL++ on $(TARGET)..."
	@ssh vagrant@$(VULN_IP) \
	  "timeout $(DURATION) afl-fuzz -i $(CORPUS) -o /opt/fuzzing/findings -- $(TARGET) @@ & \
	   sleep 30 && afl-whatsup /opt/fuzzing/findings"

triage-crashes:
ifndef BINARY
	$(error Usage: make triage-crashes BINARY=./target CRASHES=$(CRASHES_DIR))
endif
	@ssh vagrant@$(VULN_IP) \
	  "triage-crashes $(BINARY) $(CRASHES)"

poc-scaffold:
ifndef CVE
	$(error Usage: make poc-scaffold CVE=CVE-2024-12345)
endif
	@echo "📝 Creating PoC scaffold for $(CVE)..."
	@mkdir -p vulnerability-research/pocs/$(CVE)
	@cp vulnerability-research/cve-analysis/CVE_TEMPLATE.md \
	   vulnerability-research/pocs/$(CVE)/ANALYSIS.md
	@cat > vulnerability-research/pocs/$(CVE)/poc.py << 'EOF'
#!/usr/bin/env python3
# PoC: $(CVE)
from pwn import *

def exploit():
    p = process('./target')
    p.interactive()

if __name__ == '__main__':
    exploit()
EOF
	@echo "✅ PoC scaffold at vulnerability-research/pocs/$(CVE)/"

# ── Threat Intelligence ───────────────────────────────────────
ingest-feed:
ifndef FEED
	$(error Usage: make ingest-feed FEED=otx|urlhaus|feodo)
endif
	@ssh vagrant@$(TI_IP) \
	  "python3 /opt/ti-scripts/sync_feeds.py --feeds $(FEED)"

ti-status:
	@echo "📡 Threat Intel Platform Status"
	@curl -sk https://$(TI_IP)/status | python3 -m json.tool || true
	@curl -sk http://$(TI_IP):9000/api/v1/status 2>/dev/null | python3 -m json.tool || true

misp-sync:
	@ssh vagrant@$(TI_IP) \
	  "python3 /opt/ti-scripts/sync_feeds.py"
	@echo "✅ MISP sync complete"

# ── Reporting ─────────────────────────────────────────────────
report:
ifndef SAMPLE
	$(error Usage: make report SAMPLE=samplename TEMPLATE=malware)
endif
	@cp $(REPORTS_DIR)/templates/malware_report.md \
	   $(REPORTS_DIR)/$(SAMPLE)-$(shell date +%Y%m%d).md
	@echo "✅ Report template created: $(REPORTS_DIR)/$(SAMPLE)-$(shell date +%Y%m%d).md"

# ── Help ─────────────────────────────────────────────────────
help:
	@echo ""
	@echo "Security Research Platform — Make Targets"
	@echo ""
	@echo "  Malware Analysis:"
	@echo "    make analyze-static   SAMPLE=<path>        Static triage"
	@echo "    make sandbox-submit   SAMPLE=<path>        Submit to CAPE"
	@echo "    make analyze-memory   DUMP=<path>          Volatility3 analysis"
	@echo ""
	@echo "  Vulnerability Research:"
	@echo "    make fuzz             TARGET=<bin>         Start AFL++ fuzzing"
	@echo "    make triage-crashes   BINARY=<bin>         Deduplicate crashes"
	@echo "    make poc-scaffold     CVE=CVE-XXXX-XXXXX  Create PoC skeleton"
	@echo ""
	@echo "  Threat Intelligence:"
	@echo "    make ingest-feed      FEED=<name>          Pull specific feed"
	@echo "    make misp-sync                             Sync all feeds to MISP"
	@echo "    make ti-status                             Check TI platform health"
	@echo ""
	@echo "  Reporting:"
	@echo "    make report           SAMPLE=<name>        Create analysis report"
	@echo ""
