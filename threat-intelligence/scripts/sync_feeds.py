#!/usr/bin/env python3
"""
sync_feeds.py — Threat Intelligence Feed Aggregator
Pulls IOCs from multiple sources and pushes to MISP.

Supported sources:
  - AlienVault OTX
  - Abuse.ch (URLhaus, MalwareBazaar, Feodo Tracker)
  - ThreatFox
  - CISA Known Exploited Vulnerabilities

Usage:
  python3 sync_feeds.py --config feeds.yml [--dry-run]
"""

import os
import sys
import json
import time
import hashlib
import logging
import argparse
import datetime
import requests
import yaml
from dataclasses import dataclass, field
from typing import Optional

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s — %(message)s",
    handlers=[logging.StreamHandler()]
)
log = logging.getLogger("ti-sync")

# ── Configuration defaults ────────────────────────────────────────────────────

DEFAULT_CONFIG = {
    "misp": {
        "url":         os.environ.get("MISP_URL", "https://10.10.30.30"),
        "key":         os.environ.get("MISP_KEY", ""),
        "verify_ssl":  False,
    },
    "feeds": {
        "otx":           {"enabled": True,  "api_key": os.environ.get("OTX_KEY", "")},
        "urlhaus":        {"enabled": True,  "url": "https://urlhaus-api.abuse.ch/v1/urls/recent/"},
        "malwarebazaar":  {"enabled": True,  "url": "https://mb-api.abuse.ch/api/v1/"},
        "feodo":          {"enabled": True,  "url": "https://feodotracker.abuse.ch/downloads/ipblocklist.json"},
        "threatfox":      {"enabled": True,  "url": "https://threatfox-api.abuse.ch/api/v1/"},
        "cisa_kev":       {"enabled": True,  "url": "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"},
    },
    "options": {
        "max_age_days":    7,
        "deduplicate":     True,
        "min_confidence":  50,
    }
}


@dataclass
class IOC:
    value:      str
    type:       str         # ip, domain, url, md5, sha256, filename
    source:     str
    confidence: int = 80
    tags:       list = field(default_factory=list)
    comment:    str = ""
    timestamp:  str = field(default_factory=lambda: datetime.datetime.utcnow().isoformat())

    def fingerprint(self) -> str:
        return hashlib.sha1(f"{self.type}:{self.value}".encode()).hexdigest()


class FeedAggregator:
    def __init__(self, config: dict):
        self.config  = config
        self.iocs    = []
        self.seen    = set()
        self.session = requests.Session()
        self.session.headers.update({"User-Agent": "SecurityResearchPlatform/1.0"})

    def fetch_urlhaus(self) -> list[IOC]:
        """Fetch recent malicious URLs from URLhaus."""
        log.info("Fetching URLhaus...")
        iocs = []
        try:
            resp = self.session.post(
                self.config["feeds"]["urlhaus"]["url"],
                data={"query": "get_urls", "limit": 200},
                timeout=30
            )
            data = resp.json()
            for entry in data.get("urls", []):
                if entry.get("url_status") == "online":
                    iocs.append(IOC(
                        value=entry["url"], type="url",
                        source="urlhaus",
                        tags=["malware", entry.get("tags", "").split(",")] if entry.get("tags") else ["malware"],
                        comment=f"URLhaus: {entry.get('threat', '')}",
                    ))
        except Exception as e:
            log.error(f"URLhaus error: {e}")
        log.info(f"  → {len(iocs)} IOCs from URLhaus")
        return iocs

    def fetch_malwarebazaar(self) -> list[IOC]:
        """Fetch recent malware hashes from MalwareBazaar."""
        log.info("Fetching MalwareBazaar...")
        iocs = []
        try:
            resp = self.session.post(
                self.config["feeds"]["malwarebazaar"]["url"],
                data={"query": "get_recent", "selector": "time"},
                timeout=30
            )
            data = resp.json()
            for entry in data.get("data", []):
                iocs.append(IOC(
                    value=entry["sha256_hash"], type="sha256",
                    source="malwarebazaar",
                    tags=["malware", entry.get("tags", ["unknown"])],
                    comment=f"MalwareBazaar: {entry.get('signature', 'unknown')}",
                ))
        except Exception as e:
            log.error(f"MalwareBazaar error: {e}")
        log.info(f"  → {len(iocs)} IOCs from MalwareBazaar")
        return iocs

    def fetch_feodo(self) -> list[IOC]:
        """Fetch C2 IPs from Feodo Tracker."""
        log.info("Fetching Feodo Tracker...")
        iocs = []
        try:
            resp = self.session.get(
                self.config["feeds"]["feodo"]["url"], timeout=30)
            data = resp.json()
            for entry in data:
                iocs.append(IOC(
                    value=entry["ip_address"], type="ip-dst",
                    source="feodo-tracker",
                    tags=["botnet", "c2", entry.get("malware", "unknown").lower()],
                    comment=f"Feodo C2: {entry.get('malware', '')} ({entry.get('status', '')})",
                    confidence=90,
                ))
        except Exception as e:
            log.error(f"Feodo error: {e}")
        log.info(f"  → {len(iocs)} IOCs from Feodo Tracker")
        return iocs

    def fetch_threatfox(self) -> list[IOC]:
        """Fetch recent IOCs from ThreatFox."""
        log.info("Fetching ThreatFox...")
        iocs = []
        try:
            resp = self.session.post(
                self.config["feeds"]["threatfox"]["url"],
                json={"query": "get_iocs", "days": 3},
                timeout=30
            )
            data = resp.json()
            for entry in data.get("data", []):
                ioc_type = entry.get("ioc_type", "").replace("-", "")
                iocs.append(IOC(
                    value=entry["ioc"], type=ioc_type,
                    source="threatfox",
                    tags=["malware", entry.get("malware", "")],
                    comment=f"ThreatFox: {entry.get('malware', '')} — {entry.get('threat_type', '')}",
                    confidence=entry.get("confidence_level", 50),
                ))
        except Exception as e:
            log.error(f"ThreatFox error: {e}")
        log.info(f"  → {len(iocs)} IOCs from ThreatFox")
        return iocs

    def deduplicate(self, iocs: list[IOC]) -> list[IOC]:
        """Remove duplicate IOCs by fingerprint."""
        unique = []
        for ioc in iocs:
            fp = ioc.fingerprint()
            if fp not in self.seen:
                self.seen.add(fp)
                unique.append(ioc)
        return unique

    def push_to_misp(self, iocs: list[IOC], dry_run: bool = False) -> int:
        """Push IOCs to MISP as attributes."""
        if not self.config["misp"]["key"]:
            log.warning("No MISP API key configured — skipping push")
            return 0

        try:
            from pymisp import PyMISP, MISPEvent, MISPAttribute
        except ImportError:
            log.error("pymisp not installed: pip install pymisp")
            return 0

        if dry_run:
            log.info(f"[DRY RUN] Would push {len(iocs)} IOCs to MISP")
            return len(iocs)

        misp = PyMISP(
            url=self.config["misp"]["url"],
            key=self.config["misp"]["key"],
            ssl=self.config["misp"]["verify_ssl"],
        )

        # Create a new event for this batch
        event = MISPEvent()
        event.info        = f"TI Feed Sync — {datetime.date.today().isoformat()}"
        event.distribution = 0   # Organisation only
        event.threat_level_id = 2
        event.analysis    = 1

        for ioc in iocs:
            attr = MISPAttribute()
            attr.type  = ioc.type
            attr.value = ioc.value
            attr.comment = f"[{ioc.source}] {ioc.comment}"
            attr.to_ids = True
            event.add_attribute(**attr)

        result = misp.add_event(event)
        pushed = len(result.get("Attribute", []))
        log.info(f"✅ Pushed {pushed} IOCs to MISP (event ID: {result.get('id')})")
        return pushed

    def run(self, dry_run: bool = False) -> None:
        """Execute full sync pipeline."""
        start = time.time()
        log.info("Starting threat intel feed sync...")

        all_iocs = []
        cfg = self.config["feeds"]

        if cfg.get("urlhaus", {}).get("enabled"):
            all_iocs.extend(self.fetch_urlhaus())
        if cfg.get("malwarebazaar", {}).get("enabled"):
            all_iocs.extend(self.fetch_malwarebazaar())
        if cfg.get("feodo", {}).get("enabled"):
            all_iocs.extend(self.fetch_feodo())
        if cfg.get("threatfox", {}).get("enabled"):
            all_iocs.extend(self.fetch_threatfox())

        log.info(f"Total IOCs collected: {len(all_iocs)}")

        if self.config["options"]["deduplicate"]:
            all_iocs = self.deduplicate(all_iocs)
            log.info(f"After deduplication: {len(all_iocs)}")

        # Filter by confidence
        min_conf = self.config["options"]["min_confidence"]
        all_iocs = [i for i in all_iocs if i.confidence >= min_conf]
        log.info(f"After confidence filter (>= {min_conf}): {len(all_iocs)}")

        pushed = self.push_to_misp(all_iocs, dry_run=dry_run)

        elapsed = time.time() - start
        log.info(f"Sync complete in {elapsed:.1f}s — {pushed} IOCs pushed to MISP")


def main():
    parser = argparse.ArgumentParser(description="Threat Intel Feed Aggregator")
    parser.add_argument("--config",  default=None, help="Path to YAML config file")
    parser.add_argument("--dry-run", action="store_true", help="Do not push to MISP")
    args = parser.parse_args()

    config = DEFAULT_CONFIG.copy()
    if args.config and os.path.exists(args.config):
        with open(args.config) as f:
            config.update(yaml.safe_load(f))

    agg = FeedAggregator(config)
    agg.run(dry_run=args.dry_run)


if __name__ == "__main__":
    main()
