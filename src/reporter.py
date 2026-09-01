import datetime
import json
import os
from pathlib import Path
from typing import Any, Dict, List, Optional
import requests


class TelemetryReporter:
    def __init__(
        self,
        hits_file: Path,
        stats_file: Path,
        report_file: Path,
        webhook_url: str = "",
    ):
        self.hits_file = hits_file
        self.stats_file = stats_file
        self.report_file = report_file
        self.webhook_url = webhook_url

        self._init_files()

    def _init_files(self) -> None:
        self.hits_file.parent.mkdir(parents=True, exist_ok=True)
        if not self.hits_file.exists():
            with open(self.hits_file, "w", encoding="utf-8") as f:
                json.dump([], f, indent=2)

        if not self.stats_file.exists():
            default_stats = {
                "total_scanned": 0,
                "total_hits": 0,
                "last_run": None,
                "hits_by_platform": {},
                "hits_by_rule": {},
                "hits_by_source": {},
            }
            with open(self.stats_file, "w", encoding="utf-8") as f:
                json.dump(default_stats, f, indent=2)

    def load_hits(self) -> List[Dict[str, Any]]:
        try:
            with open(self.hits_file, "r", encoding="utf-8") as f:
                hits = json.load(f)
                # Auto-backfill missing source_feed for existing legacy hits
                modified = False
                for h in hits:
                    if "source_feed" not in h or not h["source_feed"]:
                        if "mb_metadata" in h:
                            h["source_feed"] = "MalwareBazaar"
                        elif h.get("vt_enrichment", {}).get("vt_status") == "success":
                            h["source_feed"] = "VirusTotal Enterprise"
                        else:
                            h["source_feed"] = "MalwareBazaar"
                        modified = True
                if modified:
                    with open(self.hits_file, "w", encoding="utf-8") as f_out:
                        json.dump(hits, f_out, indent=2)
                return hits
        except Exception:
            return []

    def load_stats(self) -> Dict[str, Any]:
        try:
            with open(self.stats_file, "r", encoding="utf-8") as f:
                stats = json.load(f)
                if "hits_by_source" not in stats:
                    stats["hits_by_source"] = {}
                return stats
        except Exception:
            return {
                "total_scanned": 0,
                "total_hits": 0,
                "last_run": None,
                "hits_by_platform": {},
                "hits_by_rule": {},
                "hits_by_source": {},
            }

    def record_run(
        self,
        scanned_count: int,
        new_hits: List[Dict[str, Any]],
        platforms: List[str],
    ) -> Dict[str, Any]:
        """Merge new hits and update overall statistics."""
        existing_hits = self.load_hits()
        stats = self.load_stats()

        timestamp = datetime.datetime.now(datetime.timezone.utc).isoformat()
        stats["last_run"] = timestamp
        stats["total_scanned"] += scanned_count

        # Deduplicate hits by (rule_name, sample_sha256)
        existing_keys = {
            f"{h.get('rule_name')}:{h.get('sample_sha256')}" for h in existing_hits
        }

        truly_new_hits = []
        for hit in new_hits:
            hit["detected_at"] = timestamp
            key = f"{hit.get('rule_name')}:{hit.get('sample_sha256')}"
            if key not in existing_keys:
                existing_keys.add(key)
                existing_hits.append(hit)
                truly_new_hits.append(hit)

        # Full recalculation of stats from all accumulated hits to ensure 100% consistency
        stats["total_hits"] = len(existing_hits)
        stats["hits_by_rule"] = {}
        stats["hits_by_source"] = {}
        stats["hits_by_platform"] = {}

        for h in existing_hits:
            rule = h.get("rule_name", "unknown")
            stats["hits_by_rule"][rule] = stats["hits_by_rule"].get(rule, 0) + 1

            source = h.get("source_feed", "MalwareBazaar")
            stats["hits_by_source"][source] = stats["hits_by_source"].get(source, 0) + 1

            plat = h.get("meta", {}).get("os") or h.get("namespace", "").split("_")[0] or "unknown"
            stats["hits_by_platform"][plat] = stats["hits_by_platform"].get(plat, 0) + 1

        # Save hits
        with open(self.hits_file, "w", encoding="utf-8") as f:
            json.dump(existing_hits, f, indent=2)

        # Save stats
        with open(self.stats_file, "w", encoding="utf-8") as f:
            json.dump(stats, f, indent=2)

        # Generate latest Markdown report
        self.generate_markdown_report(stats, existing_hits, truly_new_hits)

        # Send alert if webhook configured
        if self.webhook_url and truly_new_hits:
            self.send_webhook_alert(truly_new_hits)

        return stats

    def generate_markdown_report(
        self,
        stats: Dict[str, Any],
        all_hits: List[Dict[str, Any]],
        recent_hits: List[Dict[str, Any]],
    ) -> None:
        """Generates a GitHub-flavored Markdown report in telemetry/."""
        lines = [
            "# Yarafy Telemetry & Threat Hunting Report",
            f"\n**Last Run:** `{stats.get('last_run', 'N/A')}`",
            f"**Total Samples Scanned:** `{stats.get('total_scanned', 0)}` | **Total Rule Hits:** `{stats.get('total_hits', 0)}`\n",
            "## Hits Breakdown by Source Feed",
            "| Source Feed | Total Hits |",
            "| :--- | :--- |",
        ]

        for src, count in stats.get("hits_by_source", {}).items():
            lines.append(f"| **{src}** | `{count}` |")
        if not stats.get("hits_by_source"):
            lines.append("| *No hits recorded yet* | `0` |")

        lines.extend([
            "\n## Hits Breakdown by Platform",
            "| Platform | Total Hits |",
            "| :--- | :--- |",
        ])

        for plat, count in stats.get("hits_by_platform", {}).items():
            lines.append(f"| **{plat.upper()}** | `{count}` |")
        if not stats.get("hits_by_platform"):
            lines.append("| *None recorded yet* | `0` |")

        lines.extend([
            "\n## Hits Breakdown by YARA Rule",
            "| Rule Name | Total Detections |",
            "| :--- | :--- |",
        ])

        for rule, count in sorted(stats.get("hits_by_rule", {}).items(), key=lambda x: x[1], reverse=True):
            lines.append(f"| [`{rule}`](../yara-rules/) | `{count}` |")
        if not stats.get("hits_by_rule"):
            lines.append("| *No rule hits yet* | `0` |")

        lines.extend([
            "\n## Recent Positive Detections",
            "| Timestamp | Source Feed | Rule | Platform | SHA256 | VT Detection | VT Threat Label |",
            "| :--- | :--- | :--- | :--- | :--- | :--- | :--- |",
        ])

        # Show all recorded hits in reverse chronological order
        for hit in reversed(all_hits[-50:]):
            rule = hit.get("rule_name", "N/A")
            src_feed = hit.get("source_feed", "MalwareBazaar")
            plat = hit.get("meta", {}).get("os") or hit.get("namespace", "N/A")
            sha = hit.get("sample_sha256", "N/A")
            sha_short = f"`{sha[:10]}...`"
            ts = hit.get("detected_at", "N/A")[:19].replace("T", " ")
            vt_info = hit.get("vt_enrichment", {})
            vt_ratio = vt_info.get("detection_ratio", "N/A")
            vt_label = vt_info.get("suggested_threat_label", "N/A")
            vt_link = vt_info.get("vt_permalink")

            sha_display = f"[{sha_short}]({vt_link})" if vt_link else sha_short
            lines.append(f"| {ts} | **{src_feed}** | `{rule}` | {plat} | {sha_display} | `{vt_ratio}` | `{vt_label}` |")

        if not all_hits:
            lines.append("| - | - | *No hits recorded* | - | - | - | - |")

        with open(self.report_file, "w", encoding="utf-8") as f:
            f.write("\n".join(lines) + "\n")

    def send_webhook_alert(self, hits: List[Dict[str, Any]]) -> None:
        """Send notification webhook to Slack/Discord."""
        try:
            summary_text = f"**Yarafy Alert**: {len(hits)} new malware hit(s) detected!\n\n"
            for h in hits[:5]:
                src = h.get("source_feed", "Feed")
                rule = h.get("rule_name")
                sha = h.get("sample_sha256")
                vt = h.get("vt_enrichment", {}).get("detection_ratio", "N/A")
                summary_text += f"* **Source**: `{src}` | **Rule**: `{rule}`\n  **SHA256**: `{sha}`\n  **VT**: `{vt}`\n\n"

            payload = {"content": summary_text, "text": summary_text}
            requests.post(self.webhook_url, json=payload, timeout=10)
        except Exception as e:
            print(f"[!] Failed to send webhook alert: {e}")
