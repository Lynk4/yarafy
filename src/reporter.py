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

        # Deduplicate hits by (rule_name, sample_sha256) and map for in-place refreshment
        existing_hits_map = {
            f"{h.get('rule_name')}:{h.get('sample_sha256')}": h
            for h in existing_hits
        }

        truly_new_hits = []
        refreshed_hits = []
        for hit in new_hits:
            hit["detected_at"] = timestamp
            key = f"{hit.get('rule_name')}:{hit.get('sample_sha256')}"
            if key not in existing_hits_map:
                existing_hits_map[key] = hit
                existing_hits.append(hit)
                truly_new_hits.append(hit)
            else:
                existing = existing_hits_map[key]
                updated = False

                # Update VirusTotal telemetry if new scan returned successful enrichment
                new_vt = hit.get("vt_enrichment")
                if new_vt and new_vt.get("vt_status") == "success":
                    existing["vt_enrichment"] = new_vt
                    updated = True

                # Update MalwareBazaar metadata if present
                if hit.get("mb_metadata"):
                    existing["mb_metadata"] = hit["mb_metadata"]
                    updated = True

                # Update matched strings if captured in this scan
                if hit.get("matched_strings"):
                    existing["matched_strings"] = hit["matched_strings"]
                    updated = True

                # Update sample name if the new one is descriptive
                new_name = hit.get("sample_name")
                if (
                    new_name
                    and new_name != "sample.bin"
                    and (
                        not existing.get("sample_name")
                        or existing["sample_name"] == "sample.bin"
                    )
                ):
                    existing["sample_name"] = new_name
                    updated = True

                existing["last_seen_at"] = timestamp
                if updated:
                    refreshed_hits.append(existing)

        stats["new_hits_this_run"] = len(truly_new_hits)
        stats["refreshed_hits_this_run"] = len(refreshed_hits)

        # Full recalculation of stats from all accumulated hits to ensure 100% consistency
        stats["total_hits"] = len(existing_hits)
        stats["hits_by_rule"] = {}
        stats["hits_by_source"] = {}
        stats["hits_by_platform"] = {p: 0 for p in platforms}

        for h in existing_hits:
            rule = h.get("rule_name", "unknown")
            stats["hits_by_rule"][rule] = stats["hits_by_rule"].get(rule, 0) + 1

            source = h.get("source_feed", "MalwareBazaar")
            stats["hits_by_source"][source] = stats["hits_by_source"].get(source, 0) + 1

            plat = h.get("platform") or h.get("meta", {}).get("os") or h.get("namespace", "").split("_")[0] or "unknown"
            stats["hits_by_platform"][plat] = stats["hits_by_platform"].get(plat, 0) + 1

        # Save hits
        with open(self.hits_file, "w", encoding="utf-8") as f:
            json.dump(existing_hits, f, indent=2)

        # Save stats
        with open(self.stats_file, "w", encoding="utf-8") as f:
            json.dump(stats, f, indent=2)

        # Generate latest Markdown report
        self.generate_markdown_report(stats, existing_hits, truly_new_hits)

        # Generate latest Dashboard data file
        self.generate_dashboard_data(stats, existing_hits)

        # Generate latest Dashboard preview SVG for README.md
        self.generate_dashboard_preview(stats, existing_hits)

        # Send alert if webhook configured
        if self.webhook_url and truly_new_hits:
            self.send_webhook_alert(truly_new_hits)

        return stats

    def generate_dashboard_preview(self, stats: Dict[str, Any], all_hits: List[Dict[str, Any]]) -> None:
        """Generate an updated assets/dashboard_preview.svg for README.md."""
        try:
            root_dir = self.hits_file.parent.parent
            assets_dir = root_dir / "assets"
            assets_dir.mkdir(parents=True, exist_ok=True)

            scanned = stats.get("total_scanned", 0)
            hits_count = stats.get("total_hits", 0)
            rate = f"{(hits_count / scanned * 100):.1f}%" if scanned > 0 else "0.0%"
            p_stats = stats.get("hits_by_platform", {})
            macos = p_stats.get("macos", 0)
            windows = p_stats.get("windows", 0)
            linux = p_stats.get("linux", 0)
            non_pe = p_stats.get("non-pe", 0)

            top_rules = sorted(stats.get("hits_by_rule", {}).items(), key=lambda x: x[1], reverse=True)[:3]
            max_rule_count = top_rules[0][1] if top_rules else 1

            rule_bars = ""
            bar_colors = ["url(#roseGrad)", "url(#blueGrad)", "#10b981"]
            for idx, (r_name, r_cnt) in enumerate(top_rules):
                y_pos = 56 + (idx * 40)
                bar_y = 64 + (idx * 40)
                width = max(24, int((r_cnt / max_rule_count) * 440))
                color = bar_colors[idx % len(bar_colors)]
                display_name = r_name if len(r_name) <= 38 else r_name[:35] + "..."
                rule_bars += f"""
    <text x="18" y="{y_pos}" fill="#94a3b8" font-size="11">{display_name}</text>
    <text x="490" y="{y_pos}" fill="#cbd5e1" font-size="11" text-anchor="end" font-weight="600">{r_cnt}</text>
    <rect x="18" y="{bar_y}" width="472" height="10" rx="5" fill="#1e293b"/>
    <rect x="18" y="{bar_y}" width="{width}" height="10" rx="5" fill="{color}"/>"""

            latest_hits = list(reversed(all_hits))[:3]
            rows_svg = ""
            row_y_offsets = [72, 112, 152]
            bg_colors = ["#151d30", "#101726", "#151d30"]
            for idx, h in enumerate(latest_hits):
                y_offset = row_y_offsets[idx]
                bg = bg_colors[idx]
                d_at = (h.get("detected_at") or "")[:16].replace("T", " ") or "Recent"
                plat = (h.get("platform") or "MACOS").upper()
                r_name = h.get("rule_name") or "Detection"
                r_disp = r_name if len(r_name) <= 34 else r_name[:31] + "..."
                feed = h.get("source_feed") or "Feed"
                sha = (h.get("sample_sha256") or "")[:12] + "..."
                vt = h.get("vt_enrichment") or {}
                ratio = vt.get("detection_ratio") or "Hit"
                label = vt.get("suggested_threat_label") or "malicious"
                label_disp = label if len(label) <= 22 else label[:19] + "..."

                rows_svg += f"""
    <g transform="translate(18, {y_offset})">
      <rect x="0" y="0" width="1100" height="34" fill="{bg}" rx="4"/>
      <text x="14" y="22" fill="#94a3b8" font-size="11">{d_at}</text>
      <rect x="130" y="8" width="54" height="18" rx="9" fill="rgba(59, 130, 246, 0.15)"/>
      <text x="157" y="21" text-anchor="middle" fill="#60a5fa" font-size="10" font-weight="600">{plat}</text>
      <text x="232" y="22" fill="#f8fafc" font-size="11" font-weight="500">{r_disp}</text>
      <text x="482" y="22" fill="#94a3b8" font-size="11">{feed}</text>
      <text x="622" y="22" fill="#38bdf8" font-size="11" font-family="monospace">{sha}</text>
      <rect x="782" y="8" width="46" height="18" rx="4" fill="rgba(239, 68, 68, 0.2)"/>
      <text x="805" y="21" text-anchor="middle" fill="#f87171" font-size="10" font-weight="700">{ratio}</text>
      <text x="882" y="22" fill="#cbd5e1" font-size="11">{label_disp}</text>
      <rect x="1032" y="6" width="56" height="22" rx="4" fill="#1e293b" stroke="#334155"/>
      <text x="1060" y="21" text-anchor="middle" fill="#93c5fd" font-size="10" font-weight="500">Inspect</text>
    </g>"""

            svg_content = f"""<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 1200 700" width="1200" height="700" style="background:#0b0f19; font-family:-apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Helvetica, Arial, sans-serif;">
  <defs>
    <linearGradient id="cardBg" x1="0" y1="0" x2="0" y2="1">
      <stop offset="0%" stop-color="#151d30"/>
      <stop offset="100%" stop-color="#0f172a"/>
    </linearGradient>
    <linearGradient id="primaryBtn" x1="0" y1="0" x2="1" y2="0">
      <stop offset="0%" stop-color="#2563eb"/>
      <stop offset="100%" stop-color="#1d4ed8"/>
    </linearGradient>
    <linearGradient id="roseGrad" x1="0" y1="0" x2="1" y2="0">
      <stop offset="0%" stop-color="#f43f5e"/>
      <stop offset="100%" stop-color="#fb7185"/>
    </linearGradient>
    <linearGradient id="blueGrad" x1="0" y1="0" x2="1" y2="0">
      <stop offset="0%" stop-color="#3b82f6"/>
      <stop offset="100%" stop-color="#60a5fa"/>
    </linearGradient>
    <linearGradient id="chartLine" x1="0" y1="0" x2="0" y2="1">
      <stop offset="0%" stop-color="rgba(16, 185, 129, 0.4)"/>
      <stop offset="100%" stop-color="rgba(16, 185, 129, 0.0)"/>
    </linearGradient>
    <filter id="cardShadow" x="-5%" y="-5%" width="110%" height="115%">
      <feDropShadow dx="0" dy="4" stdDeviation="6" flood-color="#000000" flood-opacity="0.4"/>
    </filter>
  </defs>

  <rect x="0" y="0" width="1200" height="700" rx="12" fill="#0b0f19" stroke="#1f2937" stroke-width="1.5"/>

  <rect x="0" y="0" width="1200" height="38" rx="12" fill="#090d16"/>
  <rect x="0" y="26" width="1200" height="12" fill="#090d16"/>
  <circle cx="20" cy="19" r="6" fill="#ef4444"/>
  <circle cx="38" cy="19" r="6" fill="#f59e0b"/>
  <circle cx="56" cy="19" r="6" fill="#10b981"/>
  <text x="600" y="24" text-anchor="middle" fill="#64748b" font-size="12" font-weight="500">https://lynk4.github.io/yarafy/ — Live Threat Intelligence Dashboard</text>

  <g transform="translate(32, 60)">
    <text x="0" y="24" fill="#ffffff" font-size="22" font-weight="700" letter-spacing="-0.5">Yarafy Threat Intelligence Dashboard</text>
    <text x="0" y="44" fill="#94a3b8" font-size="12">Real-time YARA detection telemetry across macOS, Windows, Linux, and Non-PE feeds</text>
    
    <rect x="800" y="6" width="170" height="28" rx="14" fill="rgba(16, 185, 129, 0.1)" stroke="rgba(16, 185, 129, 0.3)" stroke-width="1"/>
    <circle cx="816" cy="20" r="4" fill="#10b981"/>
    <text x="826" y="24" fill="#10b981" font-size="11" font-weight="600" letter-spacing="0.3">LIVE TELEMETRY</text>

    <rect x="980" y="6" width="70" height="28" rx="6" fill="#1e293b" stroke="#334155" stroke-width="1"/>
    <text x="1015" y="24" text-anchor="middle" fill="#cbd5e1" font-size="11" font-weight="500">Export</text>

    <rect x="1058" y="6" width="76" height="28" rx="6" fill="url(#primaryBtn)"/>
    <text x="1096" y="24" text-anchor="middle" fill="#ffffff" font-size="11" font-weight="600">Refresh</text>
  </g>

  <g transform="translate(32, 130)">
    <g transform="translate(0, 0)">
      <rect width="176" height="88" rx="8" fill="url(#cardBg)" stroke="#1e293b" stroke-width="1" filter="url(#cardShadow)"/>
      <text x="16" y="24" fill="#94a3b8" font-size="11" font-weight="600">TOTAL SCANNED</text>
      <text x="16" y="56" fill="#ffffff" font-size="24" font-weight="700">{scanned:,}</text>
      <text x="16" y="74" fill="#64748b" font-size="10">Lifetime throughput</text>
    </g>

    <g transform="translate(192, 0)">
      <rect width="176" height="88" rx="8" fill="url(#cardBg)" stroke="#1e293b" stroke-width="1" filter="url(#cardShadow)"/>
      <text x="16" y="24" fill="#94a3b8" font-size="11" font-weight="600">RULE HITS</text>
      <text x="16" y="56" fill="#f43f5e" font-size="24" font-weight="700">{hits_count:,}</text>
      <text x="16" y="74" fill="#64748b" font-size="10">{rate} hit rate</text>
    </g>

    <g transform="translate(384, 0)">
      <rect width="176" height="88" rx="8" fill="url(#cardBg)" stroke="#1e293b" stroke-width="1" filter="url(#cardShadow)"/>
      <text x="16" y="24" fill="#94a3b8" font-size="11" font-weight="600">MACOS</text>
      <text x="16" y="56" fill="#3b82f6" font-size="24" font-weight="700">{macos:,}</text>
      <text x="16" y="74" fill="#64748b" font-size="10">Mach-O / DMG / PKG</text>
    </g>

    <g transform="translate(576, 0)">
      <rect width="176" height="88" rx="8" fill="url(#cardBg)" stroke="#1e293b" stroke-width="1" filter="url(#cardShadow)"/>
      <text x="16" y="24" fill="#94a3b8" font-size="11" font-weight="600">WINDOWS</text>
      <text x="16" y="56" fill="#06b6d4" font-size="24" font-weight="700">{windows:,}</text>
      <text x="16" y="74" fill="#64748b" font-size="10">PE / DLL / MSI</text>
    </g>

    <g transform="translate(768, 0)">
      <rect width="176" height="88" rx="8" fill="url(#cardBg)" stroke="#1e293b" stroke-width="1" filter="url(#cardShadow)"/>
      <text x="16" y="24" fill="#94a3b8" font-size="11" font-weight="600">LINUX</text>
      <text x="16" y="56" fill="#f59e0b" font-size="24" font-weight="700">{linux:,}</text>
      <text x="16" y="74" fill="#64748b" font-size="10">ELF / SO binaries</text>
    </g>

    <g transform="translate(960, 0)">
      <rect width="176" height="88" rx="8" fill="url(#cardBg)" stroke="#1e293b" stroke-width="1" filter="url(#cardShadow)"/>
      <text x="16" y="24" fill="#94a3b8" font-size="11" font-weight="600">NON-PE / SCRIPTS</text>
      <text x="16" y="56" fill="#a855f7" font-size="24" font-weight="700">{non_pe:,}</text>
      <text x="16" y="74" fill="#64748b" font-size="10">PowerShell / Py / Sh</text>
    </g>
  </g>

  <g transform="translate(32, 236)">
    <rect x="0" y="0" width="554" height="176" rx="8" fill="url(#cardBg)" stroke="#1e293b" stroke-width="1"/>
    <text x="18" y="24" fill="#ffffff" font-size="13" font-weight="600">Top Triggered YARA Rules</text>
{rule_bars}

    <g transform="translate(582, 0)">
      <rect x="0" y="0" width="554" height="176" rx="8" fill="url(#cardBg)" stroke="#1e293b" stroke-width="1"/>
      <text x="18" y="24" fill="#ffffff" font-size="13" font-weight="600">Detection History Timeline</text>

      <path d="M 30 140 Q 120 135, 180 110 T 320 80 T 420 50 T 520 65 L 520 150 L 30 150 Z" fill="url(#chartLine)"/>
      <path d="M 30 140 Q 120 135, 180 110 T 320 80 T 420 50 T 520 65" fill="none" stroke="#10b981" stroke-width="2.5"/>
      <circle cx="500" cy="65" r="4" fill="#10b981" stroke="#ffffff" stroke-width="2"/>
      <text x="500" y="55" text-anchor="middle" fill="#10b981" font-size="10" font-weight="700">Latest Run</text>

      <line x1="30" y1="150" x2="524" y2="150" stroke="#334155" stroke-dasharray="3 3"/>
      <text x="30" y="166" fill="#64748b" font-size="9">Aug 23</text>
      <text x="150" y="166" fill="#64748b" font-size="9">Aug 31</text>
      <text x="270" y="166" fill="#64748b" font-size="9">Sep 05</text>
      <text x="390" y="166" fill="#64748b" font-size="9">Sep 11</text>
      <text x="490" y="166" fill="#64748b" font-size="9">Sep 16</text>
    </g>
  </g>

  <g transform="translate(32, 430)">
    <rect x="0" y="0" width="1136" height="236" rx="8" fill="url(#cardBg)" stroke="#1e293b" stroke-width="1"/>
    
    <text x="18" y="24" fill="#ffffff" font-size="13" font-weight="600">Positive Detections Log ({hits_count} hits recorded)</text>

    <rect x="18" y="38" width="1100" height="28" fill="#111827" rx="4"/>
    <text x="32" y="56" fill="#64748b" font-size="10" font-weight="600">DETECTED AT</text>
    <text x="150" y="56" fill="#64748b" font-size="10" font-weight="600">PLATFORM</text>
    <text x="250" y="56" fill="#64748b" font-size="10" font-weight="600">YARA RULE</text>
    <text x="500" y="56" fill="#64748b" font-size="10" font-weight="600">SOURCE FEED</text>
    <text x="640" y="56" fill="#64748b" font-size="10" font-weight="600">SAMPLE SHA256</text>
    <text x="800" y="56" fill="#64748b" font-size="10" font-weight="600">VT RATIO</text>
    <text x="900" y="56" fill="#64748b" font-size="10" font-weight="600">THREAT LABEL</text>
    <text x="1050" y="56" fill="#64748b" font-size="10" font-weight="600">ACTION</text>
{rows_svg}

    <text x="568" y="215" text-anchor="middle" fill="#38bdf8" font-size="11" font-weight="600">Click to explore the full interactive dashboard on GitHub Pages &gt;&gt;</text>
  </g>
</svg>"""

            preview_file = assets_dir / "dashboard_preview.svg"
            with open(preview_file, "w", encoding="utf-8") as f:
                f.write(svg_content)
        except Exception as e:
            print(f"[!] Warning: Failed to generate dashboard_preview.svg: {e}")

    def generate_dashboard_data(self, stats: Dict[str, Any], all_hits: List[Dict[str, Any]]) -> None:
        """Outputs data.js for zero-CORS browser dashboard viewing."""
        try:
            root_dir = self.hits_file.parent.parent
            dashboard_dir = root_dir / "dashboard"
            dashboard_dir.mkdir(parents=True, exist_ok=True)
            
            payload = {
                "stats": stats,
                "hits": all_hits
            }
            js_content = f"window.YARAFY_DATA = {json.dumps(payload, indent=2)};\n"
            with open(dashboard_dir / "data.js", "w", encoding="utf-8") as f:
                f.write(js_content)
        except Exception as e:
            print(f"[!] Warning: Failed to write dashboard data.js: {e}")

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
