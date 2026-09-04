import argparse
import sys
from pathlib import Path
from typing import List
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from src.collector import MalwareBazaarCollector
from src.config import settings
from src.enricher import VirusTotalEnricher
from src.reporter import TelemetryReporter
from src.scanner import YaraScanner
from src.vt_hunter import VirusTotalHunter

console = Console()


def cmd_lint(args: argparse.Namespace) -> int:
    """Validate all YARA rules for syntax errors."""
    console.print(Panel("[bold blue]Validating YARA Rules[/bold blue]"))
    scanner = YaraScanner(
        rules_root=settings.rules_dir,
        active_platforms=settings.active_platforms,
    )

    total_files = sum(len(files) for files in scanner.rule_files.values())
    console.print(f"[*] Found [cyan]{total_files}[/cyan] rule file(s) across platforms: {', '.join(scanner.active_platforms)}")

    valid, errors = scanner.validate_rules()
    if valid:
        console.print("[bold green]All YARA rules compiled and validated successfully![/bold green]")
        return 0
    else:
        console.print("[bold red]Syntax errors found in YARA rules:[/bold red]")
        for err in errors:
            console.print(f"  * [red]{err}[/red]")
        return 1


def cmd_scan_local(args: argparse.Namespace) -> int:
    """Scan a local file or directory."""
    target = Path(args.target)
    if not target.exists():
        console.print(f"[bold red]Target path not found: {target}[/bold red]")
        return 1

    scanner = YaraScanner(
        rules_root=settings.rules_dir,
        active_platforms=settings.active_platforms,
    )
    scanner.compile()

    console.print(f"[bold blue]Scanning {target}...[/bold blue]")

    files_to_scan = [target] if target.is_file() else [p for p in target.rglob("*") if p.is_file()]
    all_hits = []

    for f in files_to_scan:
        hits = scanner.scan_file(f)
        if hits:
            all_hits.extend(hits)
            for h in hits:
                console.print(f"[bold red]HIT:[/bold red] Rule [cyan]{h['rule_name']}[/cyan] matched in [yellow]{f.name}[/yellow]")

    console.print(f"\n[bold green]Scan complete. {len(files_to_scan)} files scanned, {len(all_hits)} hits found.[/bold green]")
    return 0


def cmd_hunt(args: argparse.Namespace) -> int:
    """Execute live hunting against MalwareBazaar + VirusTotal enrichment + telemetry logging."""
    console.print(Panel("[bold magenta]Starting Yarafy Feed Hunting Workflow[/bold magenta]"))

    # 1. Initialize Scanner
    scanner = YaraScanner(
        rules_root=settings.rules_dir,
        active_platforms=settings.active_platforms,
    )
    valid, errors = scanner.validate_rules()
    if not valid:
        console.print("[bold red]Cannot proceed with hunt: YARA syntax errors detected.[/bold red]")
        for err in errors:
            console.print(f"  * {err}")
        return 1

    scanner.compile()
    console.print(f"[*] Compiled rules for active platforms: [bold cyan]{', '.join(settings.active_platforms)}[/bold cyan]")

    # 2. Initialize Collector & Reporter
    collector = MalwareBazaarCollector(api_key=settings.malwarebazaar_api_key)
    vt_enricher = VirusTotalEnricher(
        api_key=settings.virustotal_api_key,
        rate_limit_seconds=settings.virustotal_config.get("rate_limit_seconds", 15.0),
    )
    reporter = TelemetryReporter(
        hits_file=settings.hits_file,
        stats_file=settings.stats_file,
        report_file=settings.report_file,
        webhook_url=settings.webhook_url,
    )

    # 3. Collect Samples for Active Platforms
    mb_cfg = settings.malwarebazaar_config
    total_samples_meta = []

    for platform in settings.active_platforms:
        file_types = mb_cfg.get("platform_file_types", {}).get(platform, [])
        tags = mb_cfg.get("platform_tags", {}).get(platform, [])
        console.print(f"[*] Querying MalwareBazaar for [yellow]{platform}[/yellow] (Types: {file_types}, Tags: {tags[:3]}...)")
        
        samples = collector.query_platform_samples(
            platform=platform,
            file_types=file_types,
            tags=tags,
            limit_per_query=args.limit or mb_cfg.get("limit", 25),
        )
        total_samples_meta.extend(samples)

    # Deduplicate
    unique_samples = {s["sha256_hash"]: s for s in total_samples_meta if "sha256_hash" in s}
    sample_list = list(unique_samples.values())
    console.print(f"[bold green]Retrieved {len(sample_list)} unique candidate samples to scan.[/bold green]")

    if not sample_list:
        console.print("[yellow]No new samples returned from feed queries.[/yellow]")
        reporter.record_run(0, [], settings.active_platforms)
        return 0

    # 4. Download and Scan Samples
    matched_hits = []
    scanned_count = 0

    for i, s_meta in enumerate(sample_list, 1):
        sha256 = s_meta["sha256_hash"]
        fname = s_meta.get("file_name") or "sample.bin"
        console.print(f"[{i}/{len(sample_list)}] Downloading & scanning {sha256[:12]}... ({fname})")

        dl_res = collector.download_sample_bytes(sha256)
        if not dl_res:
            continue

        sample_name, sample_bytes = dl_res
        scanned_count += 1

        hits = scanner.scan_data(sample_bytes, sample_name=sample_name)
        if hits:
            for hit in hits:
                console.print(f"  [bold red]MATCH DETECTED![/bold red] Rule: [bold yellow]{hit['rule_name']}[/bold yellow]")
                hit["source_feed"] = "MalwareBazaar"
                # Attach MalwareBazaar metadata
                hit["mb_metadata"] = {
                    "first_seen": s_meta.get("first_seen"),
                    "file_type": s_meta.get("file_type"),
                    "signature": s_meta.get("signature"),
                    "tags": s_meta.get("tags", []),
                }

                # 5. Enrich with VirusTotal
                if settings.virustotal_config.get("enabled", True):
                    console.print(f"  [cyan]Querying VirusTotal for hash {sha256[:12]}...[/cyan]")
                    vt_data = vt_enricher.lookup_hash(sha256)
                    hit["vt_enrichment"] = vt_data
                    if vt_data.get("vt_status") == "success":
                        console.print(f"  [green]VT Detections: {vt_data.get('detection_ratio')} | Label: {vt_data.get('suggested_threat_label')}[/green]")

                matched_hits.append(hit)

    # 6. Record Telemetry
    stats = reporter.record_run(scanned_count, matched_hits, settings.active_platforms)
    console.print(Panel(
        f"[bold green]Hunt Complete![/bold green]\n"
        f"* Samples Downloaded & Scanned: [cyan]{scanned_count}[/cyan]\n"
        f"* Positive Hits in this run: [bold red]{len(matched_hits)}[/bold red]\n"
        f"* Total Lifetime Hits: [bold yellow]{stats['total_hits']}[/bold yellow]\n"
        f"* Report saved to: [magenta]{settings.report_file}[/magenta]"
    ))

    return 0


def cmd_vt_hunt(args: argparse.Namespace) -> int:
    """Download and scan live malware samples directly from VirusTotal Intelligence."""
    console.print(Panel("[bold cyan]Starting VirusTotal Live Sample Hunting Workflow[/bold cyan]"))

    vt_key = settings.virustotal_enterprise_api_key
    if not vt_key:
        console.print("[bold red]VT_ENTERPRISE_API_KEY (or VT_API_KEY) is not set. Please add your VirusTotal API key to .env or GitHub Secrets.[/bold red]")
        return 1

    target_platform = getattr(args, "platform", "macos") or "macos"
    default_queries = {
        "macos": "type:macho positives:5+ fs:30d+",
        "windows": "type:peexe positives:10+ fs:30d+",
        "linux": "type:elf positives:5+ fs:30d+",
        "non-pe": "(type:powershell OR type:script OR type:python OR type:javascript) positives:5+ fs:30d+",
        "all": "positives:10+ fs:30d+",
    }
    query = args.query or default_queries.get(target_platform, "type:macho positives:5+ fs:30d+")
    limit = args.limit or 10

    # 1. Initialize Scanner
    scanner = YaraScanner(
        rules_root=settings.rules_dir,
        active_platforms=settings.active_platforms,
    )
    valid, errors = scanner.validate_rules()
    if not valid:
        console.print("[bold red]Cannot proceed: YARA syntax errors detected.[/bold red]")
        return 1

    scanner.compile()
    console.print(f"[*] Compiled rules for active platforms: [bold cyan]{', '.join(settings.active_platforms)}[/bold cyan]")

    # 2. Initialize VT Hunter & Reporter
    vt_hunter = VirusTotalHunter(
        api_key=vt_key,
        rate_limit_seconds=settings.virustotal_config.get("rate_limit_seconds", 1.0),
    )
    reporter = TelemetryReporter(
        hits_file=settings.hits_file,
        stats_file=settings.stats_file,
        report_file=settings.report_file,
        webhook_url=settings.webhook_url,
    )

    console.print(f"[*] Target Platform: [bold green]{target_platform.upper()}[/bold green]")
    console.print(f"[*] Querying VirusTotal Intelligence: [yellow]{query}[/yellow] (Limit: {limit})")

    candidates = vt_hunter.search_intelligence(query=query, limit=limit)
    if not candidates:
        console.print("[yellow]No samples returned from VirusTotal query or query was rejected.[/yellow]")
        return 0

    console.print(f"[bold green]Retrieved {len(candidates)} candidate sample(s) from VirusTotal.[/bold green]")

    matched_hits = []
    scanned_count = 0

    for i, c_meta in enumerate(candidates, 1):
        sha256 = c_meta["sha256"]
        names = c_meta.get("names", ["sample.bin"])
        fname = names[0] if names else "sample.bin"
        console.print(f"[{i}/{len(candidates)}] Downloading & scanning {sha256[:12]}... ({fname})")

        dl_res = vt_hunter.download_sample_bytes(sha256)
        if not dl_res:
            continue

        sample_name, sample_bytes = dl_res
        scanned_count += 1

        hits = scanner.scan_data(sample_bytes, sample_name=sample_name)
        if hits:
            for hit in hits:
                console.print(f"  [bold red]MATCH DETECTED![/bold red] Rule: [bold yellow]{hit['rule_name']}[/bold yellow]")
                hit["platform"] = target_platform if target_platform != "all" else hit.get("namespace", "").split("_")[0]
                hit["source_feed"] = "VirusTotal Enterprise"
                hit["vt_enrichment"] = {
                    "vt_status": "success",
                    "positives": c_meta.get("positives", 0),
                    "total_engines": c_meta.get("total_engines", 0),
                    "detection_ratio": c_meta.get("detection_ratio", "N/A"),
                    "suggested_threat_label": c_meta.get("suggested_threat_label", "unknown"),
                    "names": c_meta.get("names", []),
                    "tags": c_meta.get("tags", []),
                    "vt_permalink": f"https://www.virustotal.com/gui/file/{sha256}",
                }
                matched_hits.append(hit)

    # Record Telemetry
    stats = reporter.record_run(scanned_count, matched_hits, settings.active_platforms)
    console.print(Panel(
        f"[bold green]VirusTotal Hunt Complete![/bold green]\n"
        f"* Platform: [cyan]{target_platform.upper()}[/cyan]\n"
        f"* Samples Downloaded & Scanned from VT: [cyan]{scanned_count}[/cyan]\n"
        f"* Positive Hits in this run: [bold red]{len(matched_hits)}[/bold red]\n"
        f"* Total Lifetime Hits: [bold yellow]{stats['total_hits']}[/bold yellow]\n"
        f"* Report saved to: [magenta]{settings.report_file}[/magenta]"
    ))

    return 0


def cmd_dashboard(args: argparse.Namespace) -> int:
    """Launch interactive telemetry visualization dashboard in browser."""
    import http.server
    import socketserver
    import webbrowser
    from src.config import PROJECT_ROOT

    reporter = TelemetryReporter(
        hits_file=settings.hits_file,
        stats_file=settings.stats_file,
        report_file=settings.report_file,
    )
    stats = reporter.load_stats()
    hits = reporter.load_hits()
    reporter.generate_dashboard_data(stats, hits)

    port = getattr(args, "port", 8080) or 8080
    dashboard_url = f"http://localhost:{port}/dashboard/"

    console.print(Panel(
        f"[bold blue]Yarafy Telemetry Dashboard[/bold blue]\n\n"
        f"Serving dashboard at: [bold cyan]{dashboard_url}[/bold cyan]\n"
        f"Press [bold red]Ctrl+C[/bold red] to stop server."
    ))

    os.chdir(PROJECT_ROOT)
    handler = http.server.SimpleHTTPRequestHandler

    class SilentServer(socketserver.TCPServer):
        allow_reuse_address = True

    try:
        with SilentServer(("", port), handler) as httpd:
            webbrowser.open(dashboard_url)
            httpd.serve_forever()
    except KeyboardInterrupt:
        console.print("\n[bold yellow]Dashboard server stopped.[/bold yellow]")
        return 0
    except Exception as e:
        console.print(f"[bold red]Error starting dashboard server: {e}[/bold red]")
        return 1


def cmd_stats(args: argparse.Namespace) -> int:
    """Display current telemetry stats."""
    reporter = TelemetryReporter(
        hits_file=settings.hits_file,
        stats_file=settings.stats_file,
        report_file=settings.report_file,
    )
    stats = reporter.load_stats()
    hits = reporter.load_hits()

    table = Table(title="Yarafy Telemetry Overview")
    table.add_column("Metric", style="cyan")
    table.add_column("Value", style="yellow")

    table.add_row("Total Scanned Samples", str(stats.get("total_scanned", 0)))
    table.add_row("Total Hits Recorded", str(stats.get("total_hits", 0)))
    table.add_row("Last Run Timestamp", str(stats.get("last_run", "N/A")))

    console.print(table)

    if stats.get("hits_by_source"):
        src_table = Table(title="Hits by Source Feed")
        src_table.add_column("Source Feed", style="blue")
        src_table.add_column("Detections", style="green")
        for s, c in sorted(stats["hits_by_source"].items(), key=lambda x: x[1], reverse=True):
            src_table.add_row(s, str(c))
        console.print(src_table)

    if stats.get("hits_by_rule"):
        rule_table = Table(title="Hits by YARA Rule")
        rule_table.add_column("Rule Name", style="magenta")
        rule_table.add_column("Detections", style="green")
        for r, c in sorted(stats["hits_by_rule"].items(), key=lambda x: x[1], reverse=True):
            rule_table.add_row(r, str(c))
        console.print(rule_table)

    return 0


def main():
    parser = argparse.ArgumentParser(
        prog="yarafy",
        description="Automated YARA Hunting & Telemetry Pipeline",
    )
    subparsers = parser.add_subparsers(dest="command", help="Available commands")

    # Lint
    subparsers.add_parser("lint", help="Validate and test YARA rules for syntax errors")

    # Hunt (MalwareBazaar)
    hunt_parser = subparsers.add_parser("hunt", help="Execute hunting against MalwareBazaar")
    hunt_parser.add_argument("--limit", type=int, default=25, help="Number of samples to fetch per query")

    # VT Hunt (VirusTotal Live Sample Download & Scan)
    vt_parser = subparsers.add_parser("vt-hunt", help="Search, download, and scan live samples directly from VirusTotal")
    vt_parser.add_argument("--platform", type=str, default="macos", choices=["macos", "windows", "linux", "non-pe", "all"], help="Target platform (macos, windows, linux, non-pe, all)")
    vt_parser.add_argument("--query", type=str, default=None, help="VirusTotal search query (defaults to platform-specific query)")
    vt_parser.add_argument("--limit", type=int, default=10, help="Max number of samples to download & scan")

    # Dashboard
    dash_parser = subparsers.add_parser("dashboard", help="Launch interactive telemetry visualization dashboard in browser")
    dash_parser.add_argument("--port", type=int, default=8080, help="Port for local web server (default: 8080)")

    # Local scan
    scan_parser = subparsers.add_parser("scan-local", help="Scan a local file or folder with YARA rules")
    scan_parser.add_argument("target", help="Path to local file or directory to scan")

    # Stats
    subparsers.add_parser("stats", help="Display telemetry statistics")

    args = parser.parse_args()
    if not args.command:
        parser.print_help()
        sys.exit(0)

    if args.command == "lint":
        sys.exit(cmd_lint(args))
    elif args.command == "hunt":
        sys.exit(cmd_hunt(args))
    elif args.command == "vt-hunt":
        sys.exit(cmd_vt_hunt(args))
    elif args.command == "dashboard":
        sys.exit(cmd_dashboard(args))
    elif args.command == "scan-local":
        sys.exit(cmd_scan_local(args))
    elif args.command == "stats":
        sys.exit(cmd_stats(args))


if __name__ == "__main__":
    main()
