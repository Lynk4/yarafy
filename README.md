# Yarafy

**Yarafy** is an automated YARA rule management, threat hunting, and telemetry visualization pipeline. It enables security researchers and threat hunters to store YARA rules across **macOS**, **Windows**, **Linux**, and **Non-PE / Script** platforms, hunt against live feeds from **MalwareBazaar** and **VirusTotal Intelligence**, enrich hits, record detection telemetry, and explore insights through an interactive cyber dashboard.

---

## Repository Structure

```text
yarafy/
├── yara-rules/                   # YARA Rules Repository
│   ├── macos/                    # macOS rules (Mach-O, DMG, PKG, Plists, scripts)
│   ├── windows/                  # Windows rules (PE, DLL, .NET, MSI)
│   ├── linux/                    # Linux rules (ELF binaries, shared libraries)
│   └── non-pe/                   # Scripts (PowerShell, Python, Bash, VBS)
├── dashboard/                    # Interactive Visual Dashboard
│   ├── index.html                # Single-page SOC analytics dashboard
│   └── data.js                   # Pre-compiled offline telemetry data
├── telemetry/                    # Telemetry and Hit Logs
│   ├── hits.json                 # Historical match database (deduplicated)
│   ├── stats.json                # Aggregate metrics & detection counts
│   └── LATEST_REPORT.md          # Generated markdown summary
├── src/                          # Core Engine
│   ├── collector.py              # MalwareBazaar API client & sample downloader
│   ├── vt_hunter.py              # VirusTotal live sample downloader
│   ├── scanner.py                # YARA compiler & multi-file scanner
│   ├── enricher.py               # VirusTotal API v3 enricher
│   ├── reporter.py               # Telemetry aggregator & report generator
│   ├── config.py                 # Configuration manager
│   └── main.py                   # CLI entrypoint
├── .github/workflows/
│   ├── yara_lint.yml             # CI syntax testing on pull requests / commits
│   ├── hunt_feed.yml             # Scheduled MalwareBazaar background hunting workflow
│   ├── vt_hunt_macos.yml         # Manual VirusTotal hunt for macOS
│   ├── vt_hunt_windows.yml       # Manual VirusTotal hunt for Windows
│   ├── vt_hunt_linux.yml         # Manual VirusTotal hunt for Linux
│   └── vt_hunt_non_pe.yml        # Manual VirusTotal hunt for Non-PE / Scripts
├── config.yaml                   # Hunting settings & platform configurations
├── requirements.txt              # Dependencies
└── .env.example                  # API Key template
```

---

## Quickstart

### 1. Installation

```bash
# Create and activate virtual environment
python3 -m venv venv
source venv/bin/activate

# Install dependencies
pip install -r requirements.txt
```

### 2. Configure API Keys

Copy `.env.example` to `.env`:
```bash
cp .env.example .env
```
Fill in your API keys:
- `MALWAREBAZAAR_API_KEY`: Obtain free from [MalwareBazaar](https://bazaar.abuse.ch/api/).
- `VT_API_KEY`: Free [VirusTotal Key](https://www.virustotal.com/gui/my-apikey) for routine hash lookups.
- `VT_ENTERPRISE_API_KEY`: Company/Paid VirusTotal Key for on-demand live binary downloading.

---

## Interactive Telemetry Dashboard

Launch the local visual dashboard in your default browser:

```bash
python -m src.main dashboard
```

- Accessible at: `http://localhost:8080/dashboard/`
- **Metrics**: Total throughput, positive detections, hit rates, and platform breakdown.
- **Visualizations**: Detections by Platform, Source Feed comparison (MalwareBazaar vs VirusTotal Enterprise), Top Rules, and Detection History Timeline.
- **Filters**: Platform tabs (macOS, Windows, Linux, Non-PE), Feed filters, and live keyword search.
- **Inspection Drawer**: View matched YARA strings, hex offsets, hashes, and Antivirus engine detection labels.
- **Exporting**: Export filtered telemetry to JSON or CSV with one click.

---

## CLI Commands

### 1. Validate & Lint Rules
Validates that all rules in `yara-rules/` compile without syntax errors:
```bash
python -m src.main lint
```

### 2. Run MalwareBazaar Feed Hunt
Fetches recent samples across all enabled platforms (`macos`, `windows`, `linux`, `non-pe`), scans them, and updates telemetry:
```bash
python -m src.main hunt --limit 25
```

### 3. Run VirusTotal Live Sample Hunt
Searches VirusTotal Intelligence, downloads live binaries, and scans them against your rules:
```bash
# macOS Live Hunt
python -m src.main vt-hunt --platform macos --query "type:macho positives:5+ fs:30d+" --limit 10

# Windows Live Hunt
python -m src.main vt-hunt --platform windows --query "type:peexe positives:10+ fs:30d+" --limit 10

# Linux Live Hunt
python -m src.main vt-hunt --platform linux --query "type:elf positives:5+ fs:30d+" --limit 10

# Non-PE / Scripts Live Hunt
python -m src.main vt-hunt --platform non-pe --query "(type:powershell OR type:script OR type:python) positives:5+ fs:30d+" --limit 10
```

### 4. Scan Local File or Folder
Test your rules against local samples or directories:
```bash
python -m src.main scan-local /path/to/suspicious/folder/
```

### 5. View Telemetry Stats in Terminal
```bash
python -m src.main stats
```

---

## GitHub Actions Workflows

| Workflow | Type | Description |
| :--- | :--- | :--- |
| **Automated Feed Hunt & Telemetry** | Scheduled (6h) / Manual | Scans MalwareBazaar feeds across active platforms. |
| **VirusTotal Hunt - macOS** | Manual (`workflow_dispatch`) | Downloads and scans live macOS Mach-O/DMG samples from VT. |
| **VirusTotal Hunt - Windows** | Manual (`workflow_dispatch`) | Downloads and scans live Windows PE/DLL samples from VT. |
| **VirusTotal Hunt - Linux** | Manual (`workflow_dispatch`) | Downloads and scans live Linux ELF samples from VT. |
| **VirusTotal Hunt - Non-PE & Scripts** | Manual (`workflow_dispatch`) | Downloads and scans live scripts (PowerShell, Python, Bash) from VT. |
| **YARA Rule Lint & Test** | CI (Push/PR) | Validates rule syntax before code is merged. |
