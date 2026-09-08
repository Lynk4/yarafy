# Yarafy

**Yarafy** is an automated YARA rule management, threat hunting, and telemetry visualization pipeline. It enables security researchers and threat hunters to store YARA rules across **macOS**, **Windows**, **Linux**, and **Non-PE / Script** platforms, hunt against live malware feeds from **MalwareBazaar**, enrich positive detections using VirusTotal, record continuous detection telemetry, and explore insights through an interactive cyber dashboard.

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
│   ├── scanner.py                # YARA compiler & multi-file scanner
│   ├── enricher.py               # VirusTotal API v3 enricher (free tier compliant)
│   ├── reporter.py               # Telemetry aggregator & report generator
│   ├── config.py                 # Configuration manager
│   └── main.py                   # CLI entrypoint
├── .github/workflows/
│   ├── yara_lint.yml             # CI syntax testing on pull requests / commits
│   └── hunt_feed.yml             # Scheduled MalwareBazaar background hunting workflow
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
- `MALWAREBAZAAR_API_KEY`: Obtain free from [MalwareBazaar](https://bazaar.abuse.ch/api/) for sample downloads.
- `VT_API_KEY`: Free [VirusTotal API Key](https://www.virustotal.com/gui/my-apikey) for routine hash lookup and enrichment when hits are detected.
- `ALERT_WEBHOOK_URL`: (Optional) Discord or Slack webhook URL to receive notifications on hits.

---

## Interactive Telemetry Dashboard

### 1. View Live on GitHub Pages
Your dashboard can be viewed live in the browser without running anything locally:

- **Live Dashboard URL**: `https://lynk4.github.io/yarafy/`

> [!NOTE]
> To enable GitHub Pages hosting:
> 1. In your GitHub repository, go to **Settings** -> **Pages**.
> 2. Under **Build and deployment** -> **Source**, choose **GitHub Actions**.
> 3. The dashboard will automatically deploy whenever new telemetry is recorded!

### 2. Launch Locally from Terminal
Run the local visual dashboard in your default browser:

```bash
python -m src.main dashboard
```

- Accessible locally at: `http://localhost:8080/dashboard/`
- **Metrics**: Total scanned throughput, positive detections, hit rates, and platform breakdown.
- **Visualizations**: Detections by Platform, Source Feed comparison, Top YARA Rules, and Detection History Timeline.
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

### 2. Run Targeted MalwareBazaar Feed Hunt
Search and download samples by specific platform, tags, file types, or family signatures:
```bash
# macOS Hunt: Target AMOS & ClickFix Mach-O samples
python -m src.main hunt --platform macos --tags "AMOS,ClickFix,AtomicStealer" --file-type macho --limit 25

# Windows Hunt: Target Lumma & RedLine PE executables
python -m src.main hunt --platform windows --tags "Lumma,RedLine,Stealer" --file-type exe --limit 25

# Linux Hunt: Target Mirai & Kinsing ELF binaries
python -m src.main hunt --platform linux --tags "Mirai,Kinsing,Linux" --file-type elf --limit 25

# Non-PE / Scripts Hunt: Target PowerShell & Python payloads
python -m src.main hunt --platform non-pe --tags "PowerShell,Python,script" --file-type script --limit 25

# Multi-Platform Hunt: Run across all active platforms with config defaults
python -m src.main hunt --platform all --limit 25
```

### 3. Launch Telemetry Dashboard
Launches the interactive dashboard in your browser:
```bash
python -m src.main dashboard
```

### 4. Refresh Historical VirusTotal Scores
Re-queries VirusTotal for past hits to update their AV detection scores and threat labels:
```bash
# Refresh samples with 0 detections or unverified statuses
python -m src.main refresh-vt --mode zero-only --limit 20

# Refresh all historical samples
python -m src.main refresh-vt --mode all --limit 20
```

### 5. Scan Local File or Folder
Test your rules against local samples or directories:
```bash
python -m src.main scan-local /path/to/suspicious/folder/
```

### 6. View Telemetry Stats in Terminal
```bash
python -m src.main stats
```

---

## GitHub Actions Workflows

All hunting workflows are strictly manual (`workflow_dispatch`) with no scheduled auto-runs:

| Workflow | Type | Description |
| :--- | :--- | :--- |
| **MalwareBazaar Hunt - macOS** | Manual | Targeted macOS search with tag, file type, and limit inputs. |
| **MalwareBazaar Hunt - Windows** | Manual | Targeted Windows search with tag, file type, and limit inputs. |
| **MalwareBazaar Hunt - Linux** | Manual | Targeted Linux search with tag, file type, and limit inputs. |
| **MalwareBazaar Hunt - Non-PE & Scripts** | Manual | Targeted script/non-PE search with tag, file type, and limit inputs. |
| **MalwareBazaar Hunt - All Platforms** | Manual | Executes hunting across all active platforms simultaneously. |
| **Refresh VirusTotal Scores** | Manual | Re-checks past hits on VT to update AV scores and threat labels. |
| **Deploy Dashboard to GitHub Pages** | Push / Manual | Builds and deploys the web dashboard to GitHub Pages. |
| **YARA Rule Lint & Test** | CI (Push/PR) | Validates rule syntax before code is merged. |
