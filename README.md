# Yarafy

**Yarafy** is an automated YARA rule management, threat hunting, and telemetry pipeline. It enables security researchers and threat hunters to write and store YARA rules (starting with **macOS** Mach-O/DMG/scripts, and extensible to **Windows**, **Linux**, and **non-PE** files), automatically hunt against live malware feeds on **MalwareBazaar**, enrich positive hits using **VirusTotal**, and record continuous detection telemetry.

---

## Repository Structure

```text
yarafy/
├── yara-rules/                   # YARA Rules Repository
│   ├── macos/                    # macOS rules (Mach-O, DMG, PKG, Plists, scripts)
│   │   ├── MALW_macOS_MacSync_Stealer.yar
│   │   ├── OSX_Stealer_AMOS_Generic.yar
│   │   └── macOS_ClickFix_AppleScript.yar
│   ├── windows/                  # Windows rules (PE, DLL, .NET, PowerShell)
│   ├── linux/                    # Linux rules (ELF, shell scripts)
│   └── non-pe/                   # Scripting & document payloads
├── telemetry/                    # Telemetry and Hit Logs
│   ├── hits.json                 # Historical match database (deduplicated)
│   ├── stats.json                # Aggregate metrics & detection counts
│   └── LATEST_REPORT.md          # Generated markdown summary
├── src/                          # Core Engine
│   ├── collector.py              # MalwareBazaar API client & sample downloader
│   ├── scanner.py                # YARA compiler & multi-file scanner
│   ├── enricher.py               # VirusTotal API v3 enricher (rate-limited)
│   ├── reporter.py               # Telemetry aggregator & report generator
│   ├── config.py                 # Configuration manager
│   └── main.py                   # CLI entrypoint
├── .github/workflows/
│   ├── yara_lint.yml             # CI syntax testing on pull requests / commits
│   └── hunt_feed.yml             # Scheduled GitHub Action hunting workflow
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

### 2. Configure API Keys (Optional but Recommended)

Copy `.env.example` to `.env`:
```bash
cp .env.example .env
```
Fill in your API keys:
- `MALWAREBAZAAR_API_KEY`: Obtain free from [MalwareBazaar](https://bazaar.abuse.ch/api/).
- `VT_API_KEY`: Obtain from your free [VirusTotal Account](https://www.virustotal.com/gui/my-apikey).
- `ALERT_WEBHOOK_URL`: (Optional) Discord or Slack webhook URL.

---

## CLI Commands

### 1. Validate & Lint Rules
Validates that all rules in `yara-rules/` compile without syntax errors:
```bash
python -m src.main lint
```

### 2. Run MalwareBazaar Feed Hunt
Fetches recent macOS samples from MalwareBazaar, scans them with your rules, and updates telemetry:
```bash
python -m src.main hunt --limit 25
```

### 3. Run VirusTotal Live Sample Hunt
Searches VirusTotal Intelligence, downloads live samples using your VT API key, and scans them against your rules:
```bash
# Search and download 10 recent macOS Mach-O samples from VT
python -m src.main vt-hunt --query "type:macho positives:5+ fs:30d+" --limit 10

# Search for specific threat campaigns
python -m src.main vt-hunt --query "type:macho tag:stealer" --limit 5
```

### 4. Scan Local File or Folder
Test your rules against local samples or directories:
```bash
python -m src.main scan-local /path/to/suspicious/folder/
```

### 5. View Telemetry Stats
```bash
python -m src.main stats
```

---

## GitHub Actions Automation

The repository includes 3 workflows:

1. **`yara_lint.yml`**: Automatically verifies syntax on every push or PR modifying any rule in `yara-rules/`.
2. **`hunt_feed.yml`**: Runs on a **6-hour schedule** (and manual trigger), downloading free samples from MalwareBazaar and scanning them.
3. **`vt_hunt.yml`** *(Manual Trigger Only)*: Lets you search, download, and scan live binaries directly from **VirusTotal Intelligence** using your VT API key with customizable search queries and download limits.

### Adding GitHub Secrets
To enable hunting actions on GitHub:
1. Go to your repo on GitHub: **Settings > Secrets and variables > Actions**.
2. Add the following repository secrets:
   - `MALWAREBAZAAR_API_KEY` (Free API key from abuse.ch)
   - `VT_API_KEY` (VirusTotal API key)
   - `ALERT_WEBHOOK_URL` (Optional webhook)

---

## Adding New Rules

To add a new rule:
1. Navigate to the relevant platform folder (e.g. [`yara-rules/macos/`](yara-rules/macos/)).
2. Create a new `.yar` file.
3. Validate locally with:
   ```bash
   python -m src.main lint
   ```
4. Commit and push.

To enable **Windows**, **Linux**, or **Non-PE** platforms in the hunting feed:
Open [`config.yaml`](config.yaml) and add them to `active_platforms`:
```yaml
active_platforms:
  - "macos"
  - "windows"
  - "linux"
  - "non-pe"
```
