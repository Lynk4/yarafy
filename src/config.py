import os
from pathlib import Path
from typing import Any, Dict, List
import yaml
from dotenv import load_dotenv

# Project root is the parent directory of src/
PROJECT_ROOT = Path(__file__).resolve().parent.parent

# Load .env file if present
load_dotenv(PROJECT_ROOT / ".env")


class Config:
    def __init__(self, config_path: Path = None):
        if config_path is None:
            config_path = PROJECT_ROOT / "config.yaml"
        
        self.config_path = config_path
        self._raw_config = self._load_config()

    def _load_config(self) -> Dict[str, Any]:
        if not self.config_path.exists():
            return {}
        with open(self.config_path, "r", encoding="utf-8") as f:
            return yaml.safe_load(f) or {}

    @property
    def rules_dir(self) -> Path:
        rel_path = self._raw_config.get("rules_dir", "yara-rules")
        return PROJECT_ROOT / rel_path

    @property
    def active_platforms(self) -> List[str]:
        return self._raw_config.get("active_platforms", ["macos"])

    @property
    def malwarebazaar_config(self) -> Dict[str, Any]:
        return self._raw_config.get("malwarebazaar", {})

    @property
    def malwarebazaar_api_key(self) -> str:
        return os.getenv("MALWAREBAZAAR_API_KEY", "").strip()

    @property
    def virustotal_config(self) -> Dict[str, Any]:
        return self._raw_config.get("virustotal", {})

    @property
    def virustotal_api_key(self) -> str:
        return os.getenv("VT_API_KEY", "").strip()

    @property
    def virustotal_enterprise_api_key(self) -> str:
        return os.getenv("VT_ENTERPRISE_API_KEY", "").strip() or self.virustotal_api_key

    @property
    def webhook_url(self) -> str:
        return os.getenv("ALERT_WEBHOOK_URL", "").strip()

    @property
    def telemetry_config(self) -> Dict[str, Any]:
        return self._raw_config.get("telemetry", {})

    @property
    def hits_file(self) -> Path:
        rel = self.telemetry_config.get("hits_file", "telemetry/hits.json")
        return PROJECT_ROOT / rel

    @property
    def stats_file(self) -> Path:
        rel = self.telemetry_config.get("stats_file", "telemetry/stats.json")
        return PROJECT_ROOT / rel

    @property
    def report_file(self) -> Path:
        rel = self.telemetry_config.get("report_file", "telemetry/LATEST_REPORT.md")
        return PROJECT_ROOT / rel


# Singleton instance
settings = Config()
