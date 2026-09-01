import time
from typing import Any, Dict, List, Optional, Tuple
import requests


class VirusTotalHunter:
    """Queries and downloads live malware samples using VirusTotal Intelligence / File APIs."""

    def __init__(self, api_key: str = "", rate_limit_seconds: float = 1.0):
        self.api_key = api_key
        self.rate_limit_seconds = rate_limit_seconds
        self.last_request_time = 0.0
        self.base_url = "https://www.virustotal.com/api/v3/"
        self.session = requests.Session()
        if self.api_key:
            self.session.headers.update({"x-apikey": self.api_key})

    def _wait_for_rate_limit(self) -> None:
        elapsed = time.time() - self.last_request_time
        if elapsed < self.rate_limit_seconds:
            time.sleep(self.rate_limit_seconds - elapsed)
        self.last_request_time = time.time()

    def search_intelligence(self, query: str, limit: int = 10) -> List[Dict[str, Any]]:
        """Search VirusTotal Intelligence for samples matching a query (e.g. 'type:macho positives:5+')."""
        if not self.api_key:
            print("[!] VT_API_KEY is not configured.")
            return []

        self._wait_for_rate_limit()
        url = f"{self.base_url}intelligence/search"
        params = {"query": query, "limit": min(limit, 40)}

        try:
            resp = self.session.get(url, params=params, timeout=30)
            if resp.status_code == 403:
                print("[!] VT Search 403 Forbidden: Ensure your VT API key has Intelligence / Search permissions.")
                return []
            if resp.status_code == 429:
                print("[!] VT API 429: Quota exceeded.")
                return []
            resp.raise_for_status()

            data = resp.json().get("data", [])
            results = []
            for item in data:
                attributes = item.get("attributes", {})
                sha256 = item.get("id") or attributes.get("sha256")
                stats = attributes.get("last_analysis_stats", {})
                malicious = stats.get("malicious", 0)
                suspicious = stats.get("suspicious", 0)
                total = sum(stats.values()) if stats else 0
                threat_class = attributes.get("popular_threat_classification", {})

                results.append({
                    "sha256": sha256,
                    "names": attributes.get("names", [])[:3],
                    "type_description": attributes.get("type_description", ""),
                    "size": attributes.get("size", 0),
                    "positives": malicious + suspicious,
                    "total_engines": total,
                    "detection_ratio": f"{malicious + suspicious}/{total}" if total else "0/0",
                    "suggested_threat_label": threat_class.get("suggested_threat_label", "unknown"),
                    "tags": attributes.get("tags", []),
                })
            return results[:limit]
        except requests.exceptions.RequestException as e:
            print(f"[!] VT Intelligence search failed: {e}")
            return []

    def download_sample_bytes(self, sha256_hash: str) -> Optional[Tuple[str, bytes]]:
        """Download binary sample from VirusTotal via /api/v3/files/{id}/download."""
        if not self.api_key:
            return None

        self._wait_for_rate_limit()
        url = f"{self.base_url}files/{sha256_hash}/download"

        try:
            resp = self.session.get(url, timeout=60)
            if resp.status_code == 403:
                print(f"[!] VT Download 403: API key does not have download permissions for {sha256_hash[:12]}.")
                return None
            if resp.status_code != 200 or len(resp.content) == 0:
                print(f"[!] VT Download failed with status {resp.status_code}")
                return None

            filename = f"{sha256_hash[:16]}.macho"
            return (filename, resp.content)
        except requests.exceptions.RequestException as e:
            print(f"[!] Failed to download sample {sha256_hash} from VT: {e}")
            return None
