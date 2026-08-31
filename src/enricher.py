import time
from typing import Any, Dict, Optional
import requests


class VirusTotalEnricher:
    """Enriches file hashes using VirusTotal API v3 with free-tier rate limiting."""

    def __init__(self, api_key: str = "", rate_limit_seconds: float = 15.0):
        self.api_key = api_key
        self.rate_limit_seconds = rate_limit_seconds
        self.last_request_time = 0.0
        self.base_url = "https://www.virustotal.com/api/v3/files/"
        self.session = requests.Session()
        if self.api_key:
            self.session.headers.update({"x-apikey": self.api_key})

    def _wait_for_rate_limit(self) -> None:
        """Enforces rate limiting (default 15 seconds for free tier 4 req/min)."""
        elapsed = time.time() - self.last_request_time
        if elapsed < self.rate_limit_seconds:
            sleep_time = self.rate_limit_seconds - elapsed
            time.sleep(sleep_time)
        self.last_request_time = time.time()

    def lookup_hash(self, sha256_hash: str) -> Dict[str, Any]:
        """Query VirusTotal API v3 for a given file hash."""
        if not self.api_key:
            return {
                "vt_status": "skipped",
                "reason": "VT_API_KEY not configured",
            }

        self._wait_for_rate_limit()

        try:
            url = f"{self.base_url}{sha256_hash}"
            resp = self.session.get(url, timeout=30)

            if resp.status_code == 404:
                return {
                    "vt_status": "not_found",
                    "reason": "Sample not seen on VirusTotal yet",
                }

            if resp.status_code == 429:
                return {
                    "vt_status": "rate_limited",
                    "reason": "VirusTotal quota exceeded",
                }

            resp.raise_for_status()
            data = resp.json().get("data", {})
            attributes = data.get("attributes", {})

            stats = attributes.get("last_analysis_stats", {})
            malicious = stats.get("malicious", 0)
            suspicious = stats.get("suspicious", 0)
            undetected = stats.get("undetected", 0)
            harmless = stats.get("harmless", 0)
            total_engines = malicious + suspicious + undetected + harmless

            threat_class = attributes.get("popular_threat_classification", {})
            suggested_label = threat_class.get("suggested_threat_label", "unknown")

            # Extract top AV engine detections
            analysis_results = attributes.get("last_analysis_results", {})
            key_engines = ["Microsoft", "SentinelOne", "CrowdStrike", "Kaspersky", "Sophos", "ESET-NOD32"]
            engine_detections = {}
            for eng in key_engines:
                if eng in analysis_results:
                    res = analysis_results[eng]
                    if res.get("category") == "malicious":
                        engine_detections[eng] = res.get("result", "malicious")

            return {
                "vt_status": "success",
                "positives": malicious + suspicious,
                "total_engines": total_engines,
                "detection_ratio": f"{malicious + suspicious}/{total_engines}" if total_engines else "0/0",
                "suggested_threat_label": suggested_label,
                "popular_threat_category": threat_class.get("popular_threat_category", []),
                "names": attributes.get("names", [])[:5],
                "type_description": attributes.get("type_description", ""),
                "tags": attributes.get("tags", []),
                "reputation": attributes.get("reputation", 0),
                "key_engine_detections": engine_detections,
                "vt_permalink": f"https://www.virustotal.com/gui/file/{sha256_hash}",
            }

        except requests.exceptions.RequestException as e:
            return {
                "vt_status": "error",
                "reason": str(e),
            }
