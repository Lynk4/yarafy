import io
import json
import os
import tempfile
import zipfile
from pathlib import Path
from typing import Any, Dict, Generator, List, Optional, Tuple
import requests

try:
    import pyzipper
    HAS_PYZIPPER = True
except ImportError:
    HAS_PYZIPPER = False


class MalwareBazaarCollector:
    """Client to query and download malware samples from MalwareBazaar (abuse.ch)."""

    def __init__(self, api_key: str = "", api_url: str = "https://mb-api.abuse.ch/api/v1/"):
        self.api_key = api_key
        self.api_url = api_url
        self.session = requests.Session()
        if self.api_key:
            self.session.headers.update({"Auth-Key": self.api_key, "API-KEY": self.api_key})
        else:
            print("[!] Note: MALWAREBAZAAR_API_KEY is not set. Abuse.ch requires a free Auth-Key from https://bazaar.abuse.ch/api/")

    def _post(self, data: Dict[str, Any]) -> Dict[str, Any]:
        try:
            resp = self.session.post(self.api_url, data=data, timeout=30)
            if resp.status_code == 401:
                print("[!] MalwareBazaar 401 Unauthorized: Please provide a valid MALWAREBAZAAR_API_KEY in your .env or GitHub Secrets.")
                return {"query_status": "unauthorized"}
            resp.raise_for_status()
            return resp.json()
        except requests.exceptions.RequestException as e:
            print(f"[!] MalwareBazaar API request failed: {e}")
            return {"query_status": "error", "error": str(e)}

    def get_recent_samples(self, limit: int = 50) -> List[Dict[str, Any]]:
        """Fetch the most recent malware additions."""
        data = {"query": "get_recent", "selector": "time"}
        res = self._post(data)
        if res.get("query_status") == "ok":
            return res.get("data", [])[:limit]
        return []

    def get_samples_by_file_type(self, file_type: str, limit: int = 50) -> List[Dict[str, Any]]:
        """Fetch recent samples matching a specific file type (e.g. macho, dmg, pkg, elf, exe)."""
        data = {"query": "get_file_type", "file_type": file_type, "limit": limit}
        res = self._post(data)
        if res.get("query_status") == "ok":
            return res.get("data", [])[:limit]
        return []

    def get_samples_by_tag(self, tag: str, limit: int = 50) -> List[Dict[str, Any]]:
        """Fetch samples by tag (e.g. macOS, AMOS, RustBucket)."""
        data = {"query": "get_taginfo", "tag": tag, "limit": limit}
        res = self._post(data)
        if res.get("query_status") == "ok":
            return res.get("data", [])[:limit]
        return []

    def query_platform_samples(
        self,
        platform: str,
        file_types: List[str],
        tags: List[str],
        limit_per_query: int = 25,
    ) -> List[Dict[str, Any]]:
        """Collect and deduplicate samples for a target platform based on file types and tags."""
        seen_hashes = set()
        collected_samples: List[Dict[str, Any]] = []

        # 1. Query by file types
        for ft in file_types:
            samples = self.get_samples_by_file_type(ft, limit=limit_per_query)
            for s in samples:
                h = s.get("sha256_hash")
                if h and h not in seen_hashes:
                    seen_hashes.add(h)
                    s["_source_platform"] = platform
                    s["_query_file_type"] = ft
                    collected_samples.append(s)

        # 2. Query by specific platform tags
        for tag in tags:
            samples = self.get_samples_by_tag(tag, limit=limit_per_query)
            for s in samples:
                h = s.get("sha256_hash")
                if h and h not in seen_hashes:
                    seen_hashes.add(h)
                    s["_source_platform"] = platform
                    s["_query_tag"] = tag
                    collected_samples.append(s)

        return collected_samples

    def download_sample_bytes(self, sha256_hash: str) -> Optional[Tuple[str, bytes]]:
        """
        Download a sample from MalwareBazaar by sha256.
        Samples are returned in a password-protected zip file (password: 'infected').
        Returns (sample_filename, binary_bytes) or None if download/unzip fails.
        """
        data = {"query": "get_file", "sha256_hash": sha256_hash}
        try:
            resp = self.session.post(self.api_url, data=data, timeout=45)
            if resp.status_code != 200 or len(resp.content) == 0:
                return None

            # Handle JSON error response if sample not found
            if resp.content.startswith(b"{"):
                try:
                    js = resp.json()
                    if js.get("query_status") != "ok":
                        return None
                except Exception:
                    pass

            # Extract zip payload password-protected with 'infected'
            if HAS_PYZIPPER:
                try:
                    with pyzipper.AESZipFile(io.BytesIO(resp.content)) as zf:
                        zf.pwd = b"infected"
                        for file_info in zf.infolist():
                            try:
                                extracted_bytes = zf.read(file_info)
                                return (file_info.filename, extracted_bytes)
                            except Exception as e:
                                print(f"[!] pyzipper failed to decrypt {file_info.filename}: {e}")
                except Exception:
                    pass

            # Fallback to standard zipfile
            try:
                with zipfile.ZipFile(io.BytesIO(resp.content)) as zf:
                    for file_info in zf.infolist():
                        try:
                            extracted_bytes = zf.read(file_info, pwd=b"infected")
                            return (file_info.filename, extracted_bytes)
                        except Exception as e:
                            print(f"[!] zipfile failed to decrypt {file_info.filename}: {e}")
            except Exception as e:
                print(f"[!] Failed to parse zip archive: {e}")

            return None
        except Exception as e:
            print(f"[!] Error downloading sample {sha256_hash}: {e}")
            return None
