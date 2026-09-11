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

    def get_samples_by_signature(self, signature: str, limit: int = 50) -> List[Dict[str, Any]]:
        """Fetch samples by signature/family (e.g. AMOS, RedLine, Mirai)."""
        data = {"query": "get_siginfo", "signature": signature, "limit": limit}
        res = self._post(data)
        if res.get("query_status") == "ok":
            return res.get("data", [])[:limit]
        return []

    @staticmethod
    def _matches_file_types(sample: Dict[str, Any], allowed_types: set) -> bool:
        """Check if a sample matches the allowed file types."""
        if not allowed_types or "any" in allowed_types or "all" in allowed_types:
            return True

        sample_ft = (sample.get("file_type") or "").strip().lower()
        if sample_ft and sample_ft in allowed_types:
            return True

        # Fallback check against file name extension
        fname = (sample.get("file_name") or "").strip().lower()
        if "." in fname:
            ext = fname.rsplit(".", 1)[-1]
            if ext in allowed_types:
                return True
            # Common platform mappings
            if "macho" in allowed_types and ext in {"macho", "dylib", "bundle"}:
                return True
            if "elf" in allowed_types and ext in {"elf", "so"}:
                return True

        return False

    def query_platform_samples(
        self,
        platform: str,
        file_types: List[str],
        tags: List[str],
        signatures: Optional[List[str]] = None,
        limit_per_query: int = 25,
    ) -> List[Dict[str, Any]]:
        """Collect and deduplicate samples for a target platform based on file types, tags, and signatures."""
        seen_hashes = set()
        collected_samples: List[Dict[str, Any]] = []
        allowed_types = {ft.strip().lower() for ft in file_types if ft.strip()}
        strict_file_type_filter = bool(allowed_types and "any" not in allowed_types and "all" not in allowed_types)

        # 1. Query by file types
        for ft in file_types:
            ft_clean = ft.strip().lower()
            if not ft_clean or ft_clean in ("any", "all"):
                continue
            samples = self.get_samples_by_file_type(ft_clean, limit=limit_per_query)
            for s in samples:
                h = s.get("sha256_hash")
                if h and h not in seen_hashes:
                    seen_hashes.add(h)
                    s["_source_platform"] = platform
                    s["_query_file_type"] = ft_clean
                    collected_samples.append(s)

        # 2. Query by specific platform tags
        for tag in tags:
            tag_clean = tag.strip()
            if not tag_clean:
                continue
            samples = self.get_samples_by_tag(tag_clean, limit=limit_per_query)
            for s in samples:
                if strict_file_type_filter and not self._matches_file_types(s, allowed_types):
                    continue
                h = s.get("sha256_hash")
                if h and h not in seen_hashes:
                    seen_hashes.add(h)
                    s["_source_platform"] = platform
                    s["_query_tag"] = tag_clean
                    collected_samples.append(s)

        # 3. Query by signatures if provided
        if signatures:
            for sig in signatures:
                sig_clean = sig.strip()
                if not sig_clean:
                    continue
                samples = self.get_samples_by_signature(sig_clean, limit=limit_per_query)
                for s in samples:
                    if strict_file_type_filter and not self._matches_file_types(s, allowed_types):
                        continue
                    h = s.get("sha256_hash")
                    if h and h not in seen_hashes:
                        seen_hashes.add(h)
                        s["_source_platform"] = platform
                        s["_query_signature"] = sig_clean
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
