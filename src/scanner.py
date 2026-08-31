import hashlib
import os
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple
import yara


class YaraScanner:
    def __init__(self, rules_root: Path, active_platforms: List[str] = None):
        self.rules_root = rules_root
        self.active_platforms = active_platforms or ["macos"]
        self.rules: Optional[yara.Rules] = None
        self.rule_files: Dict[str, List[Path]] = {}
        self._discover_rules()

    def _discover_rules(self) -> None:
        """Find all .yar / .yara files in active platform directories."""
        self.rule_files.clear()
        if not self.rules_root.exists():
            return

        for platform in self.active_platforms:
            plat_dir = self.rules_root / platform
            if plat_dir.exists() and plat_dir.is_dir():
                yar_files = list(plat_dir.glob("*.yar")) + list(plat_dir.glob("*.yara"))
                self.rule_files[platform] = yar_files

    def validate_rules(self) -> Tuple[bool, List[str]]:
        """Validate all rules individually to identify any syntax errors."""
        errors = []
        for platform, files in self.rule_files.items():
            for f in files:
                try:
                    yara.compile(filepath=str(f))
                except yara.SyntaxError as e:
                    errors.append(f"[{platform}] Syntax error in {f.name}: {str(e)}")
                except Exception as e:
                    errors.append(f"[{platform}] Failed to compile {f.name}: {str(e)}")
        return (len(errors) == 0, errors)

    def compile(self) -> bool:
        """Compile all active platform rules into a single Yara.Rules object with namespaces."""
        filepaths = {}
        for platform, files in self.rule_files.items():
            for f in files:
                # Namespace format: platform_rulename
                ns = f"{platform}_{f.stem}"
                filepaths[ns] = str(f)

        if not filepaths:
            return False

        try:
            self.rules = yara.compile(filepaths=filepaths)
            return True
        except Exception as e:
            raise RuntimeError(f"Global YARA compilation failed: {e}")

    @staticmethod
    def calculate_hashes(data: bytes) -> Dict[str, str]:
        """Compute sha256 and md5 hashes for a byte buffer."""
        return {
            "sha256": hashlib.sha256(data).hexdigest(),
            "md5": hashlib.md5(data).hexdigest(),
        }

    def scan_data(self, data: bytes, sample_name: str = "unknown") -> List[Dict[str, Any]]:
        """Scan in-memory byte buffer and return structured match information."""
        if not self.rules:
            if not self.compile():
                return []

        matches = self.rules.match(data=data)
        hashes = self.calculate_hashes(data)
        return self._format_matches(matches, hashes, sample_name, len(data))

    def scan_file(self, filepath: Path) -> List[Dict[str, Any]]:
        """Scan a local file on disk."""
        if not filepath.exists() or not filepath.is_file():
            return []

        try:
            with open(filepath, "rb") as f:
                data = f.read()
            return self.scan_data(data, sample_name=filepath.name)
        except Exception as e:
            print(f"[!] Error scanning {filepath.name}: {e}")
            return []

    def _format_matches(
        self,
        yara_matches: List[Any],
        hashes: Dict[str, str],
        sample_name: str,
        file_size: int,
    ) -> List[Dict[str, Any]]:
        results = []
        for match in yara_matches:
            matched_strings = []
            for string_match in getattr(match, "strings", []):
                try:
                    # In yara-python: string_match is (offset, identifier, data) or Match object
                    offset, identifier, str_data = string_match
                    # Format printable preview
                    if isinstance(str_data, bytes):
                        preview = str_data.decode("utf-8", errors="replace")[:80]
                    else:
                        preview = str(str_data)[:80]

                    matched_strings.append({
                        "offset": hex(offset),
                        "identifier": identifier,
                        "data_preview": preview,
                    })
                except Exception:
                    continue

            results.append({
                "rule_name": match.rule,
                "namespace": match.namespace,
                "tags": list(match.tags),
                "meta": dict(match.meta),
                "matched_strings": matched_strings[:15], # top 15 matches for brevity
                "sample_sha256": hashes["sha256"],
                "sample_md5": hashes["md5"],
                "sample_name": sample_name,
                "sample_size_bytes": file_size,
            })
        return results
