"""
Plugin Registry — Loads and manages check plugins from manifest.
"""

import json
import importlib
from pathlib import Path
from typing import Dict, List, Optional, Any
from dataclasses import dataclass

from checks.base import CheckPlugin, CheckMetadata, CheckStatus
from checks.system_probe import SystemProbeProvider, WindowsProbe


@dataclass
class LoadedCheck:
    """A loaded check plugin with its metadata."""
    metadata: CheckMetadata
    plugin_class: type
    instance: Optional[CheckPlugin] = None


class PluginRegistry:
    """Manages loading and instantiation of check plugins."""

    def __init__(self, probe: Optional[SystemProbeProvider] = None):
        self.probe = probe or WindowsProbe()
        self.loaded: Dict[int, LoadedCheck] = {}
        self.manifest: Optional[Dict] = None

    def load_manifest(self, manifest_path: str) -> Dict:
        """Load and validate the rules manifest."""
        path = Path(manifest_path)
        if not path.exists():
            raise FileNotFoundError(f"Manifest not found: {manifest_path}")

        with open(path) as f:
            self.manifest = json.load(f)

        if self.manifest.get("manifest_version") != "2.0":
            raise ValueError(f"Unsupported manifest version: {self.manifest.get('manifest_version')}")

        return self.manifest

    def load_all(self, manifest_path: Optional[str] = None) -> List[LoadedCheck]:
        """Load all checks from manifest."""
        if manifest_path:
            self.load_manifest(manifest_path)

        if not self.manifest:
            raise ValueError("No manifest loaded. Call load_manifest() first.")

        loaded = []
        for check_def in self.manifest.get("checks", []):
            loaded_check = self._load_check(check_def)
            if loaded_check:
                self.loaded[loaded_check.metadata.id] = loaded_check
                loaded.append(loaded_check)

        return loaded

    def _load_check(self, check_def: Dict) -> Optional[LoadedCheck]:
        """Load a single check plugin."""
        try:
            plugin_path = check_def["plugin"]
            module_path, class_name = plugin_path.rsplit(".", 1)
            module = importlib.import_module(module_path)
            plugin_class = getattr(module, class_name)

            metadata = CheckMetadata(
                id=check_def["id"],
                name=check_def["name"],
                category=check_def["category"],
                description=check_def["description"],
                remediation=check_def.get("remediation", ""),
                auto_fixable=check_def.get("auto_fixable", False),
                severity=check_def.get("severity", "Medium"),
                mitre_techniques=check_def.get("mitre_techniques", []),
                references=check_def.get("references", [])
            )

            return LoadedCheck(metadata=metadata, plugin_class=plugin_class)

        except Exception as e:
            print(f"Failed to load check {check_def.get('id')}: {e}")
            return None

    def get_check(self, check_id: int) -> Optional[CheckPlugin]:
        """Get an instantiated check plugin."""
        if check_id not in self.loaded:
            return None

        loaded = self.loaded[check_id]
        if loaded.instance is None:
            loaded.instance = loaded.plugin_class(self.probe, loaded.metadata)
        return loaded.instance

    def get_all_checks(self) -> List[CheckPlugin]:
        """Get all instantiated check plugins, sorted by ID."""
        return [self.get_check(cid) for cid in sorted(self.loaded.keys())]

    def get_by_category(self, category: str) -> List[CheckPlugin]:
        """Get checks filtered by category."""
        return [
            self.get_check(cid)
            for cid, lc in self.loaded.items()
            if lc.metadata.category == category
        ]

    def get_auto_fixable(self) -> List[CheckPlugin]:
        """Get all checks that have auto-fix capability."""
        return [
            self.get_check(cid)
            for cid, lc in self.loaded.items()
            if lc.metadata.auto_fixable
        ]


class AuditorEngine:
    """
    Main engine for running security audits.
    Replaces the monolithic AuditorCore with plugin-based architecture.
    """

    def __init__(self, probe: Optional[SystemProbeProvider] = None, manifest_path: Optional[str] = None):
        self.registry = PluginRegistry(probe)
        if manifest_path:
            self.registry.load_all(manifest_path)

        self.results: Dict[int, Any] = {}
        self.fix_history: List[tuple] = []

    def load_manifest(self, manifest_path: str):
        """Load a rules manifest."""
        self.registry.load_manifest(manifest_path)
        self.registry.load_all()

    def run_all(self, progress_callback=None) -> Dict[int, Any]:
        """Run all loaded checks."""
        checks = self.registry.get_all_checks()
        total = len(checks)

        for i, check in enumerate(checks):
            if progress_callback:
                progress_callback(i + 1, total, check.metadata.name)

            result = check.execute()
            self.results[result.check_id] = result

        return self.results

    def run_category(self, category: str, progress_callback=None) -> Dict[int, Any]:
        """Run checks in a specific category."""
        checks = self.registry.get_by_category(category)
        total = len(checks)

        for i, check in enumerate(checks):
            if progress_callback:
                progress_callback(i + 1, total, check.metadata.name)

            result = check.execute()
            self.results[result.check_id] = result

        return self.results

    def run_check(self, check_id: int) -> Any:
        """Run a single check by ID."""
        check = self.registry.get_check(check_id)
        if not check:
            raise ValueError(f"Check {check_id} not found")

        result = check.execute()
        self.results[check_id] = result
        return result

    def fix_check(self, check_id: int) -> Any:
        """Apply auto-fix for a check."""
        check = self.registry.get_check(check_id)
        if not check:
            raise ValueError(f"Check {check_id} not found")

        if not check.can_fix():
            raise ValueError(f"Check {check_id} has no auto-fix available")

        result = check.fix()
        if result.fix_result:
            self.fix_history.append((check_id, result.fix_result))

        return result

    def export_results_mcp(self) -> Dict:
        """Export results in MCP-compatible JSON format."""
        return {
            "audit_version": "2.0",
            "total_checks": len(self.results),
            "passed": sum(1 for r in self.results.values() if r.status == CheckStatus.PASS),
            "failed": sum(1 for r in self.results.values() if r.status == CheckStatus.FAIL),
            "warnings": sum(1 for r in self.results.values() if r.status == CheckStatus.WARNING),
            "errors": sum(1 for r in self.results.values() if r.status == CheckStatus.ERROR),
            "checks": {
                str(cid): {
                    "id": r.check_id,
                    "status": r.status.value,
                    "details": r.details,
                    "remediation": r.remediation,
                    "auto_fixable": r.auto_fixable,
                    "metadata": r.metadata
                }
                for cid, r in self.results.items()
            },
            "fix_history": [
                {"check_id": cid, "action": desc}
                for cid, desc in self.fix_history
            ]
        }

    def get_summary(self) -> Dict:
        """Get a summary of results."""
        if not self.results:
            return {"message": "No results available. Run checks first."}

        # Get category mapping from loaded checks
        cat_map = {cid: lc.metadata.category for cid, lc in self.registry.loaded.items()}
        
        return {
            "total": len(self.results),
            "passed": sum(1 for r in self.results.values() if r.status == CheckStatus.PASS),
            "failed": sum(1 for r in self.results.values() if r.status == CheckStatus.FAIL),
            "warnings": sum(1 for r in self.results.values() if r.status == CheckStatus.WARNING),
            "errors": sum(1 for r in self.results.values() if r.status == CheckStatus.ERROR),
            "categories": {
                cat: {
                    "total": len([cid for cid, r in self.results.items() if cat_map.get(cid) == cat]),
                    "passed": len([cid for cid, r in self.results.items() if r.status == CheckStatus.PASS and cat_map.get(cid) == cat])
                }
                for cat in set(cat_map.values())
            }
        }