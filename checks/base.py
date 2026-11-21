"""
Check Plugin Base Classes — Plugin architecture for security checks.
"""

import json
import winreg
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Any, Callable
from enum import Enum


class CheckStatus(Enum):
    PASS = "PASS"
    FAIL = "FAIL"
    WARNING = "WARNING"
    PENDING = "PENDING"
    ERROR = "ERROR"


@dataclass
class CheckResult:
    """Result of a security check execution."""
    check_id: int
    status: CheckStatus
    details: str
    remediation: str = ""
    auto_fixable: bool = False
    fix_result: Optional[str] = None
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class CheckMetadata:
    """Static metadata for a check (loaded from rule manifest)."""
    id: int
    name: str
    category: str
    description: str
    remediation: str = ""
    auto_fixable: bool = False
    severity: str = "Medium"  # Critical, High, Medium, Low
    mitre_techniques: List[str] = field(default_factory=list)
    references: List[str] = field(default_factory=list)


class CheckPlugin(ABC):
    """
    Base class for all security check plugins.
    Each check is a separate plugin with its own logic.
    """

    def __init__(self, probe, metadata: CheckMetadata):
        self.probe = probe
        self.metadata = metadata

    @property
    def id(self) -> int:
        return self.metadata.id

    @property
    def name(self) -> str:
        return self.metadata.name

    @property
    def category(self) -> str:
        return self.metadata.category

    @abstractmethod
    def execute(self) -> CheckResult:
        """Execute the check and return result."""
        pass

    def can_fix(self) -> bool:
        """Whether this check has an auto-fix available."""
        return self.metadata.auto_fixable

    @abstractmethod
    def fix(self) -> CheckResult:
        """Apply the auto-fix. Returns result with fix_result populated."""
        pass


class RegistryCheck(CheckPlugin):
    """Base class for registry-based checks."""

    def __init__(self, probe, metadata: CheckMetadata):
        super().__init__(probe, metadata)
        self._backup: Dict[str, Any] = {}

    def _read_reg(self, hive: int, subkey: str, name: str):
        return self.probe.reg_read(hive, subkey, name)

    def _write_reg(self, hive: int, subkey: str, name: str, value: Any, val_type: int = winreg.REG_DWORD) -> bool:
        # Backup before write
        key = (hive, subkey, name)
        if key not in self._backup:
            rv = self._read_reg(hive, subkey, name)
            self._backup[key] = rv
        return self.probe.reg_write(hive, subkey, name, value, val_type)

    def _restore_reg(self, hive: int, subkey: str, name: str) -> bool:
        key = (hive, subkey, name)
        if key in self._backup:
            rv = self._backup[key]
            if rv.exists:
                return self.probe.reg_write(hive, subkey, name, rv.value, rv.value_type)
            else:
                # Value didn't exist - delete it
                try:
                    with winreg.OpenKey(hive, subkey, 0, winreg.KEY_SET_VALUE) as k:
                        winreg.DeleteValue(k, name)
                    return True
                except:
                    return False
        return True


class PowerShellCheck(CheckPlugin):
    """Base class for PowerShell-based checks."""

    def _ps(self, cmd: str, elevated: bool = False):
        return self.probe.run_powershell(cmd, elevated)

    def _ps_bool(self, cmd: str, elevated: bool = False) -> bool:
        res = self._ps(cmd, elevated)
        return res.returncode == 0 and "True" in res.stdout


class ProcessCheck(CheckPlugin):
    """Base class for process/port-based checks."""

    def _listening_ports(self):
        return self.probe.get_listening_ports()

    def _network_adapters(self):
        return self.probe.get_network_adapters()


class CompositeCheck(CheckPlugin):
    """Check that combines multiple sub-checks."""

    def __init__(self, probe, metadata: CheckMetadata, sub_checks: List[CheckPlugin]):
        super().__init__(probe, metadata)
        self.sub_checks = sub_checks

    def execute(self) -> CheckResult:
        results = []
        all_pass = True
        for sub in self.sub_checks:
            r = sub.execute()
            results.append(r)
            if r.status != CheckStatus.PASS:
                all_pass = False

        status = CheckStatus.PASS if all_pass else CheckStatus.FAIL
        details = f"Sub-checks: {sum(1 for r in results if r.status == CheckStatus.PASS)}/{len(results)} passed"
        return CheckResult(
            check_id=self.id,
            status=status,
            details=details,
            remediation=self.metadata.remediation,
            auto_fixable=self.metadata.auto_fixable,
            metadata={"sub_results": [r.__dict__ for r in results]}
        )

    def fix(self) -> CheckResult:
        fix_results = []
        for sub in self.sub_checks:
            if sub.can_fix():
                fix_results.append(sub.fix())
        return CheckResult(
            check_id=self.id,
            status=CheckStatus.PASS if all(r.status == CheckStatus.PASS for r in fix_results) else CheckStatus.FAIL,
            details=f"Fixed {sum(1 for r in fix_results if r.status == CheckStatus.PASS)}/{len(fix_results)} sub-checks",
            metadata={"fix_results": [r.__dict__ for r in fix_results]}
        )