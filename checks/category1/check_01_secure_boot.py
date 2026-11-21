"""
Check 01: UEFI Secure Boot
"""

from checks.base import CheckPlugin, CheckResult, CheckStatus
from checks.system_probe import SystemProbeProvider


class SecureBootCheck(CheckPlugin):
    """Check if UEFI Secure Boot is enabled."""

    def execute(self) -> CheckResult:
        try:
            is_secure_boot = self.probe.get_secure_boot_state()
            if is_secure_boot:
                return CheckResult(
                    check_id=self.id,
                    status=CheckStatus.PASS,
                    details="Secure Boot is fully active and enforcing signed bootloaders.",
                    remediation=self.metadata.remediation,
                    auto_fixable=self.metadata.auto_fixable
                )
            else:
                return CheckResult(
                    check_id=self.id,
                    status=CheckStatus.FAIL,
                    details="Secure Boot is DISABLED. System vulnerable to bootkits.",
                    remediation=self.metadata.remediation,
                    auto_fixable=self.metadata.auto_fixable
                )
        except Exception as e:
            return CheckResult(
                check_id=self.id,
                status=CheckStatus.ERROR,
                details=f"Error checking Secure Boot: {str(e)}",
                remediation=self.metadata.remediation,
                auto_fixable=self.metadata.auto_fixable
            )

    def fix(self) -> CheckResult:
        return CheckResult(
            check_id=self.id,
            status=CheckStatus.FAIL,
            details="Cannot auto-fix: Secure Boot must be enabled in BIOS/UEFI firmware settings.",
            remediation=self.metadata.remediation,
            auto_fixable=False
        )