"""
Check 05: Firmware Updates
"""

from checks.base import CheckPlugin, CheckResult, CheckStatus


class FirmwareCheck(CheckPlugin):
    """Check if BIOS/UEFI firmware is up to date against known vulnerabilities."""

    def execute(self) -> CheckResult:
        try:
            res = self.probe.get_bios_info()
            bios_version = res.get("version", "")
            manufacturer = res.get("manufacturer", "")
            
            if bios_version:
                return CheckResult(
                    check_id=self.id,
                    status=CheckStatus.WARNING,
                    details=f"BIOS version: {bios_version} ({manufacturer}). Manually verify against latest CVE database.",
                    remediation=self.metadata.remediation,
                    auto_fixable=self.metadata.auto_fixable
                )
            else:
                return CheckResult(
                    check_id=self.id,
                    status=CheckStatus.WARNING,
                    details="Unable to retrieve firmware version.",
                    remediation=self.metadata.remediation,
                    auto_fixable=self.metadata.auto_fixable
                )
        except Exception as e:
            return CheckResult(
                check_id=self.id,
                status=CheckStatus.ERROR,
                details=f"Error checking firmware: {str(e)}",
                remediation=self.metadata.remediation,
                auto_fixable=self.metadata.auto_fixable
            )

    def fix(self) -> CheckResult:
        return CheckResult(
            check_id=self.id,
            status=CheckStatus.FAIL,
            details="Cannot auto-fix: Requires manual BIOS/UEFI update from manufacturer.",
            remediation=self.metadata.remediation,
            auto_fixable=False
        )