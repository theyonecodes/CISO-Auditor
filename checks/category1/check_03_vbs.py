"""
Check 03: Core Isolation / VBS
"""

from checks.base import CheckPlugin, CheckResult, CheckStatus
from checks.system_probe import SystemProbeProvider


class VBSCheck(CheckPlugin):
    """Check if Virtualization-Based Security (VBS) is enabled."""

    def execute(self) -> CheckResult:
        try:
            vbs_enabled = self.probe.get_vbs_state()
            if vbs_enabled:
                return CheckResult(
                    check_id=self.id,
                    status=CheckStatus.PASS,
                    details="VBS is enabled with secure platform requirements.",
                    remediation=self.metadata.remediation,
                    auto_fixable=self.metadata.auto_fixable
                )
            else:
                return CheckResult(
                    check_id=self.id,
                    status=CheckStatus.FAIL,
                    details="VBS is disabled. Memory integrity protections off.",
                    remediation=self.metadata.remediation,
                    auto_fixable=self.metadata.auto_fixable
                )
        except Exception as e:
            return CheckResult(
                check_id=self.id,
                status=CheckStatus.ERROR,
                details=f"Error checking VBS: {str(e)}",
                remediation=self.metadata.remediation,
                auto_fixable=self.metadata.auto_fixable
            )

    def fix(self) -> CheckResult:
        return CheckResult(
            check_id=self.id,
            status=CheckStatus.FAIL,
            details="Cannot auto-fix: VBS requires BIOS virtualization support and Windows Security configuration.",
            remediation=self.metadata.remediation,
            auto_fixable=False
        )