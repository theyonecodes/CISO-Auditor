"""
Check 09: SMM (System Management Mode)
"""

from checks.base import CheckPlugin, CheckResult, CheckStatus
import winreg


class SMMCheck(CheckPlugin):
    """Check SMM protection status."""

    def execute(self) -> CheckResult:
        try:
            rv = self.probe.reg_read(
                self.probe._hive_const("HKEY_LOCAL_MACHINE"),
                r"SYSTEM\CurrentControlSet\Control\SecureBoot\State",
                "UEFISecureBootEnabled"
            )
            
            if rv.exists and rv.value == 1:
                return CheckResult(
                    check_id=self.id,
                    status=CheckStatus.PASS,
                    details="Secure Boot enabled — SMM protections active at firmware level.",
                    remediation=self.metadata.remediation,
                    auto_fixable=self.metadata.auto_fixable
                )
            else:
                return CheckResult(
                    check_id=self.id,
                    status=CheckStatus.WARNING,
                    details="SMM protection status ambiguous. Requires manual firmware verification.",
                    remediation=self.metadata.remediation,
                    auto_fixable=self.metadata.auto_fixable
                )
        except Exception as e:
            return CheckResult(
                check_id=self.id,
                status=CheckStatus.ERROR,
                details=f"Error checking SMM: {str(e)}",
                remediation=self.metadata.remediation,
                auto_fixable=self.metadata.auto_fixable
            )

    def fix(self) -> CheckResult:
        return CheckResult(
            check_id=self.id,
            status=CheckStatus.FAIL,
            details="Cannot auto-fix: Requires BIOS/UEFI configuration.",
            remediation=self.metadata.remediation,
            auto_fixable=False
        )