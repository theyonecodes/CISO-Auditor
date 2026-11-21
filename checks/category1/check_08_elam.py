"""
Check 08: Early Launch Anti-Malware (ELAM)
"""

from checks.base import CheckPlugin, CheckResult, CheckStatus
import winreg


class ELAMCheck(CheckPlugin):
    """Check if ELAM is active."""

    def execute(self) -> CheckResult:
        try:
            rv = self.probe.reg_read(
                self.probe._hive_const("HKEY_LOCAL_MACHINE"),
                r"SYSTEM\CurrentControlSet\Control\EarlyLaunch",
                "DriverLoadPolicy"
            )
            
            if rv.exists:
                val = rv.value
                if val == 8:
                    return CheckResult(
                        check_id=self.id,
                        status=CheckStatus.PASS,
                        details="ELAM is enabled (policy: 8 - GoodOnly).",
                        remediation=self.metadata.remediation,
                        auto_fixable=self.metadata.auto_fixable
                    )
                elif val == 1:
                    return CheckResult(
                        check_id=self.id,
                        status=CheckStatus.WARNING,
                        details="ELAM is disabled (policy: 1 - Disabled).",
                        remediation=self.metadata.remediation,
                        auto_fixable=self.metadata.auto_fixable
                    )
                else:
                    return CheckResult(
                        check_id=self.id,
                        status=CheckStatus.WARNING,
                        details=f"ELAM policy set to {val}.",
                        remediation=self.metadata.remediation,
                        auto_fixable=self.metadata.auto_fixable
                    )
            else:
                return CheckResult(
                    check_id=self.id,
                    status=CheckStatus.PASS,
                    details="ELAM is active with default policy.",
                    remediation=self.metadata.remediation,
                    auto_fixable=self.metadata.auto_fixable
                )
        except Exception as e:
            return CheckResult(
                check_id=self.id,
                status=CheckStatus.ERROR,
                details=f"Error checking ELAM: {str(e)}",
                remediation=self.metadata.remediation,
                auto_fixable=self.metadata.auto_fixable
            )

    def fix(self) -> CheckResult:
        return CheckResult(
            check_id=self.id,
            status=CheckStatus.FAIL,
            details="Cannot auto-fix: Requires registry modification and reboot.",
            remediation=self.metadata.remediation,
            auto_fixable=False
        )