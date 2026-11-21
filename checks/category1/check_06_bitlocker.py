"""
Check 06: BitLocker / Device Encryption
"""

from checks.base import CheckPlugin, CheckResult, CheckStatus


class BitLockerCheck(CheckPlugin):
    """Check if BitLocker is enabled on OS drive."""

    def execute(self) -> CheckResult:
        try:
            res = self.probe.get_bitlocker_state("C:")
            protection = res.get("protection_status", "")
            method = res.get("encryption_method", "")
            
            if "On" in protection:
                return CheckResult(
                    check_id=self.id,
                    status=CheckStatus.PASS,
                    details=f"OS Drive encrypted. Method: {method or 'Unknown'}",
                    remediation=self.metadata.remediation,
                    auto_fixable=self.metadata.auto_fixable
                )
            else:
                return CheckResult(
                    check_id=self.id,
                    status=CheckStatus.FAIL,
                    details="BitLocker is off or suspended on C: drive.",
                    remediation=self.metadata.remediation,
                    auto_fixable=self.metadata.auto_fixable
                )
        except Exception as e:
            return CheckResult(
                check_id=self.id,
                status=CheckStatus.ERROR,
                details=f"Error checking BitLocker: {str(e)}",
                remediation=self.metadata.remediation,
                auto_fixable=self.metadata.auto_fixable
            )

    def fix(self) -> CheckResult:
        return CheckResult(
            check_id=self.id,
            status=CheckStatus.FAIL,
            details="Cannot auto-fix: Requires admin to run 'manage-bde -on C:'.",
            remediation=self.metadata.remediation,
            auto_fixable=False
        )