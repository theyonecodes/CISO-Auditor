"""
Check 10: Hardware Virtualization
"""

from checks.base import CheckPlugin, CheckResult, CheckStatus


class HVCheck(CheckPlugin):
    """Check if hardware virtualization (VT-x/AMD-V) is enabled."""

    def execute(self) -> CheckResult:
        try:
            res = self.probe.run_powershell("Get-CimInstance Win32_Processor | Select-Object -ExpandProperty VirtualizationFirmwareEnabled")
            
            if "True" in res.stdout:
                return CheckResult(
                    check_id=self.id,
                    status=CheckStatus.PASS,
                    details="VT-x/AMD-V is enabled in firmware.",
                    remediation=self.metadata.remediation,
                    auto_fixable=self.metadata.auto_fixable
                )
            else:
                return CheckResult(
                    check_id=self.id,
                    status=CheckStatus.FAIL,
                    details="Hardware virtualization is disabled in firmware.",
                    remediation=self.metadata.remediation,
                    auto_fixable=self.metadata.auto_fixable
                )
        except Exception as e:
            return CheckResult(
                check_id=self.id,
                status=CheckStatus.ERROR,
                details=f"Error checking hardware virtualization: {str(e)}",
                remediation=self.metadata.remediation,
                auto_fixable=self.metadata.auto_fixable
            )

    def fix(self) -> CheckResult:
        return CheckResult(
            check_id=self.id,
            status=CheckStatus.FAIL,
            details="Cannot auto-fix: Requires BIOS/UEFI configuration change.",
            remediation=self.metadata.remediation,
            auto_fixable=False
        )