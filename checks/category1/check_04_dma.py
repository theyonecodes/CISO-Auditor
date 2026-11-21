"""
Check 04: DMA Protection
"""

from checks.base import CheckPlugin, CheckResult, CheckStatus
from checks.system_probe import SystemProbeProvider


class DMProtectionCheck(CheckPlugin):
    """Check if Kernel DMA Protection is enabled."""

    def execute(self) -> CheckResult:
        try:
            # This uses the probe's get_vbs_state which checks Device Guard
            # For DMA protection specifically, we need a different check
            # We'll use the probe's get_vbs_state as a proxy and also check registry
            rv = self.probe.reg_read(
                self.probe._hive_const("HKEY_LOCAL_MACHINE"),
                r"SYSTEM\CurrentControlSet\Control\DeviceGuard",
                "MemBootDmaProtection"
            )
            
            if rv.exists and rv.value == 1:
                return CheckResult(
                    check_id=self.id,
                    status=CheckStatus.PASS,
                    details="Kernel DMA Protection is enabled.",
                    remediation=self.metadata.remediation,
                    auto_fixable=self.metadata.auto_fixable
                )
            elif rv.exists:
                return CheckResult(
                    check_id=self.id,
                    status=CheckStatus.FAIL,
                    details="Kernel DMA Protection is disabled. Thunderbolt/USB attacks possible.",
                    remediation=self.metadata.remediation,
                    auto_fixable=self.metadata.auto_fixable
                )
            else:
                return CheckResult(
                    check_id=self.id,
                    status=CheckStatus.WARNING,
                    details="DMA protection status unavailable (check via PS as Admin).",
                    remediation=self.metadata.remediation,
                    auto_fixable=self.metadata.auto_fixable
                )
        except Exception as e:
            return CheckResult(
                check_id=self.id,
                status=CheckStatus.ERROR,
                details=f"Error checking DMA protection: {str(e)}",
                remediation=self.metadata.remediation,
                auto_fixable=self.metadata.auto_fixable
            )

    def fix(self) -> CheckResult:
        return CheckResult(
            check_id=self.id,
            status=CheckStatus.FAIL,
            details="Cannot auto-fix: Requires BIOS support and Windows configuration.",
            remediation=self.metadata.remediation,
            auto_fixable=False
        )