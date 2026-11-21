"""
Check 02: TPM 2.0 Status
"""

from checks.base import CheckPlugin, CheckResult, CheckStatus
from checks.system_probe import SystemProbeProvider


class TPMCheck(CheckPlugin):
    """Check if TPM 2.0 is active and provisioned."""

    def execute(self) -> CheckResult:
        try:
            tpm_ready = self.probe.get_tpm_state()
            if tpm_ready:
                return CheckResult(
                    check_id=self.id,
                    status=CheckStatus.PASS,
                    details="TPM is ready and provisioned.",
                    remediation=self.metadata.remediation,
                    auto_fixable=self.metadata.auto_fixable
                )
            else:
                return CheckResult(
                    check_id=self.id,
                    status=CheckStatus.FAIL,
                    details="TPM not detected or not enabled.",
                    remediation=self.metadata.remediation,
                    auto_fixable=self.metadata.auto_fixable
                )
        except Exception as e:
            return CheckResult(
                check_id=self.id,
                status=CheckStatus.ERROR,
                details=f"Error checking TPM: {str(e)}",
                remediation=self.metadata.remediation,
                auto_fixable=self.metadata.auto_fixable
            )

    def fix(self) -> CheckResult:
        return CheckResult(
            check_id=self.id,
            status=CheckStatus.FAIL,
            details="Cannot auto-fix: TPM must be enabled in BIOS/UEFI firmware settings.",
            remediation=self.metadata.remediation,
            auto_fixable=False
        )