"""
Check 07: Boot Configuration Data (BCD)
"""

from checks.base import CheckPlugin, CheckResult, CheckStatus


class BCDCheck(CheckPlugin):
    """Check if BCD has insecure settings (testsigning, debug)."""

    def execute(self) -> CheckResult:
        try:
            res = self.probe.get_bcd_settings()
            testsigning = res.get("testsigning", False)
            debug = res.get("debug", False)
            
            issues = []
            if testsigning:
                issues.append("testsigning ON")
            if debug:
                issues.append("debug ON")
            
            if issues:
                return CheckResult(
                    check_id=self.id,
                    status=CheckStatus.FAIL,
                    details=f"BCD has insecure settings: {', '.join(issues)}",
                    remediation=self.metadata.remediation,
                    auto_fixable=self.metadata.auto_fixable
                )
            else:
                return CheckResult(
                    check_id=self.id,
                    status=CheckStatus.PASS,
                    details="BCD: testsigning and debug mode are disabled.",
                    remediation=self.metadata.remediation,
                    auto_fixable=self.metadata.auto_fixable
                )
        except Exception as e:
            return CheckResult(
                check_id=self.id,
                status=CheckStatus.ERROR,
                details=f"Error checking BCD: {str(e)}",
                remediation=self.metadata.remediation,
                auto_fixable=self.metadata.auto_fixable
            )

    def fix(self) -> CheckResult:
        try:
            res = self.probe.run_powershell("bcdedit /set testsigning off && bcdedit /set debug off")
            if res.returncode == 0:
                return CheckResult(
                    check_id=self.id,
                    status=CheckStatus.PASS,
                    details="Fixed: testsigning and debug disabled in BCD.",
                    remediation=self.metadata.remediation,
                    auto_fixable=True
                )
            else:
                return CheckResult(
                    check_id=self.id,
                    status=CheckStatus.FAIL,
                    details=f"Fix failed: {res.stderr}",
                    remediation=self.metadata.remediation,
                    auto_fixable=True
                )
        except Exception as e:
            return CheckResult(
                check_id=self.id,
                status=CheckStatus.FAIL,
                details=f"Fix failed: {str(e)}",
                remediation=self.metadata.remediation,
                auto_fixable=True
            )