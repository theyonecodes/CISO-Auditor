"""
System Probe Provider — Abstract interface for OS interactions.
Enables mocking for unit tests and cross-platform support.
"""

from abc import ABC, abstractmethod
from typing import Any, Optional, Dict, List
from dataclasses import dataclass
import winreg


@dataclass
class RegistryValue:
    """Represents a registry value read."""
    value: Any
    value_type: int
    exists: bool = True


@dataclass
class ProcessResult:
    """Result of a process execution."""
    stdout: str
    stderr: str
    returncode: int


class SystemProbeProvider(ABC):
    """
    Abstract base class for OS-level probes.
    Implementations: WindowsProbe (real), MockProbe (tests), LinuxProbe (future).
    """

    # --- Registry ---

    @abstractmethod
    def reg_read(self, hive: int, subkey: str, name: str) -> RegistryValue:
        """Read a registry value."""
        pass

    @abstractmethod
    def reg_write(self, hive: int, subkey: str, name: str, value: Any, val_type: int = winreg.REG_DWORD) -> bool:
        """Write a registry value."""
        pass

    @abstractmethod
    def reg_enum_keys(self, hive: int, subkey: str) -> List[str]:
        """Enumerate subkeys."""
        pass

    @abstractmethod
    def reg_enum_values(self, hive: int, subkey: str) -> List[tuple]:
        """Enumerate values (name, value, type)."""
        pass

    # --- Process Execution ---

    @abstractmethod
    def run_powershell(self, cmd: str, elevated: bool = False) -> ProcessResult:
        """Execute a PowerShell command."""
        pass

    @abstractmethod
    def run_command(self, cmd: List[str], capture: bool = True) -> ProcessResult:
        """Execute a command directly."""
        pass

    # --- System Info ---

    @abstractmethod
    def is_admin(self) -> bool:
        """Check if running with admin privileges."""
        pass

    @abstractmethod
    def get_bios_info(self) -> Dict[str, str]:
        """Get BIOS version and manufacturer."""
        pass

    @abstractmethod
    def get_secure_boot_state(self) -> bool:
        """Check if Secure Boot is enabled."""
        pass

    @abstractmethod
    def get_tpm_state(self) -> bool:
        """Check if TPM is ready."""
        pass

    @abstractmethod
    def get_vbs_state(self) -> bool:
        """Check if VBS is enabled."""
        pass

    @abstractmethod
    def get_bitlocker_state(self, mount_point: str = "C:") -> Dict[str, Any]:
        """Get BitLocker status for a volume."""
        pass

    @abstractmethod
    def get_bcd_settings(self) -> Dict[str, bool]:
        """Get BCD settings (testsigning, debug)."""
        pass

    @abstractmethod
    def get_scheduled_tasks(self, enabled_only: bool = True) -> List[Dict]:
        """Get scheduled tasks."""
        pass

    @abstractmethod
    def get_wmi_consumers(self) -> List[Dict]:
        """Get WMI event filters/consumers."""
        pass

    @abstractmethod
    def get_firewall_profiles(self) -> Dict[str, bool]:
        """Get firewall profile states."""
        pass

    @abstractmethod
    def get_defender_preferences(self) -> Dict[str, Any]:
        """Get Windows Defender preferences."""
        pass

    @abstractmethod
    def get_audit_policy(self) -> Dict[str, str]:
        """Get advanced audit policy settings."""
        pass

    @abstractmethod
    def get_event_log_size(self, log_name: str = "Security") -> int:
        """Get event log max size in bytes."""
        pass

    @abstractmethod
    def get_network_adapters(self) -> List[Dict]:
        """Get network adapter info."""
        pass

    @abstractmethod
    def get_listening_ports(self) -> List[Dict]:
        """Get listening ports with process info."""
        pass

    @abstractmethod
    def get_rogue_certificates(self) -> List[Dict]:
        """Get untrusted root certificates."""
        pass

    @abstractmethod
    def get_applocker_wdac_state(self) -> Dict[str, Any]:
        """Get AppLocker/WDAC policy state."""
        pass

    @abstractmethod
    def get_sysmon_state(self) -> bool:
        """Check if Sysmon is installed and running."""
        pass

    @abstractmethod
    def create_restore_point(self, description: str) -> bool:
        """Create a system restore point."""
        pass

    @abstractmethod
    def export_bcd(self, path: str) -> bool:
        """Export BCD to file."""
        pass


class WindowsProbe(SystemProbeProvider):
    """Real Windows implementation using winreg, subprocess, WMI."""

    def reg_read(self, hive: int, subkey: str, name: str) -> RegistryValue:
        try:
            with winreg.OpenKey(hive, subkey) as key:
                val, typ = winreg.QueryValueEx(key, name)
                return RegistryValue(value=val, value_type=typ, exists=True)
        except FileNotFoundError:
            return RegistryValue(value=None, value_type=0, exists=False)
        except Exception:
            return RegistryValue(value=None, value_type=0, exists=False)

    def reg_write(self, hive: int, subkey: str, name: str, value: Any, val_type: int = winreg.REG_DWORD) -> bool:
        try:
            with winreg.OpenKey(hive, subkey, 0, winreg.KEY_SET_VALUE) as key:
                winreg.SetValueEx(key, name, 0, val_type, value)
            return True
        except Exception:
            return False

    def reg_enum_keys(self, hive: int, subkey: str) -> List[str]:
        keys = []
        try:
            with winreg.OpenKey(hive, subkey) as key:
                i = 0
                while True:
                    try:
                        keys.append(winreg.EnumKey(key, i))
                        i += 1
                    except OSError:
                        break
        except Exception:
            pass
        return keys

    def reg_enum_values(self, hive: int, subkey: str) -> List[tuple]:
        vals = []
        try:
            with winreg.OpenKey(hive, subkey) as key:
                i = 0
                while True:
                    try:
                        vals.append(winreg.EnumValue(key, i))
                        i += 1
                    except OSError:
                        break
        except Exception:
            pass
        return vals

    def run_powershell(self, cmd: str, elevated: bool = False) -> ProcessResult:
        import subprocess
        try:
            ps_cmd = ["powershell", "-NoProfile", "-Command", cmd]
            if elevated:
                # For elevated, would need different approach (runas)
                pass
            res = subprocess.run(
                ps_cmd,
                capture_output=True, text=True,
                creationflags=subprocess.CREATE_NO_WINDOW
            )
            return ProcessResult(stdout=res.stdout.strip(), stderr=res.stderr.strip(), returncode=res.returncode)
        except Exception as e:
            return ProcessResult(stdout="", stderr=str(e), returncode=-1)

    def run_command(self, cmd: List[str], capture: bool = True) -> ProcessResult:
        import subprocess
        try:
            res = subprocess.run(cmd, capture_output=capture, text=True)
            return ProcessResult(stdout=res.stdout.strip(), stderr=res.stderr.strip(), returncode=res.returncode)
        except Exception as e:
            return ProcessResult(stdout="", stderr=str(e), returncode=-1)

    def is_admin(self) -> bool:
        import ctypes
        try:
            return ctypes.windll.shell32.IsUserAnAdmin() != 0
        except:
            return False

    def get_bios_info(self) -> Dict[str, str]:
        res = self.run_powershell("Get-CimInstance Win32_BIOS | Select-Object SMBIOSBIOSVersion, Manufacturer | ConvertTo-Json")
        if res.returncode == 0 and res.stdout:
            import json
            try:
                data = json.loads(res.stdout)
                return {"version": data.get("SMBIOSBIOSVersion", ""), "manufacturer": data.get("Manufacturer", "")}
            except:
                pass
        return {"version": "", "manufacturer": ""}

    def get_secure_boot_state(self) -> bool:
        res = self.run_powershell("Confirm-SecureBootUEFI")
        return "True" in res.stdout

    def get_tpm_state(self) -> bool:
        res = self.run_powershell("Get-Tpm | Select-Object -ExpandProperty TpmReady")
        return "True" in res.stdout

    def get_vbs_state(self) -> bool:
        val = self.reg_read(winreg.HKEY_LOCAL_MACHINE, r"SYSTEM\CurrentControlSet\Control\DeviceGuard", "EnableVirtualizationBasedSecurity")
        return val.exists and val.value == 1

    def get_bitlocker_state(self, mount_point: str = "C:") -> Dict[str, Any]:
        res = self.run_powershell(f"Get-BitLockerVolume -MountPoint {mount_point} 2>$null | Select-Object ProtectionStatus, EncryptionMethod | ConvertTo-Json")
        if res.returncode == 0 and res.stdout:
            import json
            try:
                data = json.loads(res.stdout)
                return {"protection_status": data.get("ProtectionStatus", ""), "encryption_method": data.get("EncryptionMethod", "")}
            except:
                pass
        return {"protection_status": "", "encryption_method": ""}

    def get_bcd_settings(self) -> Dict[str, bool]:
        res1 = self.run_powershell("bcdedit /enum 2>$null | Select-String 'testsigning'")
        res2 = self.run_powershell("bcdedit /enum 2>$null | Select-String 'debug'")
        return {"testsigning": "testsigning" in res1.stdout, "debug": "debug" in res2.stdout}

    def get_scheduled_tasks(self, enabled_only: bool = True) -> List[Dict]:
        filter_cmd = "Where-Object {$_.State -ne 'Disabled'}" if enabled_only else ""
        res = self.run_powershell(f"Get-ScheduledTask | {filter_cmd} | Select-Object TaskName, State, TaskPath | ConvertTo-Json")
        if res.returncode == 0 and res.stdout:
            import json
            try:
                return json.loads(res.stdout)
            except:
                pass
        return []

    def get_wmi_consumers(self) -> List[Dict]:
        res = self.run_powershell("Get-WmiObject -Namespace root\\subscription -Class __EventFilter 2>$null | Select-Object Name, Query | ConvertTo-Json")
        if res.returncode == 0 and res.stdout:
            import json
            try:
                return json.loads(res.stdout)
            except:
                pass
        return []

    def get_firewall_profiles(self) -> Dict[str, bool]:
        res = self.run_powershell("Get-NetFirewallProfile | Select-Object Name, Enabled | ConvertTo-Json")
        if res.returncode == 0 and res.stdout:
            import json
            try:
                data = json.loads(res.stdout)
                return {item["Name"]: item["Enabled"] for item in data}
            except:
                pass
        return {}

    def get_defender_preferences(self) -> Dict[str, Any]:
        res = self.run_powershell("Get-MpPreference | Select-Object CloudProtectionEnabled, RealTimeScanDirection, EnableControlledFolderAccess, EnableNetworkProtection, AttackSurfaceReductionRules_Ids, AttackSurfaceReductionRules_Actions, ExclusionPath, ExclusionExtension | ConvertTo-Json")
        if res.returncode == 0 and res.stdout:
            import json
            try:
                return json.loads(res.stdout)
            except:
                pass
        return {}

    def get_audit_policy(self) -> Dict[str, str]:
        res = self.run_powershell("auditpol /get /category:* /r 2>$null | ConvertFrom-Csv | ConvertTo-Json")
        if res.returncode == 0 and res.stdout:
            import json
            try:
                data = json.loads(res.stdout)
                return {item["Subcategory"]: item["SuccessAudit"] + "/" + item["FailureAudit"] for item in data}
            except:
                pass
        return {}

    def get_event_log_size(self, log_name: str = "Security") -> int:
        res = self.run_powershell(f"wevtutil gl {log_name} 2>$null | Select-String 'maxSize'")
        import re
        match = re.search(r'maxSize\s*:\s*(\d+)', res.stdout)
        return int(match.group(1)) if match else 0

    def get_network_adapters(self) -> List[Dict]:
        res = self.run_powershell("Get-NetAdapter -IncludeHidden | Select-Object Name, InterfaceDescription, Status, MacAddress | ConvertTo-Json")
        if res.returncode == 0 and res.stdout:
            import json
            try:
                return json.loads(res.stdout)
            except:
                pass
        return []

    def get_listening_ports(self) -> List[Dict]:
        res = self.run_powershell("Get-NetTCPConnection -State Listen | Select-Object LocalAddress, LocalPort, OwningProcess | ConvertTo-Json")
        if res.returncode == 0 and res.stdout:
            import json
            try:
                return json.loads(res.stdout)
            except:
                pass
        return []

    def get_rogue_certificates(self) -> List[Dict]:
        res = self.run_powershell("Get-ChildItem Cert:\\LocalMachine\\Root | Where-Object {$_.Subject -notlike '*Microsoft*' -and $_.Subject -notlike '*Windows*'} | Select-Object Subject, Thumbprint, NotAfter | ConvertTo-Json")
        if res.returncode == 0 and res.stdout:
            import json
            try:
                return json.loads(res.stdout)
            except:
                pass
        return []

    def get_applocker_wdac_state(self) -> Dict[str, Any]:
        res = self.run_powershell("Get-CimInstance -Namespace root\\Microsoft\\Windows\\CI -ClassName PS_PolicyProvider 2>$null | Select-Object InstanceId, PolicyName, Enabled | ConvertTo-Json")
        if res.returncode == 0 and res.stdout:
            import json
            try:
                return json.loads(res.stdout)
            except:
                pass
        return {}

    def get_sysmon_state(self) -> bool:
        import psutil
        for proc in psutil.process_iter(['name']):
            if proc.info['name'] and 'sysmon' in proc.info['name'].lower():
                return True
        return False

    def create_restore_point(self, description: str) -> bool:
        res = self.run_powershell(f"Checkpoint-Computer -Description '{description}' -RestorePointType MODIFY_SETTINGS")
        return res.returncode == 0

    def export_bcd(self, path: str) -> bool:
        res = self.run_powershell(f"bcdedit /export \"{path}\"")
        return res.returncode == 0