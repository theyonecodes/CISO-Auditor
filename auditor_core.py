import winreg
import os
import ctypes
import subprocess
from datetime import datetime

class SecurityCheck:
    def __init__(self, id, name, category, description, remediation="", auto_fixable=False):
        self.id = id
        self.name = name
        self.category = category
        self.description = description
        self.remediation = remediation
        self.auto_fixable = auto_fixable
        self.status = "PENDING"
        self.details = ""

class AuditorCore:
    CATEGORIES = [
        "Boot, Firmware & Hardware",
        "OS-Level Exploit Mitigations",
        "Deep Persistence Mechanisms",
        "Identity & Access Management",
        "Network, Firewall & Traffic",
        "Process Execution & App Whitelisting",
        "File System & Data Security",
        "Auditing, Logging & Telemetry"
    ]

    def __init__(self):
        self.checks = []
        self._registry_backups = {}
        self.fix_history = []
        self._initialize_checks()

    @staticmethod
    def is_admin():
        try:
            return ctypes.windll.shell32.IsUserAnAdmin() != 0
        except:
            return False

    def _reg_read(self, hive, subkey, name):
        try:
            with winreg.OpenKey(hive, subkey) as key:
                val, _ = winreg.QueryValueEx(key, name)
                return val
        except:
            return None

    def _reg_read_sz(self, hive, subkey, name):
        try:
            with winreg.OpenKey(hive, subkey) as key:
                val, typ = winreg.QueryValueEx(key, name)
                return val if typ == winreg.REG_SZ else None
        except:
            return None

    def _ps_run(self, cmd):
        try:
            res = subprocess.run(
                ["powershell", "-NoProfile", "-Command", cmd],
                capture_output=True, text=True,
                creationflags=subprocess.CREATE_NO_WINDOW
            )
            return res.stdout.strip()
        except:
            return ""

    def _reg_write(self, hive, subkey, name, value, val_type=winreg.REG_DWORD):
        try:
            with winreg.OpenKey(hive, subkey, 0, winreg.KEY_SET_VALUE) as key:
                winreg.SetValueEx(key, name, 0, val_type, value)
                return True
        except:
            return False

    def _reg_write_safe(self, hive, subkey, name, value, val_type=winreg.REG_DWORD):
        key = (hive, subkey, name)
        if key not in self._registry_backups:
            try:
                with winreg.OpenKey(hive, subkey) as k:
                    old_val, old_type = winreg.QueryValueEx(k, name)
                    self._registry_backups[key] = (old_val, old_type)
            except:
                self._registry_backups[key] = None
        return self._reg_write(hive, subkey, name, value, val_type)

    def _restore_reg(self, check_id):
        count = 0
        for (hive, subkey, name), backup in list(self._registry_backups.items()):
            try:
                with winreg.OpenKey(hive, subkey, 0, winreg.KEY_SET_VALUE) as k:
                    if backup is not None:
                        old_val, old_type = backup
                        winreg.SetValueEx(k, name, 0, old_type, old_val)
                    else:
                        winreg.DeleteValue(k, name)
                count += 1
            except:
                pass
        return count

    def _create_restore_point(self):
        desc = "CISO Auditor Pre-Fix"
        cmd = f"Checkpoint-Computer -Description '{desc}' -RestorePointType MODIFY_SETTINGS"
        out, code = self._ps_run_raised(cmd)
        return code == 0

    def undo_fix(self, check_id):
        reverted = self._restore_reg(check_id)
        self.fix_history = [(cid, desc) for cid, desc in self.fix_history if cid != check_id]
        for c in self.checks:
            if c.id == check_id:
                c.status = "PENDING"
                c.details = "Fix reverted. Run scan to re-evaluate."
                break
        return f"Reverted {reverted} registry change(s) for check #{check_id}."

    def undo_all_fixes(self):
        total_regs = 0
        for (hive, subkey, name), backup in list(self._registry_backups.items()):
            try:
                with winreg.OpenKey(hive, subkey, 0, winreg.KEY_SET_VALUE) as k:
                    if backup is not None:
                        old_val, old_type = backup
                        winreg.SetValueEx(k, name, 0, old_type, old_val)
                    else:
                        winreg.DeleteValue(k, name)
                total_regs += 1
            except:
                pass
        self._registry_backups.clear()
        self.fix_history.clear()
        for c in self.checks:
            c.status = "PENDING"
            c.details = "All fixes reverted. Run scan to re-evaluate."
        return f"Reverted {total_regs} registry change(s) across all fixes."

    def _ps_run_raised(self, cmd):
        try:
            res = subprocess.run(
                ["powershell", "-NoProfile", "-Command", cmd],
                capture_output=True, text=True,
                creationflags=subprocess.CREATE_NO_WINDOW
            )
            return res.stdout.strip(), res.returncode
        except:
            return "", -1

    def _check_mitigation_bit(self, val, bit_pos):
        if val is None:
            return None
        byte_idx = bit_pos // 8
        bit_idx = bit_pos % 8
        if isinstance(val, bytes) and byte_idx < len(val):
            return bool(val[byte_idx] & (1 << bit_idx))
        if isinstance(val, int):
            return bool(val & (1 << bit_pos))
        return None

    def _initialize_checks(self):
        self.checks = []

        def add(id, name, category, description):
            self.checks.append(SecurityCheck(id, name, category, description))

        REMEDIATION = {
            1: "Enter BIOS/UEFI -> Boot -> Secure Boot -> Enabled. Reinstall OS if switching from Legacy.",
            2: "Enter BIOS/UEFI -> Security -> TPM -> Enable & Activate. Run 'Initialize-Tpm' in PowerShell.",
            3: "Enable in BIOS: Intel VT-x/AMD-V. Then: Windows Security -> Device Security -> Core Isolation -> On.",
            4: "Enable via Group Policy: Computer Config -> Admin Templates -> System -> Kernel DMA Protection -> Enabled.",
            5: "Check motherboard manufacturer support site for BIOS updates. Apply latest firmware patch.",
            6: "Run: 'manage-bde -on C:' as Admin. Or: Control Panel -> BitLocker Drive Encryption -> Turn On.",
            7: "Run: 'bcdedit /set testsigning off' and 'bcdedit /set debug off' as Admin.",
            8: "ELAM is driver-loaded; ensure Secure Boot is enabled. No user toggle needed on modern Windows.",
            9: "SMM protection is firmware-level. Ensure BIOS is updated to latest version from manufacturer.",
            10: "Enter BIOS/UEFI -> CPU Configuration -> Intel VT-x/AMD SVM -> Enabled. Reboot.",

            11: "Enable via: Computer Config -> Admin Templates -> System -> Mitigation Options -> Enable Force ASLR.",
            12: "DEP is enforced via: System Properties -> Performance -> Data Execution Prevention -> Turn on for all programs.",
            13: "CFG is enabled by default in Win10+. Verify via: Computer Config -> Admin Templates -> System -> CFG -> Enabled.",
            14: "ACG is part of Windows Defender Exploit Guard. Set via: Windows Security -> App & browser control -> Exploit protections.",
            15: "SEHOP is enabled by default. Check via registry or Group Policy. Not commonly disabled.",
            16: "Enable via registry: HKLM\\...\\kernel\\HeapDeCommitFreeBlockThreshold > 0. Set to 65536 or higher.",
            17: "Enable via registry: HKLM\\...\\kernel\\NullPageProtection = 1. Or via Exploit Guard settings.",
            18: "Enable via: Windows Security -> App & browser control -> Exploit Guard -> Win32k System Call Lockdown.",
            19: "Enable via Group Policy: Computer Config -> Admin Templates -> System -> Mitigation Options -> Block Untrusted Fonts.",
            20: "Run as Admin: 'reg add HKLM\\SYSTEM\\CurrentControlSet\\Control\\Lsa /v RunAsPPL /t REG_DWORD /d 2 /f' and reboot.",

            21: "Review scheduled tasks: 'Get-ScheduledTask | Where State -ne Disabled'. Remove suspicious tasks manually.",
            22: "Review: 'Get-WmiObject -Namespace root\\subscription -Class __EventFilter'. Remove rogue filters.",
            23: "Clear via: 'reg delete HKLM\\...\\Windows /v AppInit_DLLs /f'. Default is empty.",
            24: "Remove rogue debuggers: navigate to HKLM\\...\\Image File Execution Options, delete Debugger values.",
            25: "Review entries in Regedit: HKLM\\...\\Run, HKCU\\...\\Run. Remove unknown entries.",
            26: "Wrap service binary paths in quotes: 'sc qc ServiceName'. Fix with reg or sc config.",
            27: "Change service accounts: 'sc config ServiceName obj= \"NT Service\\svc\"' for least privilege.",
            28: "Review: 'Get-BitsTransfer'. Remove suspicious transfers. Stop BITS service temporarily if needed.",
            29: "Reset to defaults: UserInit = 'C:\\Windows\\system32\\userinit.exe,' and Shell = 'explorer.exe'.",
            30: "Review: 'reg query HKCU\\Software\\Classes\\CLSID'. Remove unknown CLSID subkeys.",
            31: "Check: HKLM\\SOFTWARE\\Microsoft\\Active Setup\\Installed Components. Remove unknown stubs.",
            32: "Verify: HKLM\\...\\Winlogon\\Notify empty, AppSetup at default, Taskman at 'taskman.exe'.",
            33: "Check sethc.exe and utilman.exe IFEO keys. Remove any Debugger values if present.",
            34: "Verify Authentication Packages + Security Packages under HKLM\\...\\Lsa. Only standard packages allowed.",
            35: "Check: HKLM\\SYSTEM\\CurrentControlSet\\Control\\Print\\Monitors. Remove unknown DLL monitors.",
            36: "Verify NtpClient DllName = 'C:\\Windows\\system32\\w32time.dll'. Reset if altered.",
            37: "Manually inspect desktop .lnk files with text editor. Look for 'powershell' or 'mshta' args.",
            38: "Check: %APPDATA%\\...\\Startup and %PROGRAMDATA%\\...\\StartUp. Remove unknown items.",
            39: "Check: HKLM\\...\\Edge\\ExtensionInstallForcelist and Chrome\\ExtensionInstallForcelist. Remove unknown.",
            40: "Set via GPO: 'Disable VBA for Office applications' or set VBAWarnings = 2 in registry.",

            41: "Create a standard user account: 'net user UserName Password /add'. Use it for daily tasks.",
            42: "Enable UAC: 'reg add HKLM\\...\\System /v EnableLUA /t REG_DWORD /d 1 /f'. Set ConsentPromptBehaviorAdmin = 2.",
            43: "Disable: 'net user Guest /active:no' as Admin. Verify in lusrmgr.msc.",
            44: "Disable: 'net user Administrator /active:no'. Rename via lusrmgr.msc for extra security.",
            45: "Set to max: 'reg add HKLM\\...\\Lsa /v LMCompatibilityLevel /t REG_DWORD /d 5 /f'. Reboot.",
            46: "Run: 'net accounts /minpwlen:12 /maxpwage:60'. Set complexity via gpedit.msc or secpol.msc.",
            47: "Disable RDP via: System Properties -> Remote -> 'Don't allow connections'. Or set fDenyTSConnections = 1.",
            48: "Restrict remote SAM: 'reg add HKLM\\...\\Lsa /v RestrictRemoteSAM /t REG_DWORD /d 1 /f'.",
            49: "Reduce to 0: 'reg add HKLM\\...\\Winlogon /v CachedLogonsCount /t REG_SZ /d 0 /f'.",
            50: "Enable signing: 'reg add HKLM\\...\\LanmanWorkstation\\Parameters /v EnableSecuritySignature /t REG_DWORD /d 1 /f'. Same for LanmanServer.",

            51: "Enable via: 'Set-NetFirewallProfile -Profile Domain,Public,Private -Enabled True' as Admin.",
            52: "Check: 'reg query HKCU\\...\\Internet Settings /v ProxyEnable'. Set to 0 to disable proxy.",
            53: "Set DNS in Network Settings to secure resolvers (9.9.9.9, 1.1.1.1). Verify no DHCP override.",
            54: "Edit: %SystemRoot%\\System32\\drivers\\etc\\hosts. Remove suspicious entries. Keep only localhost.",
            55: "Disable NetBIOS: Network adapter properties -> IPv4 -> Advanced -> WINS -> Disable. Disable LLMNR via GPO.",
            56: "Disable Teredo: 'netsh interface teredo set state disabled'. Disable ISATAP/6to4 similarly.",
            57: "Run: 'netstat -anob' as Admin. Investigate unknown listening ports with 'Get-Process -Id PID'.",
            58: "Run: 'certlm.msc' -> Trusted Root Certification Authorities. Remove suspicious certificates.",
            59: "Check: 'Get-NetIPsecRule'. Remove any rogue rules with 'Remove-NetIPsecRule -Name Name'.",
            60: "Change RDP port via: HKLM\\...\\RDP-Tcp\\PortNumber. Or restrict via Windows Firewall rules.",
            61: "Uninstall: 'dism /online /disable-feature /featurename:SMB1Protocol' as Admin. Reboot.",
            62: "Disable: 'netsh wlan set autoconfig enabled=no interface=Wi-Fi'. Or via GPO.",
            63: "Check: 'Get-NetAdapter -IncludeHidden'. Remove unknown adapters via Device Manager.",
            64: "Enable via: 'netsh advfirewall firewall add rule name=\"Block ICMP\" protocol=icmpv4 dir=in action=block'.",
            65: "Check: 'arp -a'. Clear static ARP with 'netsh interface ip delete arpcache'. Investigate spoofed MACs.",

            66: "Deploy WDAC/AppLocker via Group Policy. See: https://aka.ms/wdac for policy creation.",
            67: "Set via: 'Set-ExecutionPolicy RemoteSigned -Scope LocalMachine' as Admin.",
            68: "Enable via GPO: Computer Config -> Admin Templates -> Windows Components -> PowerShell -> Script Block Logging -> Enable.",
            69: "Constrained Language is auto-enabled with WDAC/AppLocker. Deploy AppLocker rules to enable.",
            70: "Disable via: 'dism /online /disable-feature /featurename:WindowsScriptHost' or via GPO.",
            71: "Enable via GPO: 'Disable Internet Macros in Office' or set DisableInternetMacros = 1 in registry.",
            72: "Deploy AppLocker/WDAC rules restricting certutil, mshta, regsvr32, etc.",
            73: "Enable Credential Guard: Requires VBS. Enable via GPO or: 'Enable-CredentialGuard' after VBS is on.",
            74: "SmartScreen should be default on. Re-enable: 'reg add HKLM\\...\\System /v EnableSmartScreen /t REG_DWORD /d 1 /f'.",
            75: "Download Sysmon from Sysinternals. Install: 'sysmon64 -i sysmon-config.xml'. Configure rules.",

            76: "Check: 'icacls C:\\'. Remove 'Users' write access if present via 'icacls C:\\ /remove Users'.",
            77: "Enable VSS: 'wmic shadowcopy call create Volume=C:\\'. Configure VSS max size via vssadmin.",
            78: "Scan: 'dir /r C:\\*.*' recursively. Check for hidden streams with Sysinternals Streams.exe.",
            79: "Enable via GPO: Computer Config -> Admin Templates -> System -> Disable Temp Directory Exec.",
            80: "Disable AutoRun via GPO or: 'reg add HKLM\\...\\Explorer /v NoDriveTypeAutoRun /t REG_DWORD /d 255 /f'.",
            81: "Review: 'Get-SmbShare'. Remove unnecessary shares: 'Remove-SmbShare -Name Name -Force'.",
            82: "Disable Clipboard History: Settings -> System -> Clipboard -> Clipboard History -> Off.",
            83: "Set to 0: 'reg add HKLM\\...\\CrashControl /v CrashDumpEnabled /t REG_DWORD /d 0 /f'.",
            84: "Enable: 'reg add HKLM\\...\\Memory Management /v ClearPageFileAtShutdown /t REG_DWORD /d 1 /f'.",
            85: "Configure: Recycle Bin properties -> 'Don't move files to Recycle Bin'. Set NukeOnDelete = 1.",

            86: "Enable: 'auditpol /set /subcategory:\"Process Creation\" /success:enable'. Audit: 'auditpol /set /category:\"Detailed Tracking\"'.",
            87: "Enable: 'reg add HKLM\\...\\Audit /v ProcessCreationIncludeCmdLine /t REG_DWORD /d 1 /f'.",
            88: "Enable if needed: 'auditpol /set /subcategory:\"File System\" /success:enable /failure:enable'. Monitor log volume.",
            89: "Enable: 'auditpol /set /subcategory:\"Credential Validation\" /success:enable /failure:enable'.",
            90: "Enable: 'auditpol /set /subcategory:\"Sensitive Privilege Use\" /success:enable'.",
            91: "Increase: 'wevtutil sl Security /ms:2147483648' (2GB) via Admin PowerShell.",
            92: "Configure Windows Event Forwarding via GPO or: 'wecutil qc' and setup subscriptions.",
            93: "Set to Security: 'reg add HKLM\\...\\DataCollection /v AllowTelemetry /t REG_DWORD /d 0 /f'.",
            94: "Enable Cloud Protection: 'Set-MpPreference -CloudProtectionEnabled 1' as Admin. Verify Tamper Protection.",
            95: "Review exclusions: 'Get-MpPreference | select Exclusion*'. Remove rogue paths/extensions.",
            96: "Enable ASR rules: 'Add-MpPreference -AttackSurfaceReductionRules_Ids RuleID -AttackSurfaceReductionRules_Actions Enabled'.",
            97: "Enable: 'Set-MpPreference -EnableControlledFolderAccess Enabled' as Admin. Add protected folders.",
            98: "Enable: 'Set-MpPreference -EnableNetworkProtection Enabled' as Admin.",
            99: "Install and configure a commercial EDR (CrowdStrike, SentinelOne, Defender for Endpoint, etc.).",
            100: "Run Windows Update: Settings -> Windows Update -> Check for updates. Install all critical/security updates.",
        }
        for c in self.checks:
            c.remediation = REMEDIATION.get(c.id, "Manual investigation required. Consult security team.")

        AUTO_FIXABLE = {20, 42, 45, 50, 61, 67, 68, 74, 82, 87, 93, 94, 96, 97, 98}
        for c in self.checks:
            if c.id in AUTO_FIXABLE:
                c.auto_fixable = True

        # === 1. Boot, Firmware & Hardware (1-10) ===
        add(1, "UEFI Secure Boot", self.CATEGORIES[0], "Is Secure Boot enabled and strictly enforcing signed bootloaders?")
        add(2, "TPM 2.0 Status", self.CATEGORIES[0], "Is the Trusted Platform Module active, provisioned, and owning platform keys?")
        add(3, "Core Isolation / VBS", self.CATEGORIES[0], "Is Virtualization-Based Security running to protect memory?")
        add(4, "DMA Protection", self.CATEGORIES[0], "Is Kernel DMA Protection enabled against malicious Thunderbolt/USB/PCIe devices?")
        add(5, "Firmware Updates", self.CATEGORIES[0], "Are BIOS/UEFI versions patched against known Intel ME / AMD PSP vulnerabilities?")
        add(6, "BitLocker / Device Encryption", self.CATEGORIES[0], "Is the OS drive encrypted with XTS-AES 256?")
        add(7, "Boot Configuration Data (BCD)", self.CATEGORIES[0], "Is testsigning and debug mode strictly disabled?")
        add(8, "Early Launch Anti-Malware (ELAM)", self.CATEGORIES[0], "Are ELAM drivers verified before standard boot drivers?")
        add(9, "SMM (System Management Mode)", self.CATEGORIES[0], "Are SMM protections active against firmware rootkits?")
        add(10, "Hardware Virtualization", self.CATEGORIES[0], "Is VT-x/AMD-V enabled for hardware-backed sandboxing?")

        # === 2. OS-Level Exploit Mitigations (11-20) ===
        add(11, "ASLR (Address Space Layout Randomization)", self.CATEGORIES[1], "Is Mandatory ASLR forced system-wide?")
        add(12, "DEP (Data Execution Prevention)", self.CATEGORIES[1], "Is DEP strictly enforced for all applications?")
        add(13, "CFG (Control Flow Guard)", self.CATEGORIES[1], "Is CFG active to prevent ROP chains?")
        add(14, "ACG (Arbitrary Code Guard)", self.CATEGORIES[1], "Are dynamic code generation and modification blocked?")
        add(15, "SEHOP (Structured Exception Handler Overwrite Protection)", self.CATEGORIES[1], "Is SEHOP globally enabled?")
        add(16, "Heap Spray Allocation", self.CATEGORIES[1], "Are heap spray mitigations enabled?")
        add(17, "Null Page Protection", self.CATEGORIES[1], "Is null page dereference protection active?")
        add(18, "Win32k System Call Lockdown", self.CATEGORIES[1], "Is win32k.sys blocked from untrusted processes?")
        add(19, "Untrusted Fonts Blocking", self.CATEGORIES[1], "Are untrusted GDI fonts blocked outside of the AppContainer?")
        add(20, "LSA Protection (RunAsPPL)", self.CATEGORIES[1], "Is LSA running as a protected process to prevent credential dumping?")

        # === 3. Deep Persistence Mechanisms (21-40) ===
        add(21, "Scheduled Tasks", self.CATEGORIES[2], "Are there anomalous XML triggers in \\Windows\\System32\\Tasks?")
        add(22, "WMI Event Consumers", self.CATEGORIES[2], "Are there rogue WMI EventFilter or CommandLineEventConsumer bindings?")
        add(23, "AppInit_DLLs", self.CATEGORIES[2], "Are global DLL injection hooks empty?")
        add(24, "IFEO (Image File Execution Options)", self.CATEGORIES[2], "Are hidden debuggers attached to critical exes?")
        add(25, "Run & RunOnce Keys", self.CATEGORIES[2], "Are HKLM and HKCU auto-start registry keys verified against known hashes?")
        add(26, "Services (unquoted paths)", self.CATEGORIES[2], "Are there unquoted service paths vulnerable to privilege escalation?")
        add(27, "Service Execution Context", self.CATEGORIES[2], "Are high-risk services running as LocalSystem instead of NetworkService?")
        add(28, "BITS Jobs", self.CATEGORIES[2], "Are Background Intelligent Transfer Service jobs hiding malicious payloads?")
        add(29, "Logon Scripts", self.CATEGORIES[2], "Are UserInit and Shell registry keys set to defaults?")
        add(30, "COM Object Hijacking", self.CATEGORIES[2], "Are rogue CLSIDs overriding standard .dll components in HKCU\\Software\\Classes?")
        add(31, "Active Setup", self.CATEGORIES[2], "Are there hidden Active Setup stubs in the registry for persistent execution?")
        add(32, "Winlogon Helpers", self.CATEGORIES[2], "Are Notify, AppSetup, and Taskman registry keys clean?")
        add(33, "Accessibility Features (StickyKeys)", self.CATEGORIES[2], "Are sethc.exe or utilman.exe replaced with cmd.exe?")
        add(34, "LSA Authentication Packages", self.CATEGORIES[2], "Are unauthorized DLLs listed in Authentication Packages or Security Packages?")
        add(35, "Print Monitors", self.CATEGORIES[2], "Are there malicious print provider DLLs?")
        add(36, "Time Providers", self.CATEGORIES[2], "Are rogue DLLs hiding in W32Time registry entries?")
        add(37, "LNK Shortcut Hijacking", self.CATEGORIES[2], "Do desktop shortcuts pass hidden arguments to powershell?")
        add(38, "Startup Folder", self.CATEGORIES[2], "Are the Startup directories clean?")
        add(39, "Browser Extensions", self.CATEGORIES[2], "Are malicious extensions force-installed via Group Policy?")
        add(40, "Office Macros", self.CATEGORIES[2], "Are Trusted Locations and VBA macro execution restricted?")

        # === 4. Identity & Access Management (41-50) ===
        add(41, "Administrator Privileges", self.CATEGORIES[3], "Does your daily-driver account have UAC split-token enabled?")
        add(42, "UAC Prompts", self.CATEGORIES[3], "Is UAC set to Always Notify with secure desktop dimming?")
        add(43, "Guest Account", self.CATEGORIES[3], "Is the built-in Guest account strictly disabled?")
        add(44, "Administrator Account", self.CATEGORIES[3], "Is the built-in Administrator renamed or disabled?")
        add(45, "LM & NTLMv1", self.CATEGORIES[3], "Are weak LAN Manager hashes disabled (LMCompatibilityLevel = 5)?")
        add(46, "Password Policy", self.CATEGORIES[3], "Is local password complexity and expiration enforced?")
        add(47, "RDP Restrictions", self.CATEGORIES[3], "Is Remote Desktop restricted with NLA enforced?")
        add(48, "SAM Database Permissions", self.CATEGORIES[3], "Are permissions on the SAM registry hive restricted?")
        add(49, "Cached Credentials", self.CATEGORIES[3], "Are cached domain logons set to an appropriate minimum?")
        add(50, "SMB Signing", self.CATEGORIES[3], "Is SMB packet signing required to prevent relay attacks?")

        # === 5. Network, Firewall & Traffic (51-65) ===
        add(51, "Windows Firewall Profiles", self.CATEGORIES[4], "Are Domain, Private, and Public profiles all active?")
        add(52, "Proxy Settings", self.CATEGORIES[4], "Are WinINET and WinHTTP proxies clean?")
        add(53, "DNS Hijacking", self.CATEGORIES[4], "Are DNS servers set to secure resolvers?")
        add(54, "Hosts File", self.CATEGORIES[4], "Is the hosts file free of rogue redirects?")
        add(55, "NetBIOS & LLMNR", self.CATEGORIES[4], "Are legacy broadcast protocols disabled to prevent poisoning?")
        add(56, "IPv6 Transition Tunnels", self.CATEGORIES[4], "Are Teredo, ISATAP, and 6to4 disabled if unused?")
        add(57, "Open Ports", self.CATEGORIES[4], "Are there unauthorized listening ports?")
        add(58, "Rogue Certificates", self.CATEGORIES[4], "Are there untrusted root CAs in the Trusted Root store?")
        add(59, "IPsec Policies", self.CATEGORIES[4], "Are there rogue IPsec rules allowing bypasses?")
        add(60, "RDP Port", self.CATEGORIES[4], "Is RDP port moved from default 3389 or restricted by firewall?")
        add(61, "SMBv1", self.CATEGORIES[4], "Is the highly vulnerable SMBv1 protocol uninstalled?")
        add(62, "Wi-Fi Auto-Connect", self.CATEGORIES[4], "Is auto-connecting to open hotspots disabled?")
        add(63, "Network Adapters", self.CATEGORIES[4], "Are there hidden VPN/Tap adapters silently bridging connections?")
        add(64, "ICMP Traffic", self.CATEGORIES[4], "Are ping responses controlled?")
        add(65, "Rogue ARP Entries", self.CATEGORIES[4], "Is the ARP cache clear of spoofed gateway addresses?")

        # === 6. Process Execution & App Whitelisting (66-75) ===
        add(66, "AppLocker / WDAC", self.CATEGORIES[5], "Is Windows Defender Application Control strictly enforcing signed code?")
        add(67, "PowerShell Execution Policy", self.CATEGORIES[5], "Is PowerShell set to Restricted or RemoteSigned?")
        add(68, "PowerShell Logging", self.CATEGORIES[5], "Are Script Block Logging and Module Logging enabled?")
        add(69, "PowerShell Constrained Language Mode", self.CATEGORIES[5], "Is Constrained Language Mode active to restrict dangerous .NET APIs?")
        add(70, "WSH / Cscript", self.CATEGORIES[5], "Are VBScript and JScript execution engines disabled if unused?")
        add(71, "Macro Execution (MotW)", self.CATEGORIES[5], "Are internet-originated Office Macros blocked via Mark-of-the-Web?")
        add(72, "Living off the Land (LOLBins)", self.CATEGORIES[5], "Are binaries like certutil, mshta, regsvr32 restricted?")
        add(73, "Credential Guard", self.CATEGORIES[5], "Is Credential Guard isolating NTLM hashes and Kerberos tickets?")
        add(74, "SmartScreen", self.CATEGORIES[5], "Is Windows SmartScreen actively blocking unrecognized executables?")
        add(75, "Sysmon", self.CATEGORIES[5], "Is Sysinternals Sysmon installed and tracking process creation telemetry?")

        # === 7. File System & Data Security (76-85) ===
        add(76, "NTFS Permissions", self.CATEGORIES[6], "Are drive roots protected from standard user write access?")
        add(77, "Shadow Copies (VSS)", self.CATEGORIES[6], "Are volume shadow copies active and protected from ransomware deletion?")
        add(78, "Hidden Files / ADS", self.CATEGORIES[6], "Are there malicious Alternate Data Streams attached to legitimate files?")
        add(79, "Temp Folders", self.CATEGORIES[6], "Are %TEMP% executions blocked by policy?")
        add(80, "Removable Media", self.CATEGORIES[6], "Is USB auto-run and external device execution disabled?")
        add(81, "Shared Folders", self.CATEGORIES[6], "Are there overly permissive open network shares?")
        add(82, "Clipboard History", self.CATEGORIES[6], "Is sensitive data flushing properly from clipboard memory?")
        add(83, "Memory Dumps", self.CATEGORIES[6], "Are complete memory dumps disabled to prevent credential extraction?")
        add(84, "Paging File (pagefile.sys)", self.CATEGORIES[6], "Is the paging file set to clear at shutdown?")
        add(85, "Recycle Bin", self.CATEGORIES[6], "Are forensic remnants bypassing standard deletion?")

        # === 8. Auditing, Logging & Telemetry (86-100) ===
        add(86, "Advanced Audit Policy", self.CATEGORIES[7], "Is deep auditing enabled for Process Creation and Termination?")
        add(87, "Command Line Logging", self.CATEGORIES[7], "Is Audit Process Creation capturing full command-line arguments?")
        add(88, "Object Access Auditing", self.CATEGORIES[7], "Is file and registry access auditing active for sensitive paths?")
        add(89, "Account Logon Auditing", self.CATEGORIES[7], "Are failed logons (Event 4625) actively monitored?")
        add(90, "Privilege Use Auditing", self.CATEGORIES[7], "Is use of sensitive privileges like SeDebugPrivilege logged?")
        add(91, "Event Log Size", self.CATEGORIES[7], "Are Security logs set to a high maximum size to prevent rollover?")
        add(92, "Log Forwarding", self.CATEGORIES[7], "Are critical events forwarded to a SIEM system?")
        add(93, "Telemetry Settings", self.CATEGORIES[7], "Are Windows diagnostic data collections restricted to Security level?")
        add(94, "Windows Defender AV Status", self.CATEGORIES[7], "Is Real-time, Cloud-delivered, and Tamper Protection strictly ON?")
        add(95, "Defender Exclusions", self.CATEGORIES[7], "Are there rogue paths or extensions excluded from virus scans?")
        add(96, "Attack Surface Reduction (ASR) Rules", self.CATEGORIES[7], "Are ASR rules blocking child processes from Office and Adobe?")
        add(97, "Controlled Folder Access", self.CATEGORIES[7], "Is ransomware protection active on standard user folders?")
        add(98, "Network Protection", self.CATEGORIES[7], "Is SmartScreen for network filtering malicious IP/domains?")
        add(99, "Endpoint Detection and Response (EDR)", self.CATEGORIES[7], "Is a commercial EDR agent running and healthy?")
        add(100, "Vulnerability Assessment", self.CATEGORIES[7], "Is the system patched against latest CVEs via Windows Update?")

    def run_all_checks(self, progress_callback=None):
        for i, check in enumerate(self.checks):
            self._execute_check(check)
            if progress_callback:
                progress_callback(i + 1, len(self.checks), check)

    def _execute_check(self, check):
        dispatch = {
            1: self._check_secure_boot,
            2: self._check_tpm,
            3: self._check_vbs,
            4: self._check_dma_protection,
            5: self._check_firmware_updates,
            6: self._check_bitlocker,
            7: self._check_bcd,
            8: self._check_elam,
            9: self._check_smm,
            10: self._check_hardware_virtualization,

            11: self._check_aslr,
            12: self._check_dep,
            13: self._check_cfg,
            14: self._check_acg,
            15: self._check_sehop,
            16: self._check_heap_spray,
            17: self._check_null_page,
            18: self._check_win32k_lockdown,
            19: self._check_untrusted_fonts,
            20: self._check_lsa_protection,

            21: self._check_scheduled_tasks,
            22: self._check_wmi_consumers,
            23: self._check_appinit_dlls,
            24: self._check_ifeo,
            25: self._check_run_runonce,
            26: self._check_unquoted_services,
            27: self._check_service_context,
            28: self._check_bits_jobs,
            29: self._check_logon_scripts,
            30: self._check_com_hijacking,
            31: self._check_active_setup,
            32: self._check_winlogon_helpers,
            33: self._check_accessibility,
            34: self._check_lsa_packages,
            35: self._check_print_monitors,
            36: self._check_time_providers,
            37: self._check_lnk_hijacking,
            38: self._check_startup_folder,
            39: self._check_browser_extensions,
            40: self._check_office_macros,

            41: self._check_admin_privileges,
            42: self._check_uac,
            43: self._check_guest_account,
            44: self._check_admin_account,
            45: self._check_ntlm,
            46: self._check_password_policy,
            47: self._check_rdp,
            48: self._check_sam_permissions,
            49: self._check_cached_credentials,
            50: self._check_smb_signing,

            51: self._check_firewall,
            52: self._check_proxy,
            53: self._check_dns,
            54: self._check_hosts,
            55: self._check_netbios_llmnr,
            56: self._check_ipv6_tunnels,
            57: self._check_open_ports,
            58: self._check_rogue_certs,
            59: self._check_ipsec,
            60: self._check_rdp_port,
            61: self._check_smbv1,
            62: self._check_wifi_autoconnect,
            63: self._check_network_adapters,
            64: self._check_icmp,
            65: self._check_arp,

            66: self._check_applocker,
            67: self._check_powershell_ep,
            68: self._check_ps_logging,
            69: self._check_constrained_language,
            70: self._check_wsh,
            71: self._check_macro_execution,
            72: self._check_lolbins,
            73: self._check_credential_guard,
            74: self._check_smart_screen,
            75: self._check_sysmon,

            76: self._check_ntfs_permissions,
            77: self._check_shadow_copies,
            78: self._check_ads,
            79: self._check_temp_folders,
            80: self._check_removable_media,
            81: self._check_shared_folders,
            82: self._check_clipboard,
            83: self._check_memory_dumps,
            84: self._check_pagefile,
            85: self._check_recycle_bin,

            86: self._check_audit_policy,
            87: self._check_cmdline_logging,
            88: self._check_object_access,
            89: self._check_account_logon,
            90: self._check_privilege_use,
            91: self._check_event_log_size,
            92: self._check_log_forwarding,
            93: self._check_telemetry,
            94: self._check_defender_av,
            95: self._check_defender_exclusions,
            96: self._check_asr_rules,
            97: self._check_cfa,
            98: self._check_network_protection,
            99: self._check_edr,
            100: self._check_vulnerability_assessment,
        }

        fn = dispatch.get(check.id)
        if fn:
            try:
                fn(check)
            except Exception as e:
                check.status = "WARNING"
                check.details = f"Error during check: {str(e)}"
        else:
            check.status = "PENDING"
            check.details = "Check not implemented."

    def fix_check(self, check, silent=False):
        if not silent and not self._create_restore_point():
            pass  # non-fatal, proceed anyway

        fix_dispatch = {
            20: self._fix_lsa_protection,
            42: self._fix_uac,
            45: self._fix_ntlm,
            50: self._fix_smb_signing,
            61: self._fix_smbv1,
            67: self._fix_ps_execution_policy,
            68: self._fix_ps_logging,
            74: self._fix_smart_screen,
            82: self._fix_clipboard,
            87: self._fix_cmdline_logging,
            93: self._fix_telemetry,
            94: self._fix_defender_cloud,
            96: self._fix_asr_rules,
            97: self._fix_cfa,
            98: self._fix_network_protection,
        }
        fn = fix_dispatch.get(check.id)
        if fn:
            try:
                result = fn(check)
                if result.startswith("Fixed"):
                    desc = result.split(".")[0]
                    self.fix_history.append((check.id, desc))
                return result
            except Exception as e:
                return f"Fix failed: {str(e)}"
        return "No auto-fix available for this check."

    # ===== Category 1: Boot, Firmware & Hardware (1-10) =====

    def _check_secure_boot(self, check):
        val = self._ps_run("Confirm-SecureBootUEFI")
        if "True" in val:
            check.status, check.details = "PASS", "Secure Boot is fully active and enforcing signed bootloaders."
        elif "False" in val:
            check.status, check.details = "FAIL", "Secure Boot is DISABLED. System vulnerable to bootkits."
        else:
            check.status, check.details = "WARNING", "Cannot verify (run as Admin or unsupported hardware)."

    def _check_tpm(self, check):
        val = self._ps_run("Get-Tpm | Select-Object -ExpandProperty TpmReady")
        if "True" in val:
            check.status, check.details = "PASS", "TPM is ready and provisioned."
        else:
            val2 = self._ps_run("Get-CimInstance -Namespace root/cimv2/Security/MicrosoftTpm -Class Win32_Tpm | Select-Object -ExpandProperty IsEnabled_InitialValue")
            if "True" in val2:
                check.status, check.details = "WARNING", "TPM present but not fully provisioned."
            else:
                check.status, check.details = "FAIL", "TPM not detected or not enabled."

    def _check_vbs(self, check):
        val = self._reg_read(winreg.HKEY_LOCAL_MACHINE, r"SYSTEM\CurrentControlSet\Control\DeviceGuard", "EnableVirtualizationBasedSecurity")
        val2 = self._reg_read(winreg.HKEY_LOCAL_MACHINE, r"SYSTEM\CurrentControlSet\Control\DeviceGuard", "RequirePlatformSecurityFeatures")
        if val == 1 and val2 == 1:
            check.status, check.details = "PASS", "VBS is enabled with secure platform requirements."
        elif val == 1:
            check.status, check.details = "PASS", "VBS is enabled in registry."
        else:
            check.status, check.details = "FAIL", "VBS is disabled. Memory integrity protections off."

    def _check_dma_protection(self, check):
        val = self._ps_run("Get-CimInstance -ClassName Win32_DeviceGuard -Namespace root\\Microsoft\\Windows\\DeviceGuard 2>$null | Select-Object -ExpandProperty MemBootDmaProtection")
        if "1" in val or "True" in val:
            check.status, check.details = "PASS", "Kernel DMA Protection is enabled."
        elif val:
            check.status, check.details = "FAIL", "Kernel DMA Protection is disabled. Thunderbolt/USB attacks possible."
        else:
            check.status, check.details = "WARNING", "DMA protection status unavailable (check via PS as Admin)."

    def _check_firmware_updates(self, check):
        bios = self._ps_run("Get-CimInstance Win32_BIOS | Select-Object -ExpandProperty SMBIOSBIOSVersion")
        name = self._ps_run("Get-CimInstance Win32_BIOS | Select-Object -ExpandProperty Manufacturer")
        if bios:
            check.status, check.details = "WARNING", f"BIOS version: {bios} ({name}). Manually verify against latest CVE database."
        else:
            check.status, check.details = "WARNING", "Unable to retrieve firmware version."

    def _check_bitlocker(self, check):
        val = self._ps_run("Get-BitLockerVolume -MountPoint C: 2>$null | Select-Object -ExpandProperty ProtectionStatus")
        if "On" in val:
            enc = self._ps_run("Get-BitLockerVolume -MountPoint C: 2>$null | Select-Object -ExpandProperty EncryptionMethod")
            check.status, check.details = "PASS", f"OS Drive encrypted. Method: {enc or 'Unknown'}"
        else:
            check.status, check.details = "FAIL", "BitLocker is off or suspended on C: drive."

    def _check_bcd(self, check):
        val = self._ps_run("bcdedit /enum 2>$null | Select-String 'testsigning'")
        val2 = self._ps_run("bcdedit /enum 2>$null | Select-String 'debug'")
        issues = []
        if val:
            issues.append("testsigning ON")
        if val2:
            issues.append("debug ON")
        if issues:
            check.status, check.details = "FAIL", f"BCD has insecure settings: {', '.join(issues)}"
        else:
            check.status, check.details = "PASS", "BCD: testsigning and debug mode are disabled."

    def _check_elam(self, check):
        val = self._reg_read(winreg.HKEY_LOCAL_MACHINE, r"SYSTEM\CurrentControlSet\Control\EarlyLaunch", "DriverLoadPolicy")
        if val is None:
            check.status, check.details = "PASS", "ELAM is active with default policy."
        elif val == 8:
            check.status, check.details = "PASS", "ELAM is enabled (policy: 8 - GoodOnly)."
        elif val == 1:
            check.status, check.details = "WARNING", "ELAM is disabled (policy: 1 - Disabled)."
        else:
            check.status, check.details = "WARNING", f"ELAM policy set to {val}."

    def _check_smm(self, check):
        val = self._reg_read(winreg.HKEY_LOCAL_MACHINE, r"SYSTEM\CurrentControlSet\Control\SecureBoot\State", "UEFISecureBootEnabled")
        if val == 1:
            check.status, check.details = "PASS", "Secure Boot enabled — SMM protections active at firmware level."
        else:
            check.status, check.details = "WARNING", "SMM protection status ambiguous. Requires manual firmware verification."

    def _check_hardware_virtualization(self, check):
        val = self._ps_run("Get-CimInstance Win32_Processor | Select-Object -ExpandProperty VirtualizationFirmwareEnabled")
        if "True" in val:
            check.status, check.details = "PASS", "VT-x/AMD-V is enabled in firmware."
        else:
            check.status, check.details = "FAIL", "Hardware virtualization is disabled in firmware."

    # ===== Category 2: OS-Level Exploit Mitigations (11-20) =====

    def _check_aslr(self, check):
        val = self._reg_read(winreg.HKEY_LOCAL_MACHINE, r"SYSTEM\CurrentControlSet\Control\Session Manager\kernel", "MitigationOptions")
        bit = self._check_mitigation_bit(val, 4)
        if bit is True:
            check.status, check.details = "PASS", "Mandatory ASLR is forced system-wide (Bit 4 set)."
        elif bit is False:
            check.status, check.details = "FAIL", "Mandatory ASLR is NOT forced system-wide."
        else:
            check.status, check.details = "WARNING", "ASLR status could not be determined."

    def _check_dep(self, check):
        val = self._ps_run("Get-CimInstance Win32_OperatingSystem | Select-Object -ExpandProperty DataExecutionPrevention_SupportPolicy")
        if val in ["2", "3"]:
            check.status, check.details = "PASS", f"DEP is strictly enforced (Policy {val} - OptOut/OptIn)."
        elif val == "1":
            check.status, check.details = "FAIL", "DEP is set to AlwaysOff."
        elif val == "0":
            check.status, check.details = "FAIL", "DEP is disabled."
        else:
            check.status, check.details = "WARNING", f"DEP status ambiguous (Policy {val})."

    def _check_cfg(self, check):
        val = self._reg_read(winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options", "EnableCFG")
        if val == 1 or val is None:
            check.status, check.details = "PASS", "Control Flow Guard is active (default enabled)."
        else:
            check.status, check.details = "FAIL", "CFG is disabled system-wide."

    def _check_acg(self, check):
        val = self._reg_read(winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options", "EnableACGT")
        if val == 1:
            check.status, check.details = "PASS", "Arbitrary Code Guard is enabled."
        else:
            check.status, check.details = "WARNING", "ACG is not enabled. Dynamic code generation is permitted."

    def _check_sehop(self, check):
        val = self._reg_read(winreg.HKEY_LOCAL_MACHINE, r"SYSTEM\CurrentControlSet\Control\Session Manager\kernel", "DisableExceptionChainValidation")
        if val == 0 or val is None:
            check.status, check.details = "PASS", "SEHOP is enabled (validation active)."
        else:
            check.status, check.details = "FAIL", "SEHOP is disabled. Exception chain overwrite attacks possible."

    def _check_heap_spray(self, check):
        val = self._reg_read(winreg.HKEY_LOCAL_MACHINE, r"SYSTEM\CurrentControlSet\Control\Session Manager\kernel", "HeapDeCommitFreeBlockThreshold")
        if val and val > 0:
            check.status, check.details = "PASS", "Heap spray mitigations are configured."
        else:
            check.status, check.details = "WARNING", "Heap spray mitigation not explicitly set."

    def _check_null_page(self, check):
        val = self._reg_read(winreg.HKEY_LOCAL_MACHINE, r"SYSTEM\CurrentControlSet\Control\Session Manager\kernel", "NullPageProtection")
        if val == 1:
            check.status, check.details = "PASS", "Null page dereference protection is active."
        else:
            check.status, check.details = "WARNING", "Null page protection not explicitly configured."

    def _check_win32k_lockdown(self, check):
        val = self._reg_read(winreg.HKEY_LOCAL_MACHINE, r"SYSTEM\CurrentControlSet\Control\Session Manager\kernel", "MitigationOptions")
        bit = self._check_mitigation_bit(val, 6)
        if bit is True:
            check.status, check.details = "PASS", "Win32k system calls are blocked from untrusted processes."
        elif bit is False:
            check.status, check.details = "FAIL", "Win32k lockdown is disabled."
        else:
            check.status, check.details = "WARNING", "Win32k status could not be determined."

    def _check_untrusted_fonts(self, check):
        val = self._reg_read(winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Policies\Microsoft\Windows NT\MitigationOptions", "MitigationOptions_FontBocking")
        if val == 1:
            check.status, check.details = "PASS", "Untrusted fonts are blocked outside AppContainer."
        else:
            check.status, check.details = "WARNING", "Untrusted font blocking not enforced."
            # This is actually built into Win10+ but can be checked

    def _check_lsa_protection(self, check):
        val = self._reg_read(winreg.HKEY_LOCAL_MACHINE, r"SYSTEM\CurrentControlSet\Control\Lsa", "RunAsPPL")
        if val == 1:
            check.status, check.details = "PASS", "LSA is running as Protected Process (RunAsPPL). Credentials secure."
        else:
            check.status, check.details = "FAIL", "RunAsPPL is disabled. Mimikatz can dump credentials from lsass.exe."

    # ===== Category 3: Deep Persistence Mechanisms (21-40) =====

    def _check_scheduled_tasks(self, check):
        val = self._ps_run("Get-ScheduledTask | Where-Object {$_.State -ne 'Disabled'} | Measure-Object | Select-Object -ExpandProperty Count")
        if val:
            count = int(val)
            check.status, check.details = "WARNING", f"{count} active scheduled tasks found. Review for anomalous triggers."
        else:
            check.status, check.details = "PASS", "Few or no active scheduled tasks."

    def _check_wmi_consumers(self, check):
        val = self._ps_run("Get-WmiObject -Namespace root\\subscription -Class __EventFilter 2>$null | Measure-Object | Select-Object -ExpandProperty Count")
        val2 = self._ps_run("Get-WmiObject -Namespace root\\subscription -Class CommandLineEventConsumer 2>$null | Measure-Object | Select-Object -ExpandProperty Count")
        if val and int(val) > 0:
            check.status, check.details = "WARNING", f"{val} WMI EventFilter(s) found. Review for persistence."
        else:
            check.status, check.details = "PASS", "No rogue WMI EventFilter subscriptions detected."

    def _check_appinit_dlls(self, check):
        val = self._reg_read(winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows", "AppInit_DLLs")
        if val and str(val).strip():
            check.status, check.details = "FAIL", f"Rogue AppInit_DLLs injection found: {val}"
        else:
            check.status, check.details = "PASS", "No AppInit_DLLs hooks. Clean."

    def _check_ifeo(self, check):
        try:
            k = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options")
            count = 0
            for i in range(200):
                try:
                    app = winreg.EnumKey(k, i)
                    try:
                        sub = winreg.OpenKey(k, app)
                        dbg, _ = winreg.QueryValueEx(sub, "Debugger")
                        count += 1
                    except:
                        pass
                except:
                    break
            if count > 0:
                check.status, check.details = "FAIL", f"{count} IFEO Debugger(s) found — possible hidden debugger persistence."
            else:
                check.status, check.details = "PASS", "No IFEO debugger hijacks found."
        except:
            check.status, check.details = "WARNING", "Access Denied to IFEO registry key."

    def _check_run_runonce(self, check):
        paths = [
            (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run"),
            (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce"),
            (winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\Run"),
            (winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\RunOnce"),
        ]
        entries = []
        for hive, path in paths:
            try:
                k = winreg.OpenKey(hive, path)
                for i in range(100):
                    try:
                        name, val, _ = winreg.EnumValue(k, i)
                        entries.append(f"{name}={val[:60]}")
                    except:
                        break
            except:
                pass
        if entries:
            check.status, check.details = "WARNING", f"{len(entries)} auto-start entry(ies): {', '.join(entries[:5])}"
        else:
            check.status, check.details = "PASS", "No auto-start registry entries found."

    def _check_unquoted_services(self, check):
        val = self._ps_run("Get-CimInstance Win32_Service | Where-Object {$_.PathName -match '^[^\\\"].* .*' -and $_.PathName -notmatch '\\\\.*exe' -and $_.PathName -notmatch '\\\\.*com'} | Select-Object -ExpandProperty Name")
        if val:
            services = val.split('\n')
            check.status, check.details = "FAIL", f"Unquoted service paths: {', '.join(services[:5])}"
        else:
            check.status, check.details = "PASS", "No unquoted service paths detected."

    def _check_service_context(self, check):
        val = self._ps_run("Get-CimInstance Win32_Service | Where-Object {$_.StartName -eq 'LocalSystem' -and $_.PathName -notmatch 'windows'} | Measure-Object | Select-Object -ExpandProperty Count")
        if val and int(val) > 5:
            check.status, check.details = "WARNING", f"{val} non-MS services running as LocalSystem. Review."
        else:
            check.status, check.details = "PASS", "Service execution contexts look reasonable."

    def _check_bits_jobs(self, check):
        val = self._ps_run("Get-BitsTransfer 2>$null | Measure-Object | Select-Object -ExpandProperty Count")
        if val and int(val) > 0:
            check.status, check.details = "WARNING", f"{val} active BITS transfer job(s). Verify legitimacy."
        else:
            check.status, check.details = "PASS", "No active BITS jobs."

    def _check_logon_scripts(self, check):
        userinit = self._reg_read(winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon", "UserInit")
        shell = self._reg_read(winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon", "Shell")
        issues = []
        if userinit and userinit.lower() != r"c:\windows\system32\userinit.exe,":
            issues.append(f"UserInit={userinit}")
        if shell and shell.lower() not in ["explorer.exe", r"c:\windows\system32\explorer.exe"]:
            issues.append(f"Shell={shell}")
        if issues:
            check.status, check.details = "FAIL", f"Logon script hijack detected: {'; '.join(issues)}"
        else:
            check.status, check.details = "PASS", "UserInit and Shell are at defaults."

    def _check_com_hijacking(self, check):
        try:
            k = winreg.OpenKey(winreg.HKEY_CURRENT_USER, r"Software\Classes\CLSID")
            count = 0
            for i in range(100):
                try:
                    winreg.EnumKey(k, i)
                    count += 1
                except:
                    break
            if count > 10:
                check.status, check.details = "WARNING", f"{count} user-scope CLSID entries. Review for COM hijacking."
            else:
                check.status, check.details = "PASS", "Minimal user-scope CLSIDs."
        except:
            check.status, check.details = "PASS", "No user-scope CLSID overrides."

    def _check_active_setup(self, check):
        val = self._reg_read_sz(winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Active Setup\Installed Components", "(Default)")
        if val:
            check.status, check.details = "WARNING", "Active Setup components present. Verify each for persistence."
        else:
            check.status, check.details = "PASS", "No anomalous Active Setup entries."

    def _check_winlogon_helpers(self, check):
        notify = self._reg_read(winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon", "Notify")
        appsetup = self._reg_read_sz(winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon", "AppSetup")
        taskman = self._reg_read(winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon", "Taskman")
        issues = []
        if notify:
            issues.append(f"Notify={notify}")
        if appsetup:
            issues.append(f"AppSetup={appsetup}")
        if taskman:
            issues.append(f"Taskman={taskman}")
        if issues:
            check.status, check.details = "WARNING", f"Winlogon entries found: {'; '.join(issues)}"
        else:
            check.status, check.details = "PASS", "Winlogon helper keys are clean."

    def _check_accessibility(self, check):
        sethc = self._reg_read(winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\sethc.exe", "Debugger")
        utilman = self._reg_read(winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\utilman.exe", "Debugger")
        issues = []
        if sethc:
            issues.append(f"sethc.exe -> {sethc}")
        if utilman:
            issues.append(f"utilman.exe -> {utilman}")
        if issues:
            check.status, check.details = "FAIL", f"Accessibility binary replaced: {'; '.join(issues)}"
        else:
            check.status, check.details = "PASS", "sethc.exe and utilman.exe are not hijacked."

    def _check_lsa_packages(self, check):
        auth = self._reg_read(winreg.HKEY_LOCAL_MACHINE, r"SYSTEM\CurrentControlSet\Control\Lsa", "Authentication Packages")
        sec = self._reg_read(winreg.HKEY_LOCAL_MACHINE, r"SYSTEM\CurrentControlSet\Control\Lsa", "Security Packages")
        issues = []
        if auth:
            pkgs = [p for p in auth if p.lower() not in ["msv1_0", "wdigest", "kerberos", "negoexts", "tspkg", "pku2u"]]
            if pkgs:
                issues.append(f"AuthPkg: {pkgs}")
        if sec:
            pkgs = [p for p in sec if p.lower() not in ["msv1_0", "wdigest", "kerberos", "negoexts", "tspkg", "pku2u", "livessp", "cloudap", ""]]
            if pkgs:
                issues.append(f"SecPkg: {pkgs}")
        if issues:
            check.status, check.details = "FAIL", f"Non-standard LSA packages: {'; '.join(issues)}"
        else:
            check.status, check.details = "PASS", "LSA authentication packages are standard."

    def _check_print_monitors(self, check):
        try:
            k = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"SYSTEM\CurrentControlSet\Control\Print\Monitors")
            count = 0
            for i in range(50):
                try:
                    mon = winreg.EnumKey(k, i)
                    if mon.lower() not in ["standard tcp/ip port", "usb monitor", "local port", "apple", "wsh"]:
                        count += 1
                except:
                    break
            if count > 0:
                check.status, check.details = "WARNING", f"{count} non-standard print monitor(s) found."
            else:
                check.status, check.details = "PASS", "Print monitors are standard."
        except:
            check.status, check.details = "PASS", "Print monitors key accessible and clean."

    def _check_time_providers(self, check):
        try:
            k = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"SYSTEM\CurrentControlSet\Services\W32Time\TimeProviders\NtpClient")
            val, _ = winreg.QueryValueEx(k, "DllName")
            if val and val.lower() != r"c:\windows\system32\w32time.dll":
                check.status, check.details = "FAIL", f"NtpClient DllName altered: {val}"
            else:
                check.status, check.details = "PASS", "Time provider DLLs are default."
        except:
            check.status, check.details = "PASS", "Time provider configuration is standard."

    def _check_lnk_hijacking(self, check):
        desktop = os.path.expandvars(r"%USERPROFILE%\Desktop")
        suspicious = []
        if os.path.isdir(desktop):
            for f in os.listdir(desktop):
                if f.endswith('.lnk'):
                    path = os.path.join(desktop, f)
                    try:
                        with open(path, 'rb') as lf:
                            data = lf.read(4096)
                        ascii_lower = data.decode('latin-1', errors='replace').lower()
                        if 'powershell' in ascii_lower or 'mshta' in ascii_lower or 'rundll32' in ascii_lower or 'cmd' in ascii_lower:
                            suspicious.append(f)
                    except:
                        pass
        if suspicious:
            check.status, check.details = "WARNING", f"Suspicious .lnk(s) found: {', '.join(suspicious[:5])}"
        else:
            check.status, check.details = "PASS", "No suspicious LNK shortcuts on Desktop."

    def _check_startup_folder(self, check):
        paths = [
            os.path.expandvars(r"%APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup"),
            os.path.expandvars(r"%PROGRAMDATA%\Microsoft\Windows\Start Menu\Programs\StartUp"),
        ]
        total = 0
        for p in paths:
            if os.path.isdir(p):
                total += len([f for f in os.listdir(p) if f not in ['desktop.ini', '.']])
        if total > 0:
            check.status, check.details = "WARNING", f"{total} item(s) in Startup folders. Review."
        else:
            check.status, check.details = "PASS", "Startup folders are clean."

    def _check_browser_extensions(self, check):
        edge = self._reg_read(winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Policies\Microsoft\Edge\ExtensionInstallForcelist", "1")
        chrome = self._reg_read(winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Policies\Google\Chrome\ExtensionInstallForcelist", "1")
        if edge or chrome:
            check.status, check.details = "WARNING", "Force-installed browser extensions detected via Group Policy."
        else:
            check.status, check.details = "PASS", "No force-installed browser extensions via policy."

    def _check_office_macros(self, check):
        val = self._reg_read(winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Office\16.0\Common\Security", "VBAWarnings")
        if val == 2 or val is None:
            check.status, check.details = "PASS", "VBA macro warnings are enabled by default."
        else:
            check.status, check.details = "WARNING", f"VBA macro settings: {val}. Verify Trusted Locations."

    # ===== Category 4: Identity & Access Management (41-50) =====

    def _check_admin_privileges(self, check):
        try:
            is_admin = ctypes.windll.shell32.IsUserAnAdmin()
            if is_admin:
                check.status, check.details = "WARNING", "Current user is running as ADMIN. Consider standard user for daily use."
            else:
                check.status, check.details = "PASS", "Current user is running as standard user with UAC split-token."
        except:
            check.status, check.details = "WARNING", "Could not determine admin status."

    def _check_uac(self, check):
        val = self._reg_read(winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System", "EnableLUA")
        val2 = self._reg_read(winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System", "ConsentPromptBehaviorAdmin")
        if val == 1 and val2 == 2:
            check.status, check.details = "PASS", "UAC is enabled at 'Always Notify' with secure desktop."
        elif val == 1:
            check.status, check.details = "WARNING", f"UAC enabled but prompt level is {val2} (should be 2)."
        else:
            check.status, check.details = "FAIL", "UAC is DISABLED. Extreme risk of silent privilege escalation."

    def _check_guest_account(self, check):
        val = self._ps_run("(Get-LocalUser -Name Guest 2>$null).Enabled")
        if "False" in val:
            check.status, check.details = "PASS", "Guest account is disabled."
        elif "True" in val:
            check.status, check.details = "FAIL", "Guest account is ENABLED. Disable immediately."
        else:
            check.status, check.details = "WARNING", "Could not verify Guest account status."

    def _check_admin_account(self, check):
        val = self._ps_run("(Get-LocalUser -Name Administrator 2>$null).Enabled")
        val_renamed = self._ps_run("Get-LocalUser | Where-Object {$_.SID -like '*-500'} | Select-Object -ExpandProperty Name")
        if "False" in val:
            check.status, check.details = "PASS", f"Built-in Administrator is disabled (name: {val_renamed or 'Administrator'})."
        elif "True" in val:
            check.status, check.details = "FAIL", "Built-in Administrator is ENABLED. Disable or rename."
        else:
            check.status, check.details = "WARNING", f"Admin account: {val_renamed or 'Unknown'}"

    def _check_ntlm(self, check):
        val = self._reg_read(winreg.HKEY_LOCAL_MACHINE, r"SYSTEM\CurrentControlSet\Control\Lsa", "LMCompatibilityLevel")
        if val == 5:
            check.status, check.details = "PASS", "LM & NTLMv1 disabled (LMCompatibilityLevel=5)."
        elif val and val >= 3:
            check.status, check.details = "WARNING", f"NTLMv2-only (Level {val}). LM disabled."
        else:
            check.status, check.details = "FAIL", f"NTLM weak (Level {val}). LM hashes may be sent!"

    def _check_password_policy(self, check):
        val = self._ps_run("Get-CimInstance Win32_AccountPolicy | Where-Object {$_.Name -eq 'PasswordComplexity'} | Select-Object -ExpandProperty Setting")
        exp = self._ps_run("net accounts 2>$null | Select-String 'Maximum password age'")
        if "1" in val or "True" in val:
            check.status, check.details = "PASS", "Password complexity is enforced."
        else:
            check.status, check.details = "WARNING", "Password policy review recommended."

    def _check_rdp(self, check):
        val = self._reg_read(winreg.HKEY_LOCAL_MACHINE, r"SYSTEM\CurrentControlSet\Control\Terminal Server", "fDenyTSConnections")
        nla = self._reg_read(winreg.HKEY_LOCAL_MACHINE, r"SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp", "UserAuthentication")
        if val == 1:
            check.status, check.details = "PASS", "RDP is disabled."
        elif nla == 1:
            check.status, check.details = "WARNING", "RDP enabled with NLA. Verify user restrictions."
        else:
            check.status, check.details = "FAIL", "RDP enabled without NLA. Highly risky."

    def _check_sam_permissions(self, check):
        val = self._reg_read(winreg.HKEY_LOCAL_MACHINE, r"SYSTEM\CurrentControlSet\Control\Lsa", "RestrictRemoteSAM")
        if val == 1:
            check.status, check.details = "PASS", "Remote SAM access is restricted."
        else:
            check.status, check.details = "WARNING", "Remote SAM access not explicitly restricted."

    def _check_cached_credentials(self, check):
        val = self._reg_read(winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon", "CachedLogonsCount")
        if val == "0":
            check.status, check.details = "PASS", "Cached credentials are disabled."
        elif val and int(val) <= 2:
            check.status, check.details = "WARNING", f"Cached logons: {val}. Consider setting to 0 for high security."
        elif val:
            check.status, check.details = "WARNING", f"Cached logons: {val}. High count risks credential theft."
        else:
            check.status, check.details = "WARNING", "Cached logons at default (10). Consider reducing."

    def _check_smb_signing(self, check):
        val = self._reg_read(winreg.HKEY_LOCAL_MACHINE, r"SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters", "EnableSecuritySignature")
        val2 = self._reg_read(winreg.HKEY_LOCAL_MACHINE, r"SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters", "EnableSecuritySignature")
        if val == 1 and val2 == 1:
            check.status, check.details = "PASS", "SMB packet signing enabled for both client and server."
        else:
            check.status, check.details = "FAIL", "SMB signing not fully enforced. Relay attacks possible."

    # ===== Category 5: Network, Firewall & Traffic (51-65) =====

    def _check_firewall(self, check):
        val = self._ps_run("Get-NetFirewallProfile | Where-Object {$_.Enabled -eq $False} | Measure-Object | Select-Object -ExpandProperty Count")
        if val and int(val) > 0:
            profiles = self._ps_run("Get-NetFirewallProfile | Where-Object {$_.Enabled -eq $False} | Select-Object -ExpandProperty Name")
            check.status, check.details = "FAIL", f"Firewall disabled on profile(s): {profiles.replace(chr(10), ', ')}"
        else:
            check.status, check.details = "PASS", "All Windows Firewall profiles are active."

    def _check_proxy(self, check):
        val = self._reg_read(winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\Internet Settings", "ProxyEnable")
        server = self._reg_read(winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\Internet Settings", "ProxyServer")
        if val == 1:
            check.status, check.details = "WARNING", f"Proxy enabled: {server}. Verify authorization."
        else:
            check.status, check.details = "PASS", "No system proxy configured."

    def _check_dns(self, check):
        val = self._ps_run("Get-DnsClientServerAddress -AddressFamily IPv4 | Select-Object -ExpandProperty ServerAddresses")
        if val:
            servers = val.replace('\n', ', ')
            check.status, check.details = "WARNING", f"DNS servers: {servers}. Verify against known secure resolvers."
        else:
            check.status, check.details = "WARNING", "Could not retrieve DNS configuration."

    def _check_hosts(self, check):
        hosts_path = r"C:\Windows\System32\drivers\etc\hosts"
        try:
            with open(hosts_path, 'r') as f:
                lines = [l.strip() for l in f if l.strip() and not l.strip().startswith('#')]
            entries = [l for l in lines if not l.startswith('127.') and not l.startswith('::1')]
            if entries:
                check.status, check.details = "WARNING", f"Non-localhost hosts entries: {len(entries)}. Review."
            else:
                check.status, check.details = "PASS", "Hosts file contains only localhost entries."
        except:
            check.status, check.details = "PASS", "Hosts file not modifiable or standard."

    def _check_netbios_llmnr(self, check):
        nbns = self._reg_read(winreg.HKEY_LOCAL_MACHINE, r"SYSTEM\CurrentControlSet\Services\NetBT\Parameters\Interfaces", "NetbiosOptions")
        llmnr = self._reg_read(winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Policies\Microsoft\Windows NT\DNSClient", "EnableLLMNR")
        issues = []
        if nbns != 2:
            issues.append("NetBIOS over TCP/IP may be enabled")
        if llmnr != 0:
            issues.append("LLMNR may be enabled")
        if issues:
            check.status, check.details = "WARNING", '; '.join(issues)
        else:
            check.status, check.details = "PASS", "NetBIOS and LLMNR disabled."

    def _check_ipv6_tunnels(self, check):
        teredo = self._ps_run("Get-NetTeredoConfiguration 2>$null | Select-Object -ExpandProperty Type")
        if teredo:
            check.status, check.details = "WARNING", f"Teredo is active ({teredo}). Consider disabling."
        else:
            check.status, check.details = "PASS", "No IPv6 transition tunnels active."

    def _check_open_ports(self, check):
        val = self._ps_run("netstat -anob 2>$null | Select-String 'LISTENING' | Measure-Object | Select-Object -ExpandProperty Count")
        if val and int(val) > 0:
            check.status, check.details = "WARNING", f"{val} listening ports. Review for unauthorized services."
        else:
            check.status, check.details = "WARNING", "Could not enumerate open ports."

    def _check_rogue_certs(self, check):
        val = self._ps_run("Get-ChildItem -Path Cert:\\CurrentUser\\Root 2>$null | Measure-Object | Select-Object -ExpandProperty Count")
        if val and int(val) > 50:
            check.status, check.details = "WARNING", f"{val} trusted root CAs. Audit for rogue certificates."
        else:
            check.status, check.details = "WARNING", f"Certificate store size: {val or 'Unknown'}. Manual review recommended."

    def _check_ipsec(self, check):
        val = self._ps_run("Get-NetIPsecRule 2>$null | Measure-Object | Select-Object -ExpandProperty Count")
        if val and int(val) > 0:
            check.status, check.details = "WARNING", f"{val} IPsec rule(s) exist. Verify no rogue bypass rules."
        else:
            check.status, check.details = "PASS", "No custom IPsec rules."

    def _check_rdp_port(self, check):
        port = self._reg_read(winreg.HKEY_LOCAL_MACHINE, r"SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp", "PortNumber")
        if port and port == 3389:
            check.status, check.details = "WARNING", "RDP on default port 3389. Consider changing."
        elif port:
            check.status, check.details = "PASS", f"RDP port changed from default ({port})."
        else:
            check.status, check.details = "PASS", "RDP not enabled."

    def _check_smbv1(self, check):
        val = self._ps_run("Get-WindowsOptionalFeature -Online -FeatureName SMB1Protocol 2>$null | Select-Object -ExpandProperty State")
        if "Disabled" in val:
            check.status, check.details = "PASS", "SMBv1 is uninstalled."
        else:
            check.status, check.details = "FAIL", "SMBv1 is installed. High ransomware risk!"

    def _check_wifi_autoconnect(self, check):
        val = self._reg_read(winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Policies\Microsoft\WcmSvc\GroupPolicy", "fBlockNonDomain")
        if val == 1:
            check.status, check.details = "PASS", "Auto-connect to open hotspots is disabled."
        else:
            check.status, check.details = "WARNING", "Auto-connect to open hotspots may be enabled."

    def _check_network_adapters(self, check):
        val = self._ps_run("Get-NetAdapter -Physical | Select-Object -ExpandProperty Name")
        val2 = self._ps_run("Get-NetAdapter -IncludeHidden 2>$null | Where-Object {$_.Name -match 'VPN|Tap|Virtual|Tunnel'} | Select-Object -ExpandProperty Name")
        if val2:
            check.status, check.details = "WARNING", f"Virtual adapters: {val2.replace(chr(10), ', ')}"
        else:
            check.status, check.details = "PASS", f"Physical adapters detected. No hidden virtual adapters."

    def _check_icmp(self, check):
        val = self._ps_run("Get-NetFirewallRule | Where-Object {$_.DisplayName -like '*ICMP*' -and $_.Enabled -eq $True} | Measure-Object | Select-Object -ExpandProperty Count")
        if val and int(val) > 0:
            check.status, check.details = "WARNING", f"{val} ICMP rules active."
        else:
            check.status, check.details = "WARNING", "ICMP configuration not explicitly checked."

    def _check_arp(self, check):
        val = self._ps_run("arp -a 2>$null | Select-String 'dynamic' | Measure-Object | Select-Object -ExpandProperty Count")
        if val and int(val) > 0:
            check.status, check.details = "WARNING", f"{val} dynamic ARP entries. Review for spoofed gateway."
        else:
            check.status, check.details = "WARNING", "ARP cache empty or inaccessible."

    # ===== Category 6: Process Execution & App Whitelisting (66-75) =====

    def _check_applocker(self, check):
        val = self._ps_run("Get-AppLockerPolicy -Effective 2>$null | Select-Object -ExpandProperty RuleCollections")
        if val:
            check.status, check.details = "PASS", "AppLocker / WDAC policy is enforced."
        else:
            check.status, check.details = "FAIL", "No AppLocker or WDAC policy detected. Any code can execute."

    def _check_powershell_ep(self, check):
        val = self._ps_run("Get-ExecutionPolicy")
        if "Restricted" in val or "RemoteSigned" in val or "AllSigned" in val:
            check.status, check.details = "PASS", f"Execution policy is secure ({val})."
        else:
            check.status, check.details = "FAIL", f"Execution policy is weak ({val})."

    def _check_ps_logging(self, check):
        sb = self._reg_read(winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging", "EnableScriptBlockLogging")
        mod = self._reg_read(winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging", "EnableModuleLogging")
        if sb == 1:
            check.status, check.details = "PASS", "PowerShell Script Block Logging (Event 4104) is enabled."
        else:
            check.status, check.details = "FAIL", "PowerShell logging is not fully enabled. Attackers can hide."

    def _check_constrained_language(self, check):
        lang = self._ps_run("$ExecutionContext.SessionState.LanguageMode")
        if "ConstrainedLanguage" in lang or "RestrictedLanguage" in lang:
            check.status, check.details = "PASS", f"PowerShell Constrained Language Mode is active ({lang})."
        else:
            check.status, check.details = "FAIL", f"PowerShell is in {lang or 'FullLanguage'} mode. Dangerous .NET APIs available."

    def _check_wsh(self, check):
        val = self._reg_read(winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows Script Host\Settings", "Enabled")
        if val == 0:
            check.status, check.details = "PASS", "WSH (VBScript/JScript) is disabled."
        else:
            check.status, check.details = "WARNING", "WSH may be enabled. Consider disabling if unused."

    def _check_macro_execution(self, check):
        val = self._reg_read(winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Office\16.0\Common\Security", "DisableInternetMacros")
        if val == 1:
            check.status, check.details = "PASS", "Internet-originated macros are blocked (MotW enforced)."
        elif val == 0:
            check.status, check.details = "FAIL", "Internet macros are allowed. High risk."
        else:
            check.status, check.details = "WARNING", "Macro policy not explicitly configured."

    def _check_lolbins(self, check):
        val = self._reg_read(winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Policies\Microsoft\Windows\Safer\CodeIdentifiers", "DefaultLevel")
        if val == 131072:
            check.status, check.details = "PASS", "LOLBin restrictions may be enforced via Software Restriction Policies."
        else:
            check.status, check.details = "WARNING", "LOLBin usage not explicitly blocked. Review WDAC/AppLocker."

    def _check_credential_guard(self, check):
        val = self._reg_read(winreg.HKEY_LOCAL_MACHINE, r"SYSTEM\CurrentControlSet\Control\DeviceGuard", "EnableVirtualizationBasedSecurity")
        cg = self._reg_read(winreg.HKEY_LOCAL_MACHINE, r"SYSTEM\CurrentControlSet\Control\Lsa", "LsaCfgFlags")
        if val == 1 and cg == 1:
            check.status, check.details = "PASS", "Credential Guard is enabled with UEFI lock."
        elif cg == 1:
            check.status, check.details = "WARNING", "Credential Guard enabled without VBS lock."
        else:
            check.status, check.details = "FAIL", "Credential Guard is not enabled. NTLM/Kerberos hashes in memory."

    def _check_smart_screen(self, check):
        val = self._reg_read(winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Policies\Microsoft\Windows\System", "EnableSmartScreen")
        if val == 1 or val is None:
            check.status, check.details = "PASS", "SmartScreen is active."
        else:
            check.status, check.details = "FAIL", "SmartScreen is disabled by policy."

    def _check_sysmon(self, check):
        val = self._ps_run("Get-CimInstance Win32_Service | Where-Object {$_.Name -eq 'Sysmon' -or $_.DisplayName -like '*Sysmon*'} | Select-Object -ExpandProperty State")
        if "Running" in val:
            check.status, check.details = "PASS", "Sysmon is installed and running."
        else:
            check.status, check.details = "FAIL", "Sysmon is not detected. Deep telemetry not available."

    # ===== Category 7: File System & Data Security (76-85) =====

    def _check_ntfs_permissions(self, check):
        val = self._ps_run("icacls C:\\ 2>$null | Select-String 'BUILTIN\\\\Users' | Select-String '(OI)(CI)(F)'")
        if val:
            check.status, check.details = "FAIL", "Users have write access to C:\\ root."
        else:
            check.status, check.details = "PASS", "C:\\ root is properly restricted from standard users."

    def _check_shadow_copies(self, check):
        val = self._ps_run("Get-CimInstance Win32_ShadowCopy 2>$null | Measure-Object | Select-Object -ExpandProperty Count")
        if val and int(val) > 0:
            check.status, check.details = "PASS", f"{val} shadow copies exist. Ransomware recovery possible."
        else:
            check.status, check.details = "FAIL", "No shadow copies. Ransomware recovery harder."

    def _check_ads(self, check):
        check.status, check.details = "WARNING", "Manual scan with `dir /r` recommended. ADS not scanned."

    def _check_temp_folders(self, check):
        val = self._reg_read(winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Policies\Microsoft\Windows\safer\codeidentifiers", "DisableTemporaryDirectoryExec")
        if val == 1:
            check.status, check.details = "PASS", "%TEMP% execution is blocked by policy."
        else:
            check.status, check.details = "WARNING", "Temp folder execution policy not enforced."

    def _check_removable_media(self, check):
        val = self._reg_read(winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Policies\Microsoft\Windows\RemovableStorageDevices", "Deny_All")
        val2 = self._reg_read(winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer", "NoDriveTypeAutoRun")
        if val == 1:
            check.status, check.details = "PASS", "Removable storage is blocked."
        elif val2 and val2 & 0x4:
            check.status, check.details = "WARNING", "Auto-run disabled but removable media not fully blocked."
        else:
            check.status, check.details = "WARNING", "Removable media controls not enforced."

    def _check_shared_folders(self, check):
        val = self._ps_run("Get-SmbShare 2>$null | Select-Object Name, Path")
        if val:
            check.status, check.details = "WARNING", f"SMB shares exist. Audit permissions."
        else:
            check.status, check.details = "PASS", "No SMB shares."

    def _check_clipboard(self, check):
        val = self._reg_read(winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Policies\Microsoft\Windows\System", "AllowClipboardHistory")
        if val == 0:
            check.status, check.details = "PASS", "Clipboard history is disabled."
        else:
            check.status, check.details = "WARNING", "Clipboard history may record sensitive data."

    def _check_memory_dumps(self, check):
        val = self._reg_read(winreg.HKEY_LOCAL_MACHINE, r"SYSTEM\CurrentControlSet\Control\CrashControl", "CrashDumpEnabled")
        if val == 0:
            check.status, check.details = "PASS", "Complete memory dumps are disabled."
        elif val == 1:
            check.status, check.details = "FAIL", "Complete memory dumps enabled! Credential extraction possible."
        else:
            check.status, check.details = "WARNING", f"Crash dump setting: {val}"

    def _check_pagefile(self, check):
        val = self._reg_read(winreg.HKEY_LOCAL_MACHINE, r"SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management", "ClearPageFileAtShutdown")
        if val == 1:
            check.status, check.details = "PASS", "Page file is cleared at shutdown."
        else:
            check.status, check.details = "WARNING", "Page file not cleared at shutdown."

    def _check_recycle_bin(self, check):
        val = self._reg_read(winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\BitBucket", "NukeOnDelete")
        if val == 1:
            check.status, check.details = "PASS", "Recycle Bin is configured to bypass (files directly deleted)."
        else:
            check.status, check.details = "WARNING", "Standard Recycle Bin. Forensic recovery possible."

    # ===== Category 8: Auditing, Logging & Telemetry (86-100) =====

    def _check_audit_policy(self, check):
        val = self._ps_run("auditpol /get /category:\"Detailed Tracking\" 2>$null | Select-String 'Process Creation'")
        if val and 'Success' in val:
            check.status, check.details = "PASS", "Process Creation auditing is enabled."
        else:
            check.status, check.details = "FAIL", "Process auditing not fully enabled."

    def _check_cmdline_logging(self, check):
        val = self._reg_read(winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit", "ProcessCreationIncludeCmdLine")
        if val == 1:
            check.status, check.details = "PASS", "Command line logging (Event 4688) is active."
        else:
            check.status, check.details = "FAIL", "Command line logging not enabled. Forensic gaps."

    def _check_object_access(self, check):
        val = self._ps_run("auditpol /get /category:\"Object Access\" 2>$null | Select-String 'File System'")
        if val and 'Success' in val:
            check.status, check.details = "WARNING", "File System object access auditing is on. Monitor log volume."
        else:
            check.status, check.details = "WARNING", "Object access auditing not enabled by default."

    def _check_account_logon(self, check):
        val = self._ps_run("auditpol /get /category:\"Account Logon\" 2>$null | Select-String 'Credential Validation'")
        if val and 'Success' in val and 'Failure' in val:
            check.status, check.details = "PASS", "Account logon auditing captures failed logons (Event 4625)."
        else:
            check.status, check.details = "FAIL", "Account logon auditing not fully configured."

    def _check_privilege_use(self, check):
        val = self._ps_run("auditpol /get /category:\"Privilege Use\" 2>$null | Select-String 'Sensitive Privilege Use'")
        if val and 'Success' in val:
            check.status, check.details = "PASS", "Sensitive privilege use (SeDebugPrivilege, etc.) is logged."
        else:
            check.status, check.details = "WARNING", "Privilege use auditing not enabled."

    def _check_event_log_size(self, check):
        val = self._ps_run("Get-WinEvent -ListLog Security 2>$null | Select-Object -ExpandProperty MaximumSizeInBytes")
        if val and int(val) >= 1073741824:
            check.status, check.details = "PASS", f"Security log size: {int(val)//1048576}MB. Adequate."
        elif val:
            check.status, check.details = "WARNING", f"Security log size: {int(val)//1048576}MB. Consider 1024MB+."
        else:
            check.status, check.details = "WARNING", "Could not determine security log size."

    def _check_log_forwarding(self, check):
        val = self._ps_run("Get-WinEvent -ListLog ForwardedEvents 2>$null | Select-Object -ExpandProperty RecordCount")
        if val and int(val) > 0:
            check.status, check.details = "PASS", "Event forwarding appears configured."
        else:
            check.status, check.details = "WARNING", "No forwarded events. SIEM integration not detected."

    def _check_telemetry(self, check):
        val = self._reg_read(winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Policies\Microsoft\Windows\DataCollection", "AllowTelemetry")
        if val == 0 or val == 1:
            check.status, check.details = "PASS", f"Telemetry at Security-only level ({val})."
        elif val == 2:
            check.status, check.details = "WARNING", "Telemetry at Enhanced level. Consider reducing."
        elif val == 3:
            check.status, check.details = "FAIL", "Telemetry at Full level. Excessive data sharing."
        else:
            check.status, check.details = "WARNING", f"Telemetry level: {val}"

    def _check_defender_av(self, check):
        rt = self._ps_run("Get-MpComputerStatus | Select-Object -ExpandProperty RealTimeProtectionEnabled")
        cloud = self._ps_run("Get-MpComputerStatus | Select-Object -ExpandProperty CloudProtectionEnabled")
        tamper = self._ps_run("Get-MpComputerStatus | Select-Object -ExpandProperty IsTamperProtected")
        issues = []
        if "True" not in rt:
            issues.append("Real-Time OFF")
        if "True" not in cloud:
            issues.append("Cloud Protection OFF")
        if "True" not in tamper:
            issues.append("Tamper Protection OFF")
        if issues:
            check.status, check.details = "FAIL", f"Defender issues: {', '.join(issues)}"
        else:
            check.status, check.details = "PASS", "Defender: Real-Time, Cloud, and Tamper Protection are ON."

    def _check_defender_exclusions(self, check):
        val = self._ps_run("Get-MpComputerStatus | Select-Object -ExpandProperty ExclusionPath")
        val2 = self._ps_run("Get-MpComputerStatus | Select-Object -ExpandProperty ExclusionExtension")
        if val:
            check.status, check.details = "FAIL", f"Defender exclusions: {val.replace(chr(10), ', ')}"
        elif val2:
            check.status, check.details = "FAIL", f"Extension exclusions: {val2.replace(chr(10), ', ')}"
        else:
            check.status, check.details = "PASS", "No Defender exclusions configured."

    def _check_asr_rules(self, check):
        val = self._ps_run("Get-MpPreference | Select-Object -ExpandProperty AttackSurfaceReductionRules_Ids 2>$null")
        if val:
            check.status, check.details = "PASS", f"{len(val.split(chr(10)))} ASR rules configured."
        else:
            check.status, check.details = "FAIL", "No ASR rules configured. Office/Adobe child processes not blocked."

    def _check_cfa(self, check):
        val = self._ps_run("Get-MpPreference | Select-Object -ExpandProperty EnableControlledFolderAccess")
        if "1" in val or "True" in val or "Enabled" in val:
            check.status, check.details = "PASS", "Controlled Folder Access is active."
        else:
            check.status, check.details = "FAIL", "Controlled Folder Access is disabled. Ransomware risk."

    def _check_network_protection(self, check):
        val = self._ps_run("Get-MpPreference | Select-Object -ExpandProperty EnableNetworkProtection")
        if "1" in val or "Enabled" in val:
            check.status, check.details = "PASS", "Network Protection is active."
        elif "2" in val or "AuditMode" in val:
            check.status, check.details = "WARNING", "Network Protection in audit mode."
        else:
            check.status, check.details = "FAIL", "Network Protection is disabled."

    def _check_edr(self, check):
        val = self._ps_run("Get-CimInstance Win32_Service | Where-Object {$_.DisplayName -match 'Defender|Sentinel|CrowdStrike|Carbon|Sophos|McAfee|Trend|Symantec|PaloAlto|Microsoft Monitoring|Sense'} | Select-Object -ExpandProperty State")
        if "Running" in val:
            services = [s for s in val.split('\n') if s]
            check.status, check.details = "PASS", f"EDR/AV service running: {services[0][:60]}"
        else:
            check.status, check.details = "FAIL", "No commercial EDR agent detected."

    def _check_vulnerability_assessment(self, check):
        val = self._ps_run("Get-WUApiVersion 2>$null")
        val2 = self._ps_run("Get-CimInstance -ClassName UpdateSession -Namespace root\\Microsoft\\Windows\\WindowsUpdate 2>$null")
        if val or val2:
            check.status, check.details = "WARNING", "Windows Update API available. Verify patches via Windows Update settings."
        else:
            check.status, check.details = "WARNING", "Could not assess patch status. Run Windows Update manually."

    # ===== Auto-Fix Methods =====

    def _fix_lsa_protection(self, check):
        ok = self._reg_write_safe(winreg.HKEY_LOCAL_MACHINE, r"SYSTEM\CurrentControlSet\Control\Lsa", "RunAsPPL", 2)
        if ok:
            check.status = "PASS"
            check.details = "RunAsPPL set to 2. Reboot required for LSA Protection to take effect."
            return "Fixed: LSA Protection enabled. Reboot required."
        return "FAILED: Unable to write registry. Run as Admin."

    def _fix_uac(self, check):
        ok1 = self._reg_write_safe(winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System", "EnableLUA", 1)
        ok2 = self._reg_write_safe(winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System", "ConsentPromptBehaviorAdmin", 2)
        if ok1 and ok2:
            check.status = "PASS"
            check.details = "UAC enabled at 'Always Notify'. Reboot recommended."
            return "Fixed: UAC re-enabled. Reboot recommended."
        return "FAILED: Unable to write UAC registry keys. Run as Admin."

    def _fix_ntlm(self, check):
        ok = self._reg_write_safe(winreg.HKEY_LOCAL_MACHINE, r"SYSTEM\CurrentControlSet\Control\Lsa", "LMCompatibilityLevel", 5)
        if ok:
            check.status = "PASS"
            check.details = "LMCompatibilityLevel set to 5. Reboot required."
            return "Fixed: NTLMv1 disabled. Reboot required."
        return "FAILED: Unable to write registry. Run as Admin."

    def _fix_smb_signing(self, check):
        ok1 = self._reg_write_safe(winreg.HKEY_LOCAL_MACHINE, r"SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters", "EnableSecuritySignature", 1)
        ok2 = self._reg_write_safe(winreg.HKEY_LOCAL_MACHINE, r"SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters", "EnableSecuritySignature", 1)
        ok3 = self._reg_write_safe(winreg.HKEY_LOCAL_MACHINE, r"SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters", "RequireSecuritySignature", 1)
        ok4 = self._reg_write_safe(winreg.HKEY_LOCAL_MACHINE, r"SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters", "RequireSecuritySignature", 1)
        if ok1 and ok2:
            check.status = "PASS"
            check.details = "SMB signing enabled and required. Reboot required."
            return "Fixed: SMB signing enforced. Reboot required."
        return "FAILED: Unable to write SMB signing keys. Run as Admin."

    def _fix_smbv1(self, check):
        out, code = self._ps_run_raised("dism /online /disable-feature /featurename:SMB1Protocol /quiet /norestart")
        if code == 0:
            check.status = "PASS"
            check.details = "SMBv1 uninstalled via DISM. Reboot required."
            return "Fixed: SMBv1 uninstalled. Reboot required."
        return f"FAILED: DISM returned exit code {code}. Run as Admin."

    def _fix_ps_execution_policy(self, check):
        out, code = self._ps_run_raised("Set-ExecutionPolicy RemoteSigned -Scope LocalMachine -Force")
        if code == 0:
            check.status = "PASS"
            check.details = "PowerShell execution policy set to RemoteSigned."
            return "Fixed: PowerShell execution policy set to RemoteSigned."
        return "FAILED: Unable to set execution policy. Run as Admin."

    def _fix_ps_logging(self, check):
        path = r"SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging"
        ok1 = self._reg_write_safe(winreg.HKEY_LOCAL_MACHINE, path, "EnableScriptBlockLogging", 1)
        if ok1:
            check.status = "PASS"
            check.details = "PowerShell Script Block Logging enabled (Event 4104)."
            return "Fixed: PowerShell Script Block Logging enabled."
        return "FAILED: Unable to write registry. Run as Admin."

    def _fix_smart_screen(self, check):
        ok = self._reg_write_safe(winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Policies\Microsoft\Windows\System", "EnableSmartScreen", 1)
        if ok:
            check.status = "PASS"
            check.details = "SmartScreen re-enabled via policy."
            return "Fixed: SmartScreen enabled."
        return "FAILED: Unable to write registry. Run as Admin."

    def _fix_clipboard(self, check):
        ok = self._reg_write_safe(winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Policies\Microsoft\Windows\System", "AllowClipboardHistory", 0)
        if ok:
            check.status = "PASS"
            check.details = "Clipboard history disabled."
            return "Fixed: Clipboard history disabled."
        return "FAILED: Unable to write registry. Run as Admin."

    def _fix_cmdline_logging(self, check):
        ok = self._reg_write_safe(winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit", "ProcessCreationIncludeCmdLine", 1)
        if ok:
            self._ps_run_raised("auditpol /set /subcategory:\"Process Creation\" /success:enable")
            check.status = "PASS"
            check.details = "Command line logging enabled (Event 4688)."
            return "Fixed: Command line auditing enabled."
        return "FAILED: Unable to write registry. Run as Admin."

    def _fix_telemetry(self, check):
        ok = self._reg_write_safe(winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Policies\Microsoft\Windows\DataCollection", "AllowTelemetry", 0)
        if ok:
            check.status = "PASS"
            check.details = "Telemetry set to Security-only level (0)."
            return "Fixed: Telemetry restricted to Security."
        return "FAILED: Unable to write registry. Run as Admin."

    def _fix_defender_cloud(self, check):
        out, code = self._ps_run_raised("Set-MpPreference -CloudProtectionEnabled 1 -Force")
        if code == 0:
            check.status = "PASS"
            check.details = "Defender Cloud Protection re-enabled."
            return "Fixed: Defender Cloud Protection enabled."
        return "FAILED: Unable to update Defender settings. Run as Admin."

    def _fix_asr_rules(self, check):
        rules = "26190899-1602-49e8-8b27-eb1d0a1ce869"  # Block Office child procs
        out, code = self._ps_run_raised(f"Add-MpPreference -AttackSurfaceReductionRules_Ids {rules} -AttackSurfaceReductionRules_Actions Enabled -Force")
        if code == 0:
            check.status = "PASS"
            check.details = "ASR rule 'Block Office child processes' enabled. Add more rules as needed."
            return "Fixed: ASR rule deployed (Block Office child processes)."
        return "FAILED: Unable to configure ASR rules. Run as Admin."

    def _fix_cfa(self, check):
        out, code = self._ps_run_raised("Set-MpPreference -EnableControlledFolderAccess Enabled -Force")
        if code == 0:
            check.status = "PASS"
            check.details = "Controlled Folder Access enabled."
            return "Fixed: Controlled Folder Access activated."
        return "FAILED: Unable to enable CFA. Run as Admin."

    def _fix_network_protection(self, check):
        out, code = self._ps_run_raised("Set-MpPreference -EnableNetworkProtection Enabled -Force")
        if code == 0:
            check.status = "PASS"
            check.details = "Network Protection enabled."
            return "Fixed: Network Protection activated."
        return "FAILED: Unable to enable Network Protection. Run as Admin."
