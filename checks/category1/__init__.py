"""
Category 1: Boot, Firmware & Hardware checks.
"""

# Import all category 1 checks for registration
from .check_01_secure_boot import SecureBootCheck
from .check_02_tpm import TPMCheck
from .check_03_vbs import VBSCheck
from .check_04_dma import DMProtectionCheck
from .check_05_firmware import FirmwareCheck
from .check_06_bitlocker import BitLockerCheck
from .check_07_bcd import BCDCheck
from .check_08_elam import ELAMCheck
from .check_09_smm import SMMCheck
from .check_10_hv import HVCheck

__all__ = [
    "SecureBootCheck",
    "TPMCheck",
    "VBSCheck",
    "DMProtectionCheck",
    "FirmwareCheck",
    "BitLockerCheck",
    "BCDCheck",
    "ELAMCheck",
    "SMMCheck",
    "HVCheck",
]