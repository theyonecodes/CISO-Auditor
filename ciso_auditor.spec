# -*- mode: python ; coding: utf-8 -*-
import os

a = Analysis(
    ['main.py'],
    pathex=[],
    binaries=[],
    datas=[],
    hiddenimports=[],
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=[],
    noarchive=False,
    # Optimize: exclude unnecessary modules
    optimize=1,
)

pyz = PYZ(a.pure)

exe = EXE(
    pyz,
    a.scripts,
    a.binaries,
    a.datas,
    [],
    name='CISO_Auditor',
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=False,  # Disable UPX to avoid EDR false positives
    upx_exclude=[],
    runtime_tmpdir=None,
    console=False,
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    # Azure Trusted Signing / EV Authenticode - set via CI environment variable
    codesign_identity=os.environ.get('AZURE_CODESIGN_IDENTITY'),
    entitlements_file=None,
    icon=None,
)