@echo off
echo ========================================
echo  CISO Security Auditor - Build Script
echo ========================================
echo.

REM Check if Python is available
python --version >nul 2>&1
if errorlevel 1 (
    echo Python not found. Install Python 3.8+ from python.org
    pause
    exit /b 1
)

REM Check if PyInstaller is installed
pip show pyinstaller >nul 2>&1
if errorlevel 1 (
    echo Installing PyInstaller...
    pip install pyinstaller
)

echo Building CISO_Auditor.exe...
echo.

pyinstaller --onefile --noconsole --name CISO_Auditor main.py

echo.
echo ========================================
echo  Build complete!
echo  Find CISO_Auditor.exe in dist\ folder
echo ========================================
pause
