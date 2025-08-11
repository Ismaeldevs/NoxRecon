@echo off
echo ===============================================
echo NoxRecon Installation Script for Windows
echo ===============================================
echo.

:: Check if Python is installed
python --version >nul 2>&1
if %errorlevel% neq 0 (
    echo ERROR: Python is not installed or not in PATH
    echo Please install Python 3.8+ from https://python.org
    pause
    exit /b 1
)

:: Check Python version
for /f "tokens=2" %%i in ('python --version 2^>^&1') do set PYTHON_VERSION=%%i
echo Found Python %PYTHON_VERSION%

:: Create virtual environment
echo.
echo Creating virtual environment...
python -m venv noxrecon_env
if %errorlevel% neq 0 (
    echo ERROR: Failed to create virtual environment
    pause
    exit /b 1
)

:: Activate virtual environment
echo Activating virtual environment...
call noxrecon_env\Scripts\activate.bat

:: Upgrade pip
echo.
echo Upgrading pip...
python -m pip install --upgrade pip

:: Install NoxRecon
echo.
echo Installing NoxRecon...
pip install -e .
if %errorlevel% neq 0 (
    echo ERROR: Failed to install NoxRecon
    pause
    exit /b 1
)

:: Check for external dependencies
echo.
echo ===============================================
echo Checking external dependencies...
echo ===============================================

:: Check for curl
curl --version >nul 2>&1
if %errorlevel% neq 0 (
    echo WARNING: curl not found
    echo Download from: https://curl.se/windows/
) else (
    echo ✓ curl found
)

:: Create batch script for easy execution
echo.
echo Creating launcher script...
(
echo @echo off
echo call "%~dp0noxrecon_env\Scripts\activate.bat"
echo noxrecon
echo pause
) > noxrecon.bat

echo.
echo ===============================================
echo Installation completed!
echo ===============================================
echo.
echo To run NoxRecon:
echo 1. Double-click noxrecon.bat
echo 2. Or activate the environment and run: noxrecon
echo.
echo Optional dependencies for full functionality:
echo - Install Git for Windows to get curl
echo - Install ExifTool for metadata extraction
echo - Install whatweb for web technology detection
echo.
pause
