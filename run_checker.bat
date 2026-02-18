@echo off
REM Check-Host TCP Scanner — Windows Launcher
REM Usage: run_checker.bat [ips] [port]
REM   or just double-click to run interactively

python "%~dp0access_checker.py" %*
if %ERRORLEVEL% neq 0 (
    echo.
    echo Python not found. Install Python 3.8+ from https://python.org
    pause
)
