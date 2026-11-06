@echo off
chcp 65001 >nul
setlocal
net session >nul 2>&1
if errorlevel 1 (
    powershell -NoProfile -Command "Start-Process -FilePath '%~f0' -Verb RunAs"
    exit /b
)
cd /d "%~dp0"
if exist "%~dp0NetGuardian.exe" (
    "%~dp0NetGuardian.exe" repair --yes --timeout 5
) else (
    python -m netguardian repair --yes --timeout 5
)
echo.
pause
endlocal
