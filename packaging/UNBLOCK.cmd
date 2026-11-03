@echo off
setlocal
cd /d "%~dp0"
echo Removing "downloaded from the Internet" marks from this folder...
powershell -NoProfile -ExecutionPolicy Bypass -Command "$root=(Get-Location).Path; Get-ChildItem -LiteralPath $root -Recurse -File -ErrorAction SilentlyContinue | Unblock-File"
if errorlevel 1 (
    echo Could not unblock all files. Try running this file as administrator.
    pause
    exit /b 1
)
echo Done. You can start NetGuardian.exe now.
pause
