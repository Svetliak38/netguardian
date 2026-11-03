@echo off
rem NetGuardian launcher.
rem 1. Uses a writable per-user TEMP directory when the system one is restricted
rem    (a single-file PyInstaller build extracts its libraries there).
rem 2. Keeps the window open on failure so the error can be read.
setlocal
cd /d "%~dp0"

if not exist "%LOCALAPPDATA%\NetGuardian\tmp" mkdir "%LOCALAPPDATA%\NetGuardian\tmp" >nul 2>&1
if exist "%LOCALAPPDATA%\NetGuardian\tmp" (
    set "TEMP=%LOCALAPPDATA%\NetGuardian\tmp"
    set "TMP=%TEMP%"
)

"%~dp0NetGuardian.exe" %*
set "EXITCODE=%ERRORLEVEL%"
if not "%EXITCODE%"=="0" (
    echo.
    echo NetGuardian exited with code %EXITCODE%.
    echo If the program did not start, copy this text into the bug report.
    echo Tried: %~dp0NetGuardian.exe
    pause
)
endlocal
