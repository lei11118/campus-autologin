@echo off
REM =====================================================================
REM   Campus Net Auto-Auth  -  SETUP WIZARD launcher
REM   This launcher is intentionally ASCII-only (cmd.exe parses .bat files
REM   with the ANSI/OEM code page, so Chinese text here would show up as
REM   garbage). All Chinese UI text is printed by Python instead.
REM   It also auto-detects Python so the folder can be copied anywhere.
REM =====================================================================
setlocal
cd /d "%~dp0"
set "PY="

REM 1) the "py" launcher (python.org installs)
where py >nul 2>nul
if not errorlevel 1 set "PY=py -3"
if defined PY goto run

REM 2) python.exe on PATH
where python >nul 2>nul
if not errorlevel 1 set "PY=python"
if defined PY goto run

REM 3) common install locations (version-agnostic: any Python 3.x)
for /d %%p in ("%LOCALAPPDATA%\Programs\Python\Python*") do if not defined PY if exist "%%~fp\python.exe" set "PY=%%~fp\python.exe"
if defined PY goto run
for /d %%p in ("%SystemDrive%\Python*") do if not defined PY if exist "%%~fp\python.exe" set "PY=%%~fp\python.exe"
if defined PY goto run
for /d %%p in ("%ProgramFiles%\Python*") do if not defined PY if exist "%%~fp\python.exe" set "PY=%%~fp\python.exe"
if defined PY goto run

echo.
echo   [X] Python 3 was not found on this computer.
echo       Please install Python 3 from https://www.python.org/downloads/
echo       (tick "Add python.exe to PATH" during install), then run this again.
echo.
pause
exit /b 1

:run
"%PY%" "%~dp0giwifi_auth.py" --setup
if errorlevel 1 echo   [i] the program exited with code %errorlevel%
echo.
pause
