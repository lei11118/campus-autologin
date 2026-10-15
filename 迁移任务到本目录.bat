@echo off
REM ============================================================
REM   Re-point the auto-start tasks at THIS folder (one UAC prompt).
REM   Use this after moving/copying the folder, or if another copy
REM   of this tool stole the task names.
REM   ASCII-only by design (cmd parses .bat with the OEM code page).
REM ============================================================
setlocal
cd /d "%~dp0"
set "PY="
set "PYARG="

where py >nul 2>nul
if not errorlevel 1 set "PY=py"
if not errorlevel 1 set "PYARG=-3"
if defined PY goto run

where python >nul 2>nul
if not errorlevel 1 set "PY=python"
if defined PY goto run

for /d %%p in ("%LOCALAPPDATA%\Programs\Python\Python*") do if not defined PY if exist "%%~fp\python.exe" set "PY=%%~fp\python.exe"
if defined PY goto run
for /d %%p in ("%SystemDrive%\Python*") do if not defined PY if exist "%%~fp\python.exe" set "PY=%%~fp\python.exe"
if defined PY goto run
for /d %%p in ("%ProgramFiles%\Python*") do if not defined PY if exist "%%~fp\python.exe" set "PY=%%~fp\python.exe"
if defined PY goto run

echo.
echo   [X] Python 3 was not found on this computer.
echo       Install it from https://www.python.org/downloads/
echo       (tick "Add python.exe to PATH"), then run this again.
echo.
pause
exit /b 1

:run
echo   Re-pointing the startup tasks at this folder:
echo   %~dp0
echo   A UAC prompt will follow - please click YES.
echo.
"%PY%" %PYARG% "%~dp0giwifi_auth.py" --install-boot
echo.
pause
