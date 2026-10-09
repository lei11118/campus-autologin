@echo off
REM ASCII-only launcher: show current status (network / account / task).
setlocal
cd /d "%~dp0"
set "PY="

where py >nul 2>nul
if not errorlevel 1 set "PY=py -3"
if defined PY goto run

where python >nul 2>nul
if not errorlevel 1 set "PY=python"
if defined PY goto run

if exist "%LOCALAPPDATA%\Programs\Python\Python313\python.exe" set "PY=%LOCALAPPDATA%\Programs\Python\Python313\python.exe"
if defined PY goto run
if exist "%LOCALAPPDATA%\Programs\Python\Python312\python.exe" set "PY=%LOCALAPPDATA%\Programs\Python\Python312\python.exe"
if defined PY goto run
if exist "%SystemDrive%\Python314\python.exe" set "PY=%SystemDrive%\Python314\python.exe"
if defined PY goto run
if exist "%SystemDrive%\Python313\python.exe" set "PY=%SystemDrive%\Python313\python.exe"
if defined PY goto run
if exist "%SystemDrive%\Python312\python.exe" set "PY=%SystemDrive%\Python312\python.exe"
if defined PY goto run

echo   [X] Python 3 was not found. Run the setup launcher in this folder first.
pause
exit /b 1

:run
"%PY%" "%~dp0giwifi_auth.py" --status
echo.
pause
