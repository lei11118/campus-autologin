@echo off
REM ASCII-only launcher: show current status (network / account / task).
setlocal
cd /d "%~dp0"
set "PY="
set "PYARG="

REM the "py" launcher: keep exe and args separate ("%PY%" must never hold "py -3")
where py >nul 2>nul
if not errorlevel 1 set "PY=py"
if not errorlevel 1 set "PYARG=-3"
if defined PY goto run

where python >nul 2>nul
if not errorlevel 1 set "PY=python"
if defined PY goto run

REM common install locations (version-agnostic: any Python 3.x)
for /d %%p in ("%LOCALAPPDATA%\Programs\Python\Python*") do if not defined PY if exist "%%~fp\python.exe" set "PY=%%~fp\python.exe"
if defined PY goto run
for /d %%p in ("%SystemDrive%\Python*") do if not defined PY if exist "%%~fp\python.exe" set "PY=%%~fp\python.exe"
if defined PY goto run
for /d %%p in ("%ProgramFiles%\Python*") do if not defined PY if exist "%%~fp\python.exe" set "PY=%%~fp\python.exe"
if defined PY goto run

echo   [X] Python 3 was not found. Run the setup launcher in this folder first.
pause
exit /b 1

:run
"%PY%" %PYARG% "%~dp0giwifi_auth.py" --status
echo.
pause
