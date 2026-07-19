@echo off
setlocal EnableExtensions EnableDelayedExpansion
chcp 65001 >nul 2>&1
cd /d "%~dp0"
title AI Based Cybercrime Prediction System

cls
echo ================================================================
echo          AI BASED CYBERCRIME PREDICTION SYSTEM
echo ================================================================
echo.
echo Project folder:
echo %CD%
echo.

if not exist "%CD%\portable_server.py" goto :incomplete
if not exist "%CD%\models\portable_prediction_model.pkl.gz" goto :incomplete
if not exist "%CD%\models\portable_text_classifier.json.gz" goto :incomplete
if not exist "%CD%\models\real_incident_multilabel_classifier.json.gz" goto :incomplete
if not exist "%CD%\nlp_classifier.py" goto :incomplete
if not exist "%CD%\web\index.html" goto :incomplete

if not exist "%CD%\outputs\logs" mkdir "%CD%\outputs\logs" >nul 2>&1
if not exist "%CD%\outputs\text_predictions" mkdir "%CD%\outputs\text_predictions" >nul 2>&1
if not exist "%CD%\outputs\text_evaluations" mkdir "%CD%\outputs\text_evaluations" >nul 2>&1
if not exist "%CD%\outputs\real_incident_evaluations" mkdir "%CD%\outputs\real_incident_evaluations" >nul 2>&1
if not exist "%CD%\outputs\realworld_training" mkdir "%CD%\outputs\realworld_training" >nul 2>&1
if not exist "%CD%\data\uploads" mkdir "%CD%\data\uploads" >nul 2>&1
if not exist "%CD%\data\real\raw" mkdir "%CD%\data\real\raw" >nul 2>&1

set "PYTHON_EXE="

rem Prefer the Python launcher when available. Native ARM64 and x64 are both supported.
where py.exe >nul 2>&1
if not errorlevel 1 (
  for %%V in (3.14 3.13 3.12 3.11 3.10) do (
    if not defined PYTHON_EXE (
      for /f "usebackq delims=" %%P in (`py -%%V -c "import sys; print(sys.executable)" 2^>nul`) do set "PYTHON_EXE=%%P"
    )
  )
)

rem Check normal PATH commands.
if not defined PYTHON_EXE (
  for %%C in (python.exe python3.exe) do (
    if not defined PYTHON_EXE (
      for /f "delims=" %%P in ('where %%C 2^>nul') do (
        echo %%P | findstr /i "WindowsApps" >nul || set "PYTHON_EXE=%%P"
      )
    )
  )
)

rem Check common per-user installations, including native Windows ARM64 Python.
if not defined PYTHON_EXE (
  for %%P in (
    "%LOCALAPPDATA%\Programs\Python\Python314-arm64\python.exe"
    "%LOCALAPPDATA%\Programs\Python\Python313-arm64\python.exe"
    "%LOCALAPPDATA%\Programs\Python\Python312-arm64\python.exe"
    "%LOCALAPPDATA%\Programs\Python\Python311-arm64\python.exe"
    "%LOCALAPPDATA%\Programs\Python\Python314\python.exe"
    "%LOCALAPPDATA%\Programs\Python\Python313\python.exe"
    "%LOCALAPPDATA%\Programs\Python\Python312\python.exe"
    "%LOCALAPPDATA%\Programs\Python\Python311\python.exe"
  ) do (
    if not defined PYTHON_EXE if exist "%%~P" set "PYTHON_EXE=%%~P"
  )
)

if not defined PYTHON_EXE goto :python_missing

"%PYTHON_EXE%" -c "import sys,struct; assert sys.version_info >= (3,10); assert struct.calcsize('P')*8==64" >nul 2>&1
if errorlevel 1 goto :python_invalid

for /f "delims=" %%V in ('"%PYTHON_EXE%" -c "import platform,sysconfig; print(platform.python_version()+' | '+sysconfig.get_platform())"') do set "PYINFO=%%V"
echo Python: %PYTHON_EXE%
echo Runtime: !PYINFO!
echo.
echo Verifying the portable model bundle and real-world training modules...
"%PYTHON_EXE%" "%CD%\verify_system.py" > "%CD%\outputs\logs\startup_verification.json" 2>&1
if errorlevel 1 (
  echo ERROR: Model verification failed.
  start "" notepad.exe "%CD%\outputs\logs\startup_verification.json"
  pause
  exit /b 5
)
echo Verification passed.
echo.
echo Starting the network forecasting and NLP text intelligence modules.
echo No package installation is required.
echo Keep this window open while using the system.
echo.

"%PYTHON_EXE%" "%CD%\portable_server.py"
set "EXIT_CODE=%ERRORLEVEL%"
if "%EXIT_CODE%"=="0" exit /b 0

echo.
echo The application stopped with error code %EXIT_CODE%.
if exist "%CD%\outputs\logs\portable_server.log" start "" notepad.exe "%CD%\outputs\logs\portable_server.log"
pause
exit /b %EXIT_CODE%

:incomplete
echo ERROR: The extracted application is incomplete.
echo Extract the entire ZIP before starting it. Do not run START from inside the ZIP.
pause
exit /b 2

:python_missing
echo ERROR: A 64-bit Python 3.10 or newer installation was not found.
echo Your existing native ARM64 Python is supported; no x64 emulation is required.
echo Install Python from python.org or Microsoft Store, then start again.
pause
exit /b 3

:python_invalid
echo ERROR: The detected Python is not a supported 64-bit Python 3.10 or newer installation.
echo Detected path: %PYTHON_EXE%
pause
exit /b 4
