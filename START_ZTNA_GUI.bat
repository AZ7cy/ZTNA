@echo off
setlocal
cd /d "%~dp0"
set "ZTNA_DEMO=1"
set "ZTNA_DEMO_OTP=1"
echo Starting the native ZTNA desktop GUI...
echo No browser or localhost web page is used.
where python >nul 2>nul
if %errorlevel%==0 (
  python ztna_lab_v2.py gui
) else (
  py -3 ztna_lab_v2.py gui
)
if errorlevel 1 (
  echo.
  echo ZTNA exited with an error. Check Python 3.10+ and Tkinter installation.
  pause
)
endlocal
