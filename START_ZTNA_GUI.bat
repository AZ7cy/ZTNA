@echo off
setlocal
cd /d "%~dp0"
set "ZTNA_DEMO=1"
set "ZTNA_DEMO_OTP=1"
echo Starting the native ZTNA desktop GUI...
echo No browser or localhost web page is used.
where python >nul 2>nul
if %errorlevel%==0 (
  python ztna.py gui
) else (
  py -3 ztna.py gui
)
if errorlevel 1 (
  echo.
  echo ZTNA exited with an error ^(see the message above^).
  echo It needs Python 3.10+ with Tkinter, and the cryptography package:
  echo     python -m pip install cryptography
  pause
)
endlocal
