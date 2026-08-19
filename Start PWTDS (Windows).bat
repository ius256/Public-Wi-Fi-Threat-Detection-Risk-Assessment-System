@echo off
REM ==== PWTDS launcher for Windows ====
cd /d "%~dp0"
echo Installing requirements (first run only)...
py -m pip install -r requirements.txt --quiet 2>nul || python -m pip install -r requirements.txt --quiet 2>nul
echo Starting PWTDS...
py app.py 2>nul || python app.py
echo.
pause
