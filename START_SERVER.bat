@echo off
echo ============================================================
echo        WiFi Security Analyzer - Starting...
echo ============================================================
echo.

cd /d "%~dp0backend"

echo Checking Python installation...
python --version
if errorlevel 1 (
    echo ERROR: Python is not installed or not in PATH
    pause
    exit /b 1
)

echo.
echo Installing/Updating dependencies...
pip install -r requirements.txt --quiet

echo.
echo ============================================================
echo Starting Flask server in background...
echo ============================================================
echo.

REM Start Flask server in a new window
start "WiFi Analyzer Server" cmd /k "python app.py"

REM Wait 3 seconds for server to start
timeout /t 3 /nobreak >nul

echo.
echo ============================================================
echo Opening frontend in your browser...
echo ============================================================
echo.

REM Open frontend in default browser
start "" "%~dp0frontend\index.html"

echo.
echo ============================================================
echo     ALL STARTED SUCCESSFULLY!
echo ============================================================
echo.
echo   Backend Server: http://127.0.0.1:5000
echo   Frontend: Opened in your browser
echo.
echo   To stop server: Close the "WiFi Analyzer Server" window
echo ============================================================
echo.
pause
