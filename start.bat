@echo off
setlocal enabledelayedexpansion
echo ========================================
echo Starting Private Chat v3.6.0
echo ========================================
echo.

cd /d "%~dp0backend"

echo Environment:
echo   PYTHONIOENCODING=utf-8
echo   STARLETTE_ENV_FILE=
echo.

echo Starting uvicorn...
python -m uvicorn main:app --host 0.0.0.0 --port 8080

echo.
echo Server stopped.
pause
