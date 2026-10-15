@echo off
title IPsec VPN Analyzer
echo ================================================
echo   IPsec VPN Analyzer - Starting...
echo ================================================
echo.

echo [1/2] Starting Backend (FastAPI) on port 8000...
cd backend
start cmd /k "title Backend-FastAPI && python -m uvicorn main:app --reload --port 8000"
cd ..

echo [2/2] Starting Frontend (Vite) on port 5173...
cd frontend
start cmd /k "title Frontend-Vite && npm run dev"
cd ..

echo.
echo ================================================
echo   Servers are starting in separate windows.
echo   Please wait 15 seconds for them to be ready!
echo ================================================
echo.

echo Waiting 5 seconds...
timeout /t 5 /nobreak >nul
echo Waiting 10 seconds...
timeout /t 5 /nobreak >nul
echo Waiting 15 seconds... Almost ready!
timeout /t 5 /nobreak >nul

echo.
echo Opening browser at http://localhost:5173 ...
start "" "http://localhost:5173"
echo Done! If browser shows error, wait 5 more seconds and refresh.
