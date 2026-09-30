@echo off
echo Starting IPsec VPN Analyzer...

echo Starting Backend (FastAPI) on port 8000...
cd backend
start cmd /k "python -m uvicorn main:app --reload --port 8000"
cd ..

echo Starting Frontend (Vite)...
cd frontend
start cmd /k "npm run dev"
cd ..

echo Both servers are starting in separate windows!
echo Backend: http://localhost:8000
echo Frontend: http://localhost:5173

echo Waiting for servers to start...
timeout /t 4 /nobreak >nul
start "" "http://localhost:5173"
