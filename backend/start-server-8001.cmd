@echo off
cd /d "%~dp0"
echo Starting Morrow on http://127.0.0.1:8001
".venv\Scripts\python.exe" -m uvicorn app:app --host 127.0.0.1 --port 8001 --log-level info 1>uvicorn-8001.out.log 2>uvicorn-8001.err.log
