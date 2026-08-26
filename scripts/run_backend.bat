@echo off
REM Start the API on http://127.0.0.1:8000  (docs at /docs)
cd /d "%~dp0.."
if not exist .venv python -m venv .venv
call .venv\Scripts\activate.bat
pip install -q -r backend\requirements.txt
uvicorn backend.app.main:app --reload --port 8000
