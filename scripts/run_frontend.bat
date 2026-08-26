@echo off
REM Serve the frontend on http://127.0.0.1:5500
cd /d "%~dp0..\frontend"
python -m http.server 5500
