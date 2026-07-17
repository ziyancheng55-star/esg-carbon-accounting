@echo off
chcp 65001 >nul
echo.
echo   =============================================
echo     ESG碳核算助手 4.0 — 多用户版
echo   =============================================
echo.
echo   正在启动后端服务...
echo.

cd /d "%~dp0"
..\.venv\Scripts\python server.py

pause
