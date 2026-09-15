@echo off
chcp 65001 >nul
cd /d "%~dp0"
echo ================================
echo   密码保险箱 —— 调试模式启动
echo ================================
echo.
python main.py
echo.
echo 程序已退出，按任意键关闭窗口。
pause >nul
