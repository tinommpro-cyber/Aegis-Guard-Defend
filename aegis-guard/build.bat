@echo off
REM One-click build on Windows. Needs Node, Rust (rustup) and Python installed.
call npm install || goto :err
if not exist src-tauri\icons\icon.ico ( python scripts\make_icon.py && call npm run tauri icon icon.png ) || goto :err
call npm run app:build || goto :err
echo.
echo Done. Installer: src-tauri\target\release\bundle\nsis\
echo Portable exe:    src-tauri\target\release\aegis-guard.exe
pause & exit /b 0
:err
echo Build failed. & pause & exit /b 1
