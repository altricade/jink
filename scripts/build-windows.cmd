@echo off
rem Builds jink.exe with WinDivert compiled in (needs Rust and the Visual
rem Studio C++ build tools) and puts it, with the WinDivert driver it needs,
rem into the dist folder. CI does the same (.github/workflows/windows.yml).
setlocal
cd /d "%~dp0.."
set WINDIVERT_STATIC=1
cargo build --release -p jink-cli || exit /b 1
powershell -NoProfile -ExecutionPolicy Bypass -File scripts\windivert.ps1 -Out dist || exit /b 1
copy /y target\release\jink.exe dist\jink.exe >nul || exit /b 1
copy /y LICENSE dist\LICENSE.txt >nul || exit /b 1
echo.
echo Built dist\jink.exe, with WinDivert64.sys next to it
