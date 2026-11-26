@echo off
rem Builds jink.exe (needs Rust and the Visual Studio C++ build tools) and
rem puts it, with the WinDivert files it needs, into the dist folder. CI does
rem the same (.github/workflows/windows.yml).
setlocal
cd /d "%~dp0.."
powershell -NoProfile -ExecutionPolicy Bypass -File scripts\windivert.ps1 -Out dist -Sdk target\windivert || exit /b 1
set WINDIVERT_PATH=%CD%\target\windivert
cargo build --release -p jink-cli || exit /b 1
copy /y target\release\jink.exe dist\jink.exe >nul || exit /b 1
copy /y LICENSE dist\LICENSE.txt >nul || exit /b 1
echo.
echo Built dist\jink.exe, with WinDivert.dll and WinDivert64.sys next to it
