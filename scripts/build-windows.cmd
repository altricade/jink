@echo off
rem Builds jink.exe with WinDivert compiled in (needs Rust and the Visual
rem Studio C++ build tools). Optional argument: your zapret-discord-youtube
rem folder, to copy its WinDivert64.sys next to jink.exe.
setlocal
cd /d "%~dp0.."
set WINDIVERT_STATIC=1
cargo build --release -p jink-cli || exit /b 1
if not "%~1"=="" (
    copy /y "%~1\bin\WinDivert64.sys" "target\release\WinDivert64.sys" >nul || exit /b 1
    echo Copied WinDivert64.sys from %~1\bin
)
echo.
echo Built target\release\jink.exe
if not exist "target\release\WinDivert64.sys" (
    echo WinDivert64.sys is missing: copy it from zapret-discord-youtube\bin into target\release
)
