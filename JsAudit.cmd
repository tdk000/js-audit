@echo off
rem ============================================================
rem  JsAudit portable launcher - double-click on any Windows 10/11
rem  Extra args are passed to JsAudit.ps1, e.g.:  JsAudit.cmd -NoOpen
rem ============================================================
setlocal
set "PS=%SystemRoot%\System32\WindowsPowerShell\v1.0\powershell.exe"
if exist "%SystemRoot%\SysNative\WindowsPowerShell\v1.0\powershell.exe" set "PS=%SystemRoot%\SysNative\WindowsPowerShell\v1.0\powershell.exe"
set "DIR=%~dp0"
"%PS%" -NoProfile -ExecutionPolicy Bypass -File "%DIR%JsAudit.ps1" %*
echo.
pause
endlocal
