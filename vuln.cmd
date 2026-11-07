@echo off
powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%~dp0vuln-client.ps1" %*
exit /b %errorlevel%
