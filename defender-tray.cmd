@echo off
rem Launch the tray tool silently (no console window)
start "" powershell.exe -NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -File "%~dp0defender-tray.ps1"
