@ECHO OFF
SET SCRIPT_PATH=%~dp0%winerva.ps1
PowerShell -NoProfile -ExecutionPolicy Bypass -Command "& { Start-Process PowerShell -ArgumentList '-NoProfile -ExecutionPolicy Bypass -File ""%SCRIPT_PATH%""' -Verb RunAs }"