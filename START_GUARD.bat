@echo off
title NeuronX Guard
cd /d E:\NeuronX-Guard

:: Load env
for /f "usebackq tokens=1,* delims==" %%a in (".env") do set "%%a=%%b" 2>nul

echo NeuronX Guard starting on port %GUARD_PORT%...
echo Webhook: http://0.0.0.0:%GUARD_PORT%/webhook
echo Landing: http://localhost:%GUARD_PORT%/

C:\Python313\python.exe guard_server.py
