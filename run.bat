@echo off
title SOC Security Operations Center AI Dashboard
cls

echo ====================================================================
echo  🛡️  SOC SECURITY OPERATIONS CENTER & AI THREAT SENTINEL
echo ====================================================================
echo.
echo  Starting Real-Time Log Ingestion, Threat Detection Engine,
echo  and Groq AI Analysis Assistant...
echo.
echo  Opening Web Dashboard at: http://127.0.0.1:5000
echo  Press Ctrl+C in this window anytime to stop the server.
echo.
echo ====================================================================
echo.

:: Automatically open browser after 2 seconds
start "" http://127.0.0.1:5000

:: Run the Python Flask application
python app.py

pause
