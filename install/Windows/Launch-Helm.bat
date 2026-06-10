@echo off
title Launch Helm

echo Launching Helm...
echo Browser will open at http://127.0.0.1:8111
echo (Close this window to stop the server)
echo.

:: Check standard install location first
if exist "%USERPROFILE%\.crux\bin\helm.exe" (
    "%USERPROFILE%\.crux\bin\helm.exe"
    goto :done
)

:: Fall back to PATH
where helm >nul 2>&1
if %ERRORLEVEL% EQU 0 (
    helm
    goto :done
)

echo Helm is not installed.
echo Run Install-Crux.bat first.
echo.
pause
exit /b 1

:done
