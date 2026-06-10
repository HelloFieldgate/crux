@echo off
setlocal enabledelayedexpansion
title Crux Mesh Installer

echo Crux Mesh Installer
echo ===================
echo.

:: -- Locate repo root (two levels up from install\Windows\) ----------------
set "REPO_DIR=%~dp0..\.."
pushd "%REPO_DIR%"
set "REPO_DIR=%CD%"
popd

set "INSTALL_DIR=%USERPROFILE%\.crux\bin"

echo Repo:       %REPO_DIR%
echo Install to: %INSTALL_DIR%
echo.

:: -- Check for cargo / Rust ------------------------------------------------
where cargo >nul 2>&1
if %ERRORLEVEL% NEQ 0 (
    echo It looks like you're missing Rust.
    echo.
    set /p "INSTALL_RUST=Would you like to install the latest version from https://rustup.rs/ ? [Y/n] "
    if /i "!INSTALL_RUST!"=="" set "INSTALL_RUST=Y"
    if /i "!INSTALL_RUST!"=="Y" (
        echo.
        echo Downloading rustup-init.exe ...
        powershell -NoProfile -Command "Invoke-WebRequest -Uri 'https://static.rust-lang.org/rustup/dist/x86_64-pc-windows-msvc/rustup-init.exe' -OutFile '%TEMP%\rustup-init.exe'"
        echo Installing Rust ...
        "%TEMP%\rustup-init.exe" -y --default-toolchain stable
        del "%TEMP%\rustup-init.exe"
        :: Add cargo to PATH for this session
        set "PATH=%USERPROFILE%\.cargo\bin;%PATH%"
        where cargo >nul 2>&1
        if %ERRORLEVEL% NEQ 0 (
            echo.
            echo Rust was installed but cargo is not on PATH in this session.
            echo Please close this window, open a new Command Prompt, and re-run Install-Crux.bat.
            pause
            exit /b 1
        )
        echo.
        echo Rust installed.
    ) else (
        echo.
        echo OK. Install Rust later from https://rustup.rs/ and re-run this script.
        pause
        exit /b 0
    )
)

for /f "tokens=*" %%v in ('rustc --version 2^>^&1') do echo Rust: %%v
echo.

:: -- Check for MSVC linker (link.exe) ---------------------------------------
:: link.exe is never on the system PATH — it must be activated via vcvars64.bat.
:: Try to find and call it before falling back to installing Build Tools.
call :activate_vcvars

where link.exe >nul 2>&1
if %ERRORLEVEL% NEQ 0 (
    echo It looks like the Visual C++ Build Tools are not installed.
    echo Rust on Windows requires the MSVC linker ^(link.exe^).
    echo.
    set /p "INSTALL_VCT=Would you like to install the Visual C++ Build Tools now? [Y/n] "
    if /i "!INSTALL_VCT!"=="" set "INSTALL_VCT=Y"
    if /i "!INSTALL_VCT!"=="Y" (
        echo.
        echo Downloading Visual Studio Build Tools installer ...
        echo ^(This is a ~5 MB bootstrapper; the full install is ~2 GB and takes several minutes.^)
        echo.
        powershell -NoProfile -Command "Invoke-WebRequest -Uri 'https://aka.ms/vs/17/release/vs_BuildTools.exe' -OutFile '%TEMP%\vs_BuildTools.exe'"
        echo Installing Visual C++ Build Tools ^(please wait, this takes a few minutes^) ...
        echo Administrator rights are required for this step - a UAC prompt will appear.
        echo.
        set "VCT_ARGS=--quiet --wait --norestart --nocache --add Microsoft.VisualStudio.Workload.VCTools --add Microsoft.VisualStudio.Component.VC.Tools.x86.x64 --add Microsoft.VisualStudio.Component.Windows11SDK.22000"
        if /i "%PROCESSOR_ARCHITECTURE%"=="ARM64" set "VCT_ARGS=!VCT_ARGS! --add Microsoft.VisualStudio.Component.VC.Tools.ARM64"
        powershell -NoProfile -Command "Start-Process '%TEMP%\vs_BuildTools.exe' -ArgumentList '!VCT_ARGS!' -Verb RunAs -Wait"
        del "%TEMP%\vs_BuildTools.exe"
        echo.
        call :activate_vcvars
        where link.exe >nul 2>&1
        if %ERRORLEVEL% NEQ 0 (
            echo Build Tools installed but link.exe could not be activated in this session.
            echo Please close this window, open a new Command Prompt, and re-run Install-Crux.bat.
            pause
            exit /b 1
        )
        echo Visual C++ Build Tools installed and activated.
    ) else (
        echo.
        echo OK. Install the Visual C++ Build Tools from:
        echo   https://visualstudio.microsoft.com/visual-cpp-build-tools/
        echo Then re-run this script.
        pause
        exit /b 0
    )
)

:: -- Check for curl ----------------------------------------------------------
:: curl is required by crux-router for HTTPS forwarding (OAuth token endpoints).
where curl >nul 2>&1
if %ERRORLEVEL% NEQ 0 (
    echo It looks like curl is missing.
    echo crux-router requires curl for HTTPS traffic.
    echo.
    set /p "INSTALL_CURL=Would you like to install it via winget now? [Y/n] "
    if /i "!INSTALL_CURL!"=="" set "INSTALL_CURL=Y"
    if /i "!INSTALL_CURL!"=="Y" (
        echo.
        where winget >nul 2>&1
        if %ERRORLEVEL% EQU 0 (
            winget install --id cURL.cURL --accept-source-agreements --accept-package-agreements --silent
            set "PATH=%USERPROFILE%\.local\bin;%ProgramFiles%\cURL\bin;%PATH%"
            where curl >nul 2>&1
            if %ERRORLEVEL% EQU 0 (
                echo.
                echo curl installed.
            ) else (
                echo winget install completed. You may need to open a new terminal for curl to be on PATH.
            )
        ) else (
            echo winget not available. Please download curl from https://curl.se/windows/
            echo and add it to your PATH, then re-run this installer.
        )
    ) else (
        echo.
        echo OK. Install curl later from https://curl.se/windows/ and re-run.
        echo crux-router will fall back to plain HTTP only until curl is available.
    )
    echo.
) else (
    for /f "tokens=1,2" %%a in ('curl --version 2^>^&1 ^| findstr /i "curl"') do (
        echo curl: %%a %%b
        goto :curl_ver_done
    )
    :curl_ver_done
    echo.
)

:: -- Check for ARM64 Windows SDK libs (ARM64 systems only) -----------------
:: Uses a temp file to avoid (x86) parentheses inside for /f ('command').
if /i "%PROCESSOR_ARCHITECTURE%" NEQ "ARM64" goto :arm64_sdk_ok
del "%TEMP%\_crux_sdk.txt" >nul 2>&1
powershell -NoProfile -Command "Get-ChildItem \"!PF64!\Windows Kits\10\Lib\",\"!PF86!\Windows Kits\10\Lib\" -Filter kernel32.lib -Recurse -EA 0 | Where-Object {$_.DirectoryName -match \"arm64\"} | Select-Object -First 1 -ExpandProperty FullName | Out-File \"$env:TEMP\_crux_sdk.txt\" -Encoding ASCII -NoNewline"
set "ARM64_K32="
for /f "usebackq tokens=*" %%p in ("%TEMP%\_crux_sdk.txt") do set "ARM64_K32=%%p"
del "%TEMP%\_crux_sdk.txt" >nul 2>&1
if defined ARM64_K32 goto :arm64_sdk_ok
echo The Windows SDK ARM64 libraries are not installed.
echo This is required to link Rust binaries on ARM64 Windows.
echo.
echo Installing Windows SDK for ARM64...
echo.
winget install --id Microsoft.WindowsSDK.10.0.22000 --accept-source-agreements --accept-package-agreements --silent
if %ERRORLEVEL% NEQ 0 (
    echo.
    echo winget install failed. Please install the Windows SDK manually from:
    echo https://developer.microsoft.com/en-us/windows/downloads/windows-sdk/
    echo Then re-run this installer.
    pause
    exit /b 1
)
echo.
echo Windows SDK installed.
call :activate_vcvars
echo.
:arm64_sdk_ok

:: -- Build ------------------------------------------------------------------
:: Build artifacts must land on local disk — network shares (e.g. \\Mac\Home)
:: cause "os error 87" when cargo tries to rename temp files across the share.
set "CARGO_TARGET_DIR=%USERPROFILE%\.crux\build"
echo Build output: %CARGO_TARGET_DIR%
echo Building Crux (this takes a minute or two on first build)...
echo.
cd /d "%REPO_DIR%"
cargo build --release
if %ERRORLEVEL% NEQ 0 (
    echo.
    echo Build failed.
    pause
    exit /b 1
)
echo.

:: -- Install ----------------------------------------------------------------
echo Installing binaries to %INSTALL_DIR% ...
if not exist "%INSTALL_DIR%" mkdir "%INSTALL_DIR%"
copy /y "%CARGO_TARGET_DIR%\release\crux.exe"        "%INSTALL_DIR%\crux.exe"        >nul
copy /y "%CARGO_TARGET_DIR%\release\crux-router.exe" "%INSTALL_DIR%\crux-router.exe" >nul
copy /y "%CARGO_TARGET_DIR%\release\helm.exe"        "%INSTALL_DIR%\helm.exe"        >nul

:: -- Verify -----------------------------------------------------------------
"%INSTALL_DIR%\crux.exe" --version 2>nul || echo warning: could not verify crux --version

echo.
echo Installation complete.
echo.

:: -- PATH hint --------------------------------------------------------------
echo %PATH% | findstr /i /c:"%INSTALL_DIR%" >nul 2>&1
if %ERRORLEVEL% NEQ 0 (
    echo To use crux from any terminal, add this folder to your PATH:
    echo.
    echo   %INSTALL_DIR%
    echo.
    echo You can do this by running in PowerShell:
    echo   setx PATH "%%PATH%%;%INSTALL_DIR%"
    echo.
)

pause
goto :eof

:: -- Subroutine: activate MSVC environment (arch-aware) ---------------------
:: Uses goto instead of multi-line if blocks to avoid (x86) parser issues.
:activate_vcvars
set "PF86=%ProgramFiles(x86)%"
set "PF64=%ProgramFiles%"
set "VSWHERE=!PF86!\Microsoft Visual Studio\Installer\vswhere.exe"
if not exist "!VSWHERE!" exit /b 0
for /f "usebackq tokens=*" %%i in (`"!VSWHERE!" -latest -products * -property installationPath`) do set "VS_INST=%%i"
if not defined VS_INST exit /b 0
set "VCVARS=!VS_INST!\VC\Auxiliary\Build\vcvars64.bat"
if /i "%PROCESSOR_ARCHITECTURE%"=="ARM64" set "VCVARS=!VS_INST!\VC\Auxiliary\Build\vcvarsarm64.bat"
if exist "!VCVARS!" call "!VCVARS!" >nul 2>&1
if /i "%PROCESSOR_ARCHITECTURE%" NEQ "ARM64" exit /b 0
for /f "tokens=*" %%v in ('dir /b /ad "!PF64!\Windows Kits\10\Lib" 2^>nul') do call :add_sdk_lib "!PF64!\Windows Kits\10\Lib\%%v"
for /f "tokens=*" %%v in ('dir /b /ad "!PF86!\Windows Kits\10\Lib" 2^>nul') do call :add_sdk_lib "!PF86!\Windows Kits\10\Lib\%%v"
exit /b 0

:add_sdk_lib
if exist "%~1\um\arm64\kernel32.lib" set "LIB=!LIB!;%~1\um\arm64;%~1\ucrt\arm64"
exit /b 0
