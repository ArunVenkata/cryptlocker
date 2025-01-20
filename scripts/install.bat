@echo off
setlocal enabledelayedexpansion

:: Configuration
set REPO_OWNER=ArunVenkata
set REPO_NAME=cryptlocker
set BINARY_NAME=cryptlocker.exe
set INSTALL_DIR=%ProgramFiles%\ArunVenkata-Cryptlocker
set INSTALL_NAME=cryptlocker.exe
set PUBLIC_KEY_URL=https://github.com/%REPO_OWNER%/%REPO_NAME%/raw/master/pubkey.gpg

:: Fetch the latest release version
for /f "tokens=*" %%i in ('powershell -Command "(Invoke-WebRequest -Uri https://api.github.com/repos/%REPO_OWNER%/%REPO_NAME%/releases/latest).Content | ConvertFrom-Json | Select-Object -ExpandProperty tag_name"') do set VERSION=%%i

:: Construct download URLs
set DOWNLOAD_URL=https://github.com/%REPO_OWNER%/%REPO_NAME%/releases/download/%VERSION%/%BINARY_NAME%
set SIGNATURE_URL=%DOWNLOAD_URL%.sig

:: Create temporary directory
set TMP_DIR=%TEMP%\cryptlocker
if exist "%TMP_DIR%" (
    rmdir /s /q "%TMP_DIR%"
)
mkdir "%TMP_DIR%"
set TMP_FILE=%TMP_DIR%\%BINARY_NAME%
set TMP_SIGNATURE=%TMP_DIR%\%BINARY_NAME%.sig
set TMP_PUBLIC_KEY=%TMP_DIR%\pubkey.gpg

:: Download files
echo Downloading binary, signature, and public key...
powershell -Command "Invoke-WebRequest -Uri %DOWNLOAD_URL% -OutFile %TMP_FILE%"
powershell -Command "Invoke-WebRequest -Uri %SIGNATURE_URL% -OutFile %TMP_SIGNATURE%"
powershell -Command "Invoke-WebRequest -Uri %PUBLIC_KEY_URL% -OutFile %TMP_PUBLIC_KEY%"

:: Check if gpg is installed
where gpg >nul 2>&1
if %errorlevel% neq 0 (
    echo GPG not found, skipping signature verification.
) else (
    :: Import the public GPG key
    gpg --import "%TMP_PUBLIC_KEY%" >nul 2>&1

    :: Verify the GPG signature
    gpg --verify "%TMP_SIGNATURE%" "%TMP_FILE%" >nul 2>&1
    if %errorlevel% neq 0 (
        echo GPG signature verification failed!
        exit /b 1
    ) else (
        echo GPG Signature Successfully Verified.
    )
)

:: Create installation directory if it doesn't exist
if not exist "%INSTALL_DIR%" (
    mkdir "%INSTALL_DIR%"
)

:: Move the binary to the installation directory and rename it to "cryptlocker"
move /y "%TMP_FILE%" "%INSTALL_DIR%\%INSTALL_NAME%"
icacls "%INSTALL_DIR%\%INSTALL_NAME%" /grant Everyone:RX

:: Clean up
rmdir /s /q "%TMP_DIR%"

echo Installation complete: %INSTALL_DIR%\%INSTALL_NAME%
endlocal