@echo off
setlocal

:: Configuration
set INSTALL_DIR=%ProgramFiles%\ArunVenkata-Cryptlocker
set INSTALL_NAME=cryptlocker.exe

:: Check if the binary exists
if exist "%INSTALL_DIR%\%INSTALL_NAME%" (
    :: Remove the binary
    del "%INSTALL_DIR%\%INSTALL_NAME%"
    echo Uninstallation complete: %INSTALL_DIR%\%INSTALL_NAME%
) else (
    echo Error: %INSTALL_DIR%\%INSTALL_NAME% not found.
    exit /b 1
)

:: Optionally, remove the installation directory if it's empty
rmdir "%INSTALL_DIR%" 2>nul

endlocal