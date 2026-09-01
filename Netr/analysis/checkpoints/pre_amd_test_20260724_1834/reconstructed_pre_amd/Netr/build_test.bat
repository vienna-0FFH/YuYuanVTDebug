@echo off
setlocal
set "NETR_BUILD_PATH=%PATH%"
set "PATH="
set "Path="
set "Path=%NETR_BUILD_PATH%"
set "NETR_BUILD_PATH="
set "MSBUILD=D:\Program Files\Microsoft Visual Studio\2022\Community\MSBuild\Current\Bin\MSBuild.exe"
if not exist "%MSBUILD%" set "MSBUILD=C:\Program Files\Microsoft Visual Studio\2022\Community\MSBuild\Current\Bin\MSBuild.exe"
set "CONFIG=%~1"
if "%CONFIG%"=="" set "CONFIG=Release"
set "SKIP_EARLY_PACKAGE_COLLECT="
set "LICENSE_BUILD_ARG="
set "LICENSE_MODE=Open"
set "GUI_LICENSE_ARGS="
if /I not "%~2"=="DriverOnly" set "SKIP_EARLY_PACKAGE_COLLECT=/p:SkipGuardMetaCorePackageCollect=true"
if /I "%~3"=="EnforceLicense" (
    set "LICENSE_BUILD_ARG=/p:HvLicenseEnforcement=true"
    set "LICENSE_MODE=Enforced"
    set "GUI_LICENSE_ARGS=-- --features network-license"
)

if not exist "%MSBUILD%" (
    echo MSBuild not found
    exit /b 1
)

"%MSBUILD%" "%~dp0Netr.vcxproj" /t:Rebuild /p:Configuration=%CONFIG% /p:Platform=x64 %SKIP_EARLY_PACKAGE_COLLECT% %LICENSE_BUILD_ARG% /m /v:minimal
if errorlevel 1 exit /b %ERRORLEVEL%

if /I "%~2"=="DriverOnly" exit /b 0

call "%~dp0DebuggerBridge\build.bat" NoCollect
if errorlevel 1 exit /b %ERRORLEVEL%

where npm.cmd >nul 2>&1
if errorlevel 1 (
    echo npm.cmd not found
    exit /b 1
)

pushd "%~dp0tools\netr-gui-rs"
call npm.cmd run tauri:build:raw %GUI_LICENSE_ARGS%
set "GUI_BUILD_ERROR=%ERRORLEVEL%"
popd
if not "%GUI_BUILD_ERROR%"=="0" exit /b %GUI_BUILD_ERROR%

powershell.exe -NoProfile -NonInteractive -ExecutionPolicy Bypass -File "%~dp0CollectTestPackage.ps1" -Configuration "%CONFIG%" -Profile Full -LicenseMode "%LICENSE_MODE%" -RequireAll -RequireSignedDriver
exit /b %ERRORLEVEL%
