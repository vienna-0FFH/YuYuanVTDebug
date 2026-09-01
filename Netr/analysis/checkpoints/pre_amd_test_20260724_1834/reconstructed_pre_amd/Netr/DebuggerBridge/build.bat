@echo off
setlocal
cd /d "%~dp0"

set "VSROOT=D:\Program Files\Microsoft Visual Studio\2022\Community"
if not exist "%VSROOT%\VC\Auxiliary\Build\vcvars64.bat" set "VSROOT=C:\Program Files\Microsoft Visual Studio\2022\Community"
if not exist "%VSROOT%\VC\Auxiliary\Build\vcvars64.bat" (
    echo Visual Studio 2022 Community with C++ tools was not found.
    exit /b 1
)

if not exist bin mkdir bin

call :build_arch x64 64 vcvars64.bat
if errorlevel 1 exit /b %errorlevel%
call :build_arch x86 32 vcvars32.bat
if errorlevel 1 exit /b %errorlevel%

if exist "%~dp0..\tools\netr-gui-rs\src-tauri\target\release" (
    call :copy_artifacts "%~dp0..\tools\netr-gui-rs\src-tauri\target\release"
    if errorlevel 1 exit /b 1
)
if /I "%~1"=="NoCollect" exit /b 0

powershell.exe -NoProfile -NonInteractive -ExecutionPolicy Bypass -File "%~dp0..\CollectTestPackage.ps1" -Configuration Release -Profile Bridge -RequireAll
exit /b %ERRORLEVEL%

:build_arch
setlocal
call "%VSROOT%\VC\Auxiliary\Build\%~3" >nul
if errorlevel 1 exit /b %errorlevel%

cl /nologo /LD /EHa /O2 /Z7 /MT /std:c++17 /utf-8 /W4 /DUNICODE /D_UNICODE /D_WIN32_WINNT=0x0601 /Fo"bin\Bridge%~2.obj" Bridge.cpp advapi32.lib dbghelp.lib psapi.lib /link /DEBUG:FULL /OPT:REF /OPT:ICF /OUT:"bin\NetrDebuggerBridge%~2.dll" /IMPLIB:"bin\NetrDebuggerBridge%~2.lib" /PDB:"bin\NetrDebuggerBridge%~2.pdb" /MACHINE:%~1
if errorlevel 1 exit /b %errorlevel%

cl /nologo /EHa /O2 /Z7 /MT /std:c++17 /utf-8 /W4 /DUNICODE /D_UNICODE /D_WIN32_WINNT=0x0601 /Fo"bin\Injector%~2.obj" Injector.cpp /link /DEBUG:FULL /OPT:REF /OPT:ICF /OUT:"bin\NetrBridgeInjector%~2.exe" /PDB:"bin\NetrBridgeInjector%~2.pdb" /MACHINE:%~1
exit /b %errorlevel%

:copy_artifacts
if not exist "%~1" mkdir "%~1"
copy /y "bin\NetrDebuggerBridge32.dll" "%~1\" >nul
if errorlevel 1 exit /b %errorlevel%
copy /y "bin\NetrDebuggerBridge64.dll" "%~1\" >nul
if errorlevel 1 exit /b %errorlevel%
copy /y "bin\NetrBridgeInjector32.exe" "%~1\" >nul
if errorlevel 1 exit /b %errorlevel%
copy /y "bin\NetrBridgeInjector64.exe" "%~1\" >nul
if errorlevel 1 exit /b %errorlevel%
copy /y "bin\NetrDebuggerBridge32.pdb" "%~1\" >nul
if errorlevel 1 exit /b %errorlevel%
copy /y "bin\NetrDebuggerBridge64.pdb" "%~1\" >nul
if errorlevel 1 exit /b %errorlevel%
copy /y "bin\NetrBridgeInjector32.pdb" "%~1\" >nul
if errorlevel 1 exit /b %errorlevel%
copy /y "bin\NetrBridgeInjector64.pdb" "%~1\" >nul
if errorlevel 1 exit /b %errorlevel%
echo Bridge artifacts copied to %~1
exit /b 0
