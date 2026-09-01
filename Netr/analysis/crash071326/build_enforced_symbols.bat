@echo off
setlocal
set "SAVED_PATH=%PATH%"
set "PATH="
set "Path="
set "Path=%SAVED_PATH%"
set "SAVED_PATH="

set "MSBUILD=C:\Program Files\Microsoft Visual Studio\2022\Community\MSBuild\Current\Bin\MSBuild.exe"
set "OUT=%~dp0enforced\"
set "INT=%~dp0enforced\obj\"

"%MSBUILD%" "%~dp0..\..\Netr.vcxproj" /t:Rebuild /p:Configuration=Release /p:Platform=x64 /p:HvLicenseEnforcement=true /p:SkipGuardMetaCorePackageCollect=true /p:OutDir=%OUT% /p:IntDir=%INT% /m /v:minimal
exit /b %ERRORLEVEL%
