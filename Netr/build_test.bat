@echo off
set MSBUILD="C:\Program Files\Microsoft Visual Studio\2022\Community\MSBuild\Current\Bin\MSBuild.exe"
if not exist %MSBUILD% (
    echo MSBuild not found
    exit /b 1
)
%MSBUILD% MyDriver1.sln /p:Configuration=Release /p:Platform=x64 /t:Netr /v:minimal
