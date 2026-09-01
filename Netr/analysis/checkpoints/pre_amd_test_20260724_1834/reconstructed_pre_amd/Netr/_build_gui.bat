@echo off
cd /d E:\project_learning\YuYuanVTDebug\Netr\tools\netr-gui-rs
call npm.cmd run tauri:build:raw > E:\project_learning\YuYuanVTDebug\Netr\test-package\_build_gui.log 2>&1
echo EXIT=%ERRORLEVEL%>> E:\project_learning\YuYuanVTDebug\Netr\test-package\_build_gui.log
