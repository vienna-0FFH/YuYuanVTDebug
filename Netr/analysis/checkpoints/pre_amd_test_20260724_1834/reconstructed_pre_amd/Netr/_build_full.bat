@echo off
cd /d E:\project_learning\YuYuanVTDebug\Netr
call build_test.bat Release > E:\project_learning\YuYuanVTDebug\Netr\test-package\_build_full.log 2>&1
echo EXIT=%ERRORLEVEL%>> E:\project_learning\YuYuanVTDebug\Netr\test-package\_build_full.log
