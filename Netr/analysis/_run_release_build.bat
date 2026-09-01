@echo off
cd /d E:\project_learning\YuYuanVTDebug\Netr
echo BUILD_START %DATE% %TIME% > E:\project_learning\YuYuanVTDebug\Netr\analysis\_build_release_rollback.out.log
call build_test.bat Release >> E:\project_learning\YuYuanVTDebug\Netr\analysis\_build_release_rollback.out.log 2>&1
echo EXIT_CODE=%ERRORLEVEL% >> E:\project_learning\YuYuanVTDebug\Netr\analysis\_build_release_rollback.out.log
echo BUILD_END %DATE% %TIME% >> E:\project_learning\YuYuanVTDebug\Netr\analysis\_build_release_rollback.out.log
