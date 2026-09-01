<#
.SYNOPSIS
    用 PyInstaller 把 Netr GUI 打包成 EXE。

.DESCRIPTION
    默认产物：dist\Netr-GUI.exe — 单文件、无控制台、嵌入 UAC manifest，
    双击即触发管理员提权（与驱动加载的权限需求一致）。

.PARAMETER NoClean
    保留上次的 build\ / dist\ / *.spec，做增量构建（更快）。

.PARAMETER OneDir
    产出 dist\Netr-GUI\ 目录形式（启动更快、便于调试），而非单 EXE。

.PARAMETER Console
    保留控制台窗口（默认隐藏）。诊断打包问题时打开很有用。

.PARAMETER NoUac
    不嵌入 UAC manifest。仅用于绕开 UAC 做调试，正常分发请勿使用。

.EXAMPLE
    .\build.ps1
    # 标准发布：dist\Netr-GUI.exe，单文件，启动即弹 UAC

.EXAMPLE
    .\build.ps1 -OneDir -Console
    # 调试：dist\Netr-GUI\Netr-GUI.exe，启动快，有控制台输出
#>
[CmdletBinding()]
param(
    [switch]$NoClean,
    [switch]$OneDir,
    [switch]$Console,
    [switch]$NoUac
)

$ErrorActionPreference = 'Stop'
Set-Location -Path $PSScriptRoot

function Step($msg) { Write-Host "==> $msg" -ForegroundColor Cyan }

# ----------------------------------------------------------------- 1) Python
$venvPython = Join-Path $PSScriptRoot '.venv\Scripts\python.exe'
if (-not (Test-Path $venvPython)) {
    Step "创建本地 Python 虚拟环境 (.venv)"
    $basePython = $null
    $pyLauncher = Get-Command py -ErrorAction SilentlyContinue
    if ($pyLauncher) {
        & py -3.10 -c "import sys;print(sys.executable)" *> $null
        if ($LASTEXITCODE -eq 0) { $basePython = @('py', '-3.10') }
    }
    if (-not $basePython) {
        $py = Get-Command python -ErrorAction SilentlyContinue
        if (-not $py) {
            throw "未在 PATH 中找到 python，也无法通过 py -3.10 创建虚拟环境。请先安装 Python 3.10+。"
        }
        $basePython = @($py.Source)
    }
    if ($basePython.Length -gt 1) {
        & $basePython[0] $basePython[1] -m venv .venv
    } else {
        & $basePython[0] -m venv .venv
    }
    if ($LASTEXITCODE -ne 0) { throw "创建 .venv 失败" }
}
$pythonExe = (Resolve-Path $venvPython).Path
$pyVer = & $pythonExe -c "import sys;print(f'{sys.version_info.major}.{sys.version_info.minor}.{sys.version_info.micro}')"
Step "Python: $pythonExe  ($pyVer)"

# ----------------------------------------------------------------- 2) deps
Step "安装/校验 PySide6 Essentials (requirements.txt)"
& $pythonExe -m pip install --disable-pip-version-check -r requirements.txt
if ($LASTEXITCODE -ne 0) { throw "pip install requirements.txt 失败" }

Step "安装/校验 PyInstaller"
& $pythonExe -m pip install --disable-pip-version-check "pyinstaller>=6.0"
if ($LASTEXITCODE -ne 0) { throw "pip install pyinstaller 失败" }

Step "校验 PySide6 Qt 模块可导入"
& $pythonExe -c "from PySide6.QtCore import Qt; from PySide6.QtWidgets import QApplication; print('PySide6 Qt import OK')"
if ($LASTEXITCODE -ne 0) { throw "PySide6 Qt 模块导入失败" }

# ----------------------------------------------------------------- 3) clean
if (-not $NoClean) {
    Step "清理 build\ dist\ *.spec __pycache__\"
    foreach ($d in 'build', 'dist', '__pycache__') {
        if (Test-Path $d) { Remove-Item -Recurse -Force $d }
    }
    Get-ChildItem -Filter '*.spec' -ErrorAction SilentlyContinue |
        Remove-Item -Force
}

# ----------------------------------------------------------------- 4) args
$piArgs = @(
    '--noconfirm'
    '--clean'
    '--name', 'Netr-GUI'
    '--paths', '.'
)

if ($OneDir)     { $piArgs += '--onedir' }  else { $piArgs += '--onefile' }
if ($Console)    { $piArgs += '--console' } else { $piArgs += '--windowed' }
if (-not $NoUac) { $piArgs += '--uac-admin' }

# 显式补几个 PySide6 子模块（hook 一般会自动捕获，这里加一道保险）
foreach ($h in 'PySide6.QtCore','PySide6.QtGui','PySide6.QtWidgets') {
    $piArgs += '--hidden-import', $h
}

# 我们没用的重量级 Qt 模块全部排掉，能省 100+ MB
$excludes = @(
    'PySide6.Qt3DCore', 'PySide6.Qt3DRender', 'PySide6.Qt3DInput',
    'PySide6.Qt3DLogic', 'PySide6.Qt3DAnimation', 'PySide6.Qt3DExtras',
    'PySide6.QtCharts', 'PySide6.QtDataVisualization',
    'PySide6.QtMultimedia', 'PySide6.QtMultimediaWidgets',
    'PySide6.QtPdf', 'PySide6.QtPdfWidgets',
    'PySide6.QtQml', 'PySide6.QtQuick', 'PySide6.QtQuickWidgets',
    'PySide6.QtWebChannel',
    'PySide6.QtWebEngineCore', 'PySide6.QtWebEngineQuick', 'PySide6.QtWebEngineWidgets',
    'PySide6.QtWebSockets',
    'PySide6.QtPositioning', 'PySide6.QtLocation',
    'PySide6.QtScxml', 'PySide6.QtSensors', 'PySide6.QtSerialPort',
    'PySide6.QtSpatialAudio', 'PySide6.QtSql', 'PySide6.QtTest',
    'PySide6.QtTextToSpeech',
    'PySide6.QtRemoteObjects',
    'tkinter'
)
foreach ($e in $excludes) { $piArgs += '--exclude-module', $e }

$piArgs += 'main.py'

# ----------------------------------------------------------------- 5) run
Step "运行 PyInstaller"
Write-Host "  $pythonExe -m PyInstaller $($piArgs -join ' ')" -ForegroundColor DarkGray
& $pythonExe -m PyInstaller @piArgs
if ($LASTEXITCODE -ne 0) { throw "PyInstaller 失败 (exit $LASTEXITCODE)" }

# ----------------------------------------------------------------- 6) report
$exePath = if ($OneDir) { 'dist\Netr-GUI\Netr-GUI.exe' } else { 'dist\Netr-GUI.exe' }
if (-not (Test-Path $exePath)) {
    throw "构建结束但找不到产物：$exePath"
}

$full = (Resolve-Path $exePath).Path
$size = '{0:N1} MB' -f ((Get-Item $full).Length / 1MB)

Write-Host ""
Write-Host "构建完成" -ForegroundColor Green
Write-Host "  产物：$full"
Write-Host "  大小：$size"
if (-not $NoUac) {
    Write-Host "  备注：已嵌入 UAC manifest — 双击启动会弹管理员授权" -ForegroundColor Yellow
}
