[CmdletBinding()]
param(
    [string]$Configuration = "Release",
    [ValidateSet("Full", "Driver", "Bridge", "Gui")]
    [string]$Profile = "Full",
    [ValidateSet("Open", "Enforced")]
    [string]$LicenseMode = "Open",
    [switch]$RequireAll,
    [switch]$RequireSignedDriver
)

$ErrorActionPreference = "Stop"

$projectRoot = $PSScriptRoot
$destination = Join-Path $projectRoot "test-package"
$logDestination = Join-Path $destination "logs"
$driverStem = if ($Configuration -eq "VmxProbe") {
    "GuardMetaCoreVmxProbe"
} else {
    "GuardMetaCore"
}

$driverArtifacts = @(
    [pscustomobject]@{
        Source = Join-Path $projectRoot "x64\$Configuration\$driverStem.sys"
        Name = "$driverStem.sys"
    }
    [pscustomobject]@{
        Source = Join-Path $projectRoot "x64\$Configuration\$driverStem.pdb"
        Name = "$driverStem.pdb"
    }
    [pscustomobject]@{
        Source = Join-Path $projectRoot "cert\GuardMetaCore-Test.cer"
        Name = "GuardMetaCore-Test.cer"
    }
)

$guiArtifacts = @(
    [pscustomobject]@{
        Source = Join-Path $projectRoot "tools\netr-gui-rs\src-tauri\target\release\guardmeta-vsp.exe"
        Name = "guardmeta-vsp.exe"
    }
    [pscustomobject]@{
        Source = Join-Path $projectRoot "tools\netr-gui-rs\src-tauri\target\release\guardmeta_vsp.pdb"
        Name = "guardmeta_vsp.pdb"
    }
)

$bridgeArtifacts = @(
    [pscustomobject]@{
        Source = Join-Path $projectRoot "DebuggerBridge\bin\NetrDebuggerBridge32.dll"
        Name = "NetrDebuggerBridge32.dll"
    }
    [pscustomobject]@{
        Source = Join-Path $projectRoot "DebuggerBridge\bin\NetrDebuggerBridge64.dll"
        Name = "NetrDebuggerBridge64.dll"
    }
    [pscustomobject]@{
        Source = Join-Path $projectRoot "DebuggerBridge\bin\NetrBridgeInjector32.exe"
        Name = "NetrBridgeInjector32.exe"
    }
    [pscustomobject]@{
        Source = Join-Path $projectRoot "DebuggerBridge\bin\NetrBridgeInjector64.exe"
        Name = "NetrBridgeInjector64.exe"
    }
    [pscustomobject]@{
        Source = Join-Path $projectRoot "DebuggerBridge\bin\NetrDebuggerBridge32.pdb"
        Name = "NetrDebuggerBridge32.pdb"
    }
    [pscustomobject]@{
        Source = Join-Path $projectRoot "DebuggerBridge\bin\NetrDebuggerBridge64.pdb"
        Name = "NetrDebuggerBridge64.pdb"
    }
    [pscustomobject]@{
        Source = Join-Path $projectRoot "DebuggerBridge\bin\NetrBridgeInjector32.pdb"
        Name = "NetrBridgeInjector32.pdb"
    }
    [pscustomobject]@{
        Source = Join-Path $projectRoot "DebuggerBridge\bin\NetrBridgeInjector64.pdb"
        Name = "NetrBridgeInjector64.pdb"
    }
)

$allArtifacts = @($driverArtifacts) + @($guiArtifacts) + @($bridgeArtifacts)
switch ($Profile) {
    "Driver" { $artifacts = @($driverArtifacts); break }
    "Bridge" { $artifacts = @($bridgeArtifacts); break }
    "Gui" { $artifacts = @($guiArtifacts); break }
    default { $artifacts = @($allArtifacts) }
}

if ($RequireSignedDriver -and $Profile -notin @("Full", "Driver")) {
    throw "RequireSignedDriver is only valid for the Full and Driver profiles."
}

function Assert-ValidDriverSignature {
    param([Parameter(Mandatory = $true)][string]$DriverPath)

    $signature = Get-AuthenticodeSignature -LiteralPath $DriverPath
    if ($signature.Status.ToString() -ne "Valid") {
        throw "Driver signature verification failed for '$DriverPath': $($signature.Status) $($signature.StatusMessage)"
    }
}

if ($RequireAll) {
    $missingArtifacts = @(
        $artifacts | Where-Object {
            -not (Test-Path -LiteralPath $_.Source -PathType Leaf)
        }
    )
    if ($missingArtifacts.Count -gt 0) {
        $missingList = ($missingArtifacts.Source -join "`n  ")
        throw "Missing required test artifacts:`n  $missingList"
    }
}

$driverSource = Join-Path $projectRoot "x64\$Configuration\$driverStem.sys"
if ($RequireSignedDriver) {
    Assert-ValidDriverSignature -DriverPath $driverSource
}

New-Item -ItemType Directory -Path $destination -Force | Out-Null
New-Item -ItemType Directory -Path $logDestination -Force | Out-Null

$logCutoff = (Get-Date).AddDays(-7)
$bridgeLogs = @(
    Get-ChildItem -LiteralPath $logDestination `
        -Filter "GuardMetaBridge-*.log" -File -ErrorAction SilentlyContinue |
        Sort-Object -Property LastWriteTime -Descending
)
$staleLogs = @(
    $bridgeLogs | Where-Object {
        $_.Length -eq 0 -or $_.LastWriteTime -lt $logCutoff
    }
    $bridgeLogs | Select-Object -Skip 10
) | Sort-Object -Property FullName -Unique

foreach ($log in $staleLogs) {
    Remove-Item -LiteralPath $log.FullName -Force -ErrorAction SilentlyContinue
}

foreach ($artifact in $artifacts) {
    if (-not (Test-Path -LiteralPath $artifact.Source -PathType Leaf)) {
        $message = "Missing test artifact: $($artifact.Source)"
        if ($RequireAll) {
            throw $message
        }
        Write-Warning $message
        continue
    }

    $destinationPath = Join-Path $destination $artifact.Name
    $sourceHash = (Get-FileHash -LiteralPath $artifact.Source -Algorithm SHA256).Hash
    if (Test-Path -LiteralPath $destinationPath -PathType Leaf) {
        $destinationHash = (Get-FileHash -LiteralPath $destinationPath -Algorithm SHA256).Hash
    } else {
        $destinationHash = $null
    }
    if ($sourceHash -ne $destinationHash) {
        Copy-Item -LiteralPath $artifact.Source -Destination $destinationPath -Force
        $destinationHash = (Get-FileHash -LiteralPath $destinationPath -Algorithm SHA256).Hash
    }
    if ($sourceHash -ne $destinationHash) {
        throw "Artifact hash mismatch after copy: $($artifact.Source) -> $destinationPath"
    }
}

if ($RequireSignedDriver) {
    $driverDestination = Join-Path $destination "$driverStem.sys"
    Assert-ValidDriverSignature -DriverPath $driverDestination
}

$licenseModePath = Join-Path $destination "LICENSE_MODE.txt"
$licenseModeLines = @(
    "GuardMetaCore test package license mode",
    "Generated=$((Get-Date).ToString('yyyy-MM-dd HH:mm:ss zzz'))",
    "Mode=$LicenseMode"
)
if ($LicenseMode -eq "Open") {
    $licenseModeLines += "NOTICE=Authorization enforcement is disabled for the current project/test workflow."
}
Set-Content -LiteralPath $licenseModePath -Value $licenseModeLines -Encoding ASCII

$manifestNames = @($artifacts.Name) + @("LICENSE_MODE.txt")
$manifestLines = @(
    "# GuardMeta test package SHA-256",
    "# Generated: $((Get-Date).ToString('yyyy-MM-dd HH:mm:ss zzz'))",
    "# Update profile: $Profile ($Configuration)",
    "# License mode: $LicenseMode",
    "# Only artifacts refreshed and source-parity checked by this profile are managed below."
)

foreach ($name in ($manifestNames | Sort-Object -Unique)) {
    $path = Join-Path $destination $name
    if (Test-Path -LiteralPath $path -PathType Leaf) {
        $hash = (Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash
        $manifestLines += "$hash  $name"
    }
}

$manifestPath = Join-Path $destination "SHA256SUMS.txt"
Set-Content -LiteralPath $manifestPath -Value $manifestLines -Encoding ASCII

$unmanagedReportPath = Join-Path $destination "UNMANAGED_ARTIFACTS.txt"
$managedRootNames = @($manifestNames) + @(
    "SHA256SUMS.txt",
    "UNMANAGED_ARTIFACTS.txt"
)
$unmanagedFiles = @(
    Get-ChildItem -LiteralPath $destination -File |
        Where-Object { $_.Name -notin $managedRootNames } |
        Sort-Object Name
)
$unmanagedLines = @(
    "# Files present in test-package but not refreshed by the current $Profile profile",
    "# Generated: $((Get-Date).ToString('yyyy-MM-dd HH:mm:ss zzz'))",
    "# These files are not covered by SHA256SUMS.txt and must be treated as stale/unmanaged for this handoff."
)
if ($unmanagedFiles.Count -eq 0) {
    $unmanagedLines += "(none)"
} else {
    foreach ($file in $unmanagedFiles) {
        $hash = (Get-FileHash -LiteralPath $file.FullName -Algorithm SHA256).Hash
        $unmanagedLines += "$hash  $($file.Name)  size=$($file.Length)"
    }
}
Set-Content -LiteralPath $unmanagedReportPath -Value $unmanagedLines -Encoding ASCII

$runtimeCount = ($manifestLines | Where-Object { $_ -notlike '#*' }).Count
Write-Host "Test package ready: $destination ($runtimeCount managed artifacts, profile=$Profile)"
