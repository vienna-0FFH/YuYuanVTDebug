[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string]$Path,
    [string]$Subject = "CN=GuardMetaCore Test Signing"
)

$ErrorActionPreference = "Stop"

$resolvedPath = (Resolve-Path -LiteralPath $Path).ProviderPath
$certificate = Get-ChildItem -Path Cert:\CurrentUser\My -CodeSigningCert |
    Where-Object {
        $_.Subject -eq $Subject -and
        $_.HasPrivateKey -and
        $_.NotAfter -gt (Get-Date)
    } |
    Sort-Object NotAfter -Descending |
    Select-Object -First 1

if (-not $certificate) {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent().Name
    throw "GuardMetaCore test certificate with a private key is missing for build account '$identity'. Run SetupTestSigning.ps1 once as Administrator under the same account."
}

$kitsBin = Join-Path ${env:ProgramFiles(x86)} "Windows Kits\10\bin"
$signTool = Get-ChildItem -LiteralPath $kitsBin -Directory |
    Where-Object { $_.Name -match '^\d+\.\d+\.\d+\.\d+$' } |
    Sort-Object { [version]$_.Name } -Descending |
    ForEach-Object { Join-Path $_.FullName "x64\signtool.exe" } |
    Where-Object { Test-Path -LiteralPath $_ -PathType Leaf } |
    Select-Object -First 1

if (-not $signTool) {
    throw "Windows SDK signtool.exe was not found under $kitsBin."
}

& $signTool sign /v /fd SHA256 /s My /sha1 $certificate.Thumbprint $resolvedPath
if ($LASTEXITCODE -ne 0) {
    throw "signtool sign failed with exit code $LASTEXITCODE."
}

& $signTool verify /v /pa $resolvedPath
if ($LASTEXITCODE -ne 0) {
    throw "signtool Authenticode verification failed with exit code $LASTEXITCODE."
}

Write-Host "Test-signed $resolvedPath with $($certificate.Thumbprint)"
