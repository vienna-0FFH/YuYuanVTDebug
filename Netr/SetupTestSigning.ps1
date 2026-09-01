[CmdletBinding()]
param(
    [string]$Subject = "CN=GuardMetaCore Test Signing",
    [int]$ValidYears = 10
)

$ErrorActionPreference = "Stop"

$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
$principal = [Security.Principal.WindowsPrincipal]$identity
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw "Run SetupTestSigning.ps1 from an elevated PowerShell window."
}

$codeSigningOid = "1.3.6.1.5.5.7.3.3"
$minimumExpiry = (Get-Date).AddDays(30)
$certificate = Get-ChildItem -Path Cert:\CurrentUser\My -CodeSigningCert |
    Where-Object {
        $_.Subject -eq $Subject -and
        $_.HasPrivateKey -and
        $_.NotAfter -gt $minimumExpiry
    } |
    Sort-Object NotAfter -Descending |
    Select-Object -First 1

if (-not $certificate) {
    $certificate = New-SelfSignedCertificate `
        -Type CodeSigningCert `
        -Subject $Subject `
        -FriendlyName "GuardMetaCore Test Signing" `
        -CertStoreLocation "Cert:\CurrentUser\My" `
        -KeyAlgorithm RSA `
        -KeyLength 3072 `
        -HashAlgorithm SHA256 `
        -KeyExportPolicy Exportable `
        -KeyUsage DigitalSignature `
        -NotAfter (Get-Date).AddYears($ValidYears)
}

$hasCodeSigningEku = $certificate.EnhancedKeyUsageList | Where-Object {
    $_.ObjectId -eq $codeSigningOid -or $_.ObjectId.Value -eq $codeSigningOid
}
if (-not $hasCodeSigningEku) {
    throw "Certificate $($certificate.Thumbprint) does not contain the Code Signing EKU."
}

$certificateDir = Join-Path $PSScriptRoot "cert"
$certificatePath = Join-Path $certificateDir "GuardMetaCore-Test.cer"
New-Item -ItemType Directory -Path $certificateDir -Force | Out-Null
Export-Certificate -Cert $certificate -FilePath $certificatePath -Force | Out-Null

foreach ($storeName in @("Root", "TrustedPublisher")) {
    $storePath = "Cert:\LocalMachine\$storeName"
    $trusted = Get-ChildItem -Path $storePath |
        Where-Object Thumbprint -eq $certificate.Thumbprint |
        Select-Object -First 1
    if (-not $trusted) {
        Import-Certificate -FilePath $certificatePath -CertStoreLocation $storePath | Out-Null
    }
}

$testPackage = Join-Path $PSScriptRoot "test-package"
if (Test-Path -LiteralPath $testPackage -PathType Container) {
    Copy-Item -LiteralPath $certificatePath -Destination $testPackage -Force
}

[pscustomobject]@{
    Subject = $certificate.Subject
    Thumbprint = $certificate.Thumbprint
    NotAfter = $certificate.NotAfter
    PublicCertificate = $certificatePath
}
