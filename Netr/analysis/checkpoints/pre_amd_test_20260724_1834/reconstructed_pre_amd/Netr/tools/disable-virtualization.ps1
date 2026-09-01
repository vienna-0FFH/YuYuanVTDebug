<#
.SYNOPSIS
    One-shot script to disable everything that could occupy Intel VMX / AMD SVM
.DESCRIPTION
    Used for Netr (SimpleHypervisor) debug environment prep. When
    CPUID.01H.ECX[31]=1 it means Hypervisor Present and our VMXON will fail.
    This script disables in one pass:
        - bcdedit hypervisorlaunchtype off
        - Hyper-V (Microsoft-Hyper-V-All)
        - Windows Hypervisor Platform
        - Virtual Machine Platform
        - WSL / WSL2
        - Containers / Windows Sandbox
        - Windows Defender Application Guard
        - VBS (Virtualization-Based Security)
        - HVCI / Memory Integrity
        - Credential Guard (LsaCfgFlags)
        - Smart App Control
        - Hyper-V services
    A restore script is dropped on the desktop for one-click undo.
.PARAMETER Force
    Skip the YES prompt
.PARAMETER NoRestart
    Do not auto-reboot
.PARAMETER CheckOnly
    Only show current state, no modifications
.EXAMPLE
    .\disable-virtualization.ps1
    .\disable-virtualization.ps1 -Force
    .\disable-virtualization.ps1 -CheckOnly
.NOTES
    Must run as Administrator.
    BIOS may still hold Intel TXT / SGX / Boot Guard - disable them there too.
#>

[CmdletBinding()]
param(
    [switch]$Force,
    [switch]$NoRestart,
    [switch]$CheckOnly
)

$ErrorActionPreference = 'Continue'

# ============================================================
# Helpers
# ============================================================

function Test-Admin {
    $current = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($current)
    return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Info  ($msg) { Write-Host "[i] $msg" -ForegroundColor Cyan }
function Ok    ($msg) { Write-Host "[+] $msg" -ForegroundColor Green }
function Warn  ($msg) { Write-Host "[!] $msg" -ForegroundColor Yellow }
function ErrEx ($msg) { Write-Host "[x] $msg" -ForegroundColor Red }
function Step  ($msg) {
    Write-Host ""
    Write-Host "==> $msg" -ForegroundColor Magenta
}

# ============================================================
# State probe
# ============================================================

function Get-VirtualizationStatus {
    $status = [ordered]@{}

    try {
        $ci = Get-ComputerInfo -Property HyperV* -ErrorAction Stop
        $status['HypervisorPresent']    = $ci.HyperVisorPresent
        $status['SLAT_Available']       = $ci.HyperVRequirementSecondLevelAddressTranslation
        $status['VMMonitorModeExt']     = $ci.HyperVRequirementVMMonitorModeExtensions
        $status['VirtFirmwareEnabled']  = $ci.HyperVRequirementVirtualizationFirmwareEnabled
        $status['DEP_Available']        = $ci.HyperVRequirementDataExecutionPreventionAvailable
    } catch {
        Warn "Get-ComputerInfo failed: $($_.Exception.Message)"
    }

    try {
        $bcd = (& bcdedit /enum '{current}') -join "`n"
        if ($bcd -match 'hypervisorlaunchtype\s+(\w+)') {
            $status['hypervisorlaunchtype'] = $Matches[1]
        } else {
            $status['hypervisorlaunchtype'] = 'NotSet [default Auto]'
        }
    } catch { }

    try {
        $dg = Get-CimInstance -ClassName Win32_DeviceGuard `
                              -Namespace root\Microsoft\Windows\DeviceGuard `
                              -ErrorAction Stop
        $vbsMap = @{ 0 = 'OFF'; 1 = 'Configured'; 2 = 'RUNNING' }
        $vbsStat = [int]$dg.VirtualizationBasedSecurityStatus
        $status['VBSStatus']      = "$vbsStat [$($vbsMap[$vbsStat])]"
        $status['SvcRunning']     = (($dg.SecurityServicesRunning    | ForEach-Object { $_ }) -join ',')
        $status['SvcConfigured']  = (($dg.SecurityServicesConfigured | ForEach-Object { $_ }) -join ',')
    } catch { $status['VBSStatus'] = 'WMI unavailable' }

    try {
        # wsl -l -q outputs UTF-16; PowerShell mis-decodes as ASCII -> spaced chars.
        # Strip embedded NULs to recover the actual distro names.
        $wslRaw = ((& wsl -l -q 2>$null) -join "`n").Replace("`0", '')
        $distros = $wslRaw -split "`r?`n" | Where-Object { $_ -and $_.Trim() } | ForEach-Object { $_.Trim() }
        if ($LASTEXITCODE -eq 0 -and $distros) {
            $status['WSL.Distros'] = ($distros -join ', ')
        } else {
            $status['WSL.Distros'] = '[none]'
        }
    } catch { $status['WSL.Distros'] = '[unavailable]' }

    foreach ($svc in @('vmms','vmcompute','hvhost','vmickvpexchange')) {
        $s = Get-Service -Name $svc -ErrorAction SilentlyContinue
        if ($s) { $status["Svc.$svc"] = "$($s.Status) / $($s.StartType)" }
    }

    return $status
}

function Show-Status ($title, $status) {
    Step $title
    $status.GetEnumerator() | ForEach-Object {
        $key = $_.Key.PadRight(28)
        Write-Host "  $key = $($_.Value)"
    }
}

# ============================================================
# Operations
# ============================================================

function Step-BcdeditHypervisor {
    Step "1. bcdedit /set hypervisorlaunchtype off"
    & bcdedit /set hypervisorlaunchtype off | Out-Null
    if ($LASTEXITCODE -eq 0) {
        Ok "hypervisorlaunchtype = off [reboot to take effect]"
    } else {
        ErrEx "bcdedit failed [exit $LASTEXITCODE]"
    }
}

function Step-DisableFeatures {
    Step "2. Disable Hyper-V / WSL / Containers / Application Guard features"
    $features = @(
        'Microsoft-Hyper-V-All',
        'Microsoft-Hyper-V',
        'Microsoft-Hyper-V-Hypervisor',
        'Microsoft-Hyper-V-Tools-All',
        'Microsoft-Hyper-V-Management-PowerShell',
        'Microsoft-Hyper-V-Management-Clients',
        'Microsoft-Hyper-V-Services',
        'HypervisorPlatform',
        'VirtualMachinePlatform',
        'Microsoft-Windows-Subsystem-Linux',
        'Containers',
        'Containers-DisposableClientVM',
        'Windows-Defender-ApplicationGuard'
    )
    foreach ($f in $features) {
        try {
            $out = & dism /online /disable-feature /featurename:$f /norestart 2>&1 | Out-String
            if ($out -match 'completed successfully') {
                Ok "  disabled: $f"
            } elseif ($out -match 'is not enabled|is not present|0x800f080c') {
                Info "  skip: $f [already disabled or missing]"
            } elseif ($out -match '3010|restart is required') {
                Ok "  disabled: $f [reboot required]"
            } else {
                $tail = ($out.Trim() -split "`n")[-1]
                Warn "  $f -> $tail"
            }
        } catch {
            Warn "  $f -> $($_.Exception.Message)"
        }
    }
}

function Step-DisableVBS {
    Step "3. Disable VBS / HVCI / Credential Guard via registry"
    $entries = @(
        @{ Path='HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard';
           Name='EnableVirtualizationBasedSecurity'; Value=0 }
        @{ Path='HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard';
           Name='RequirePlatformSecurityFeatures';   Value=0 }
        @{ Path='HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard';
           Name='Locked';                            Value=0 }
        @{ Path='HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios\HypervisorEnforcedCodeIntegrity';
           Name='Enabled';                           Value=0 }
        @{ Path='HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios\HypervisorEnforcedCodeIntegrity';
           Name='Locked';                            Value=0 }
        @{ Path='HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios\SystemGuard';
           Name='Enabled';                           Value=0 }
        @{ Path='HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios\CredentialGuard';
           Name='Enabled';                           Value=0 }
        @{ Path='HKLM:\SYSTEM\CurrentControlSet\Control\Lsa';
           Name='LsaCfgFlags';                       Value=0 }
        @{ Path='HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeviceGuard';
           Name='EnableVirtualizationBasedSecurity'; Value=0 }
        @{ Path='HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeviceGuard';
           Name='HypervisorEnforcedCodeIntegrity';   Value=0 }
    )
    foreach ($e in $entries) {
        try {
            if (-not (Test-Path $e.Path)) {
                New-Item -Path $e.Path -Force -ErrorAction Stop | Out-Null
            }
            Set-ItemProperty -Path $e.Path -Name $e.Name -Value $e.Value -Type DWord -Force -ErrorAction Stop
            Ok "  $($e.Path)\$($e.Name) = $($e.Value)"
        } catch {
            Warn "  $($e.Path)\$($e.Name) -> $($_.Exception.Message)"
        }
    }
}

function Step-DisableSmartAppControl {
    Step "4. Smart App Control [Win11 22H2+]"
    $sac = 'HKLM:\SYSTEM\CurrentControlSet\Control\CI\Policy'
    if (Test-Path $sac) {
        try {
            Set-ItemProperty -Path $sac -Name 'VerifiedAndReputablePolicyState' -Value 0 -Type DWord -Force -ErrorAction Stop
            Ok "  Smart App Control = 0 [Off]"
        } catch {
            Warn "  Smart App Control: $($_.Exception.Message)"
        }
    } else {
        Info "  Smart App Control registry key missing [default Off]"
    }
}

function Step-StopWSL {
    Step "5. Shut down WSL2 runtime"
    try {
        & wsl --shutdown 2>$null
        Ok "wsl --shutdown done"
    } catch {
        Info "WSL not installed or unavailable"
    }
}

function Step-StopServices {
    Step "6. Stop and disable Hyper-V services"
    $services = @(
        'vmms',
        'vmcompute',
        'vmickvpexchange',
        'vmicvss',
        'vmicrdv',
        'vmicheartbeat',
        'vmicshutdown',
        'vmicvmsession',
        'vmictimesync',
        'hvhost'
    )
    foreach ($svc in $services) {
        $s = Get-Service -Name $svc -ErrorAction SilentlyContinue
        if (-not $s) { continue }
        try {
            if ($s.Status -eq 'Running') {
                Stop-Service -Name $svc -Force -ErrorAction Stop
            }
            Set-Service -Name $svc -StartupType Disabled -ErrorAction Stop
            Ok "  $svc -> Stopped, Disabled"
        } catch {
            Warn "  $svc -> $($_.Exception.Message)"
        }
    }
}

function Step-DisableKernelDma {
    Step "7. Optional: turn off Kernel DMA Protection registry"
    $entries = @(
        @{ Path='HKLM:\SYSTEM\CurrentControlSet\Control\DmaSecurity';
           Name='DmaGuardEnabled'; Value=0 }
    )
    foreach ($e in $entries) {
        try {
            if (Test-Path $e.Path) {
                Set-ItemProperty -Path $e.Path -Name $e.Name -Value $e.Value -Type DWord -Force -ErrorAction Stop
                Ok "  $($e.Path)\$($e.Name) = $($e.Value)"
            } else {
                Info "  $($e.Path) missing [default Off]"
            }
        } catch {
            Warn "  $($e.Path)\$($e.Name) -> $($_.Exception.Message)"
        }
    }
}

function Generate-RestoreScript {
    Step "0. Generating restore script on Desktop"
    $desktop = [Environment]::GetFolderPath('Desktop')
    $path = Join-Path $desktop 'restore-virtualization.ps1'

    $lines = @()
    $lines += '<# Restore Hyper-V / VBS / WSL — run as Admin, reboots automatically. #>'
    $lines += '[CmdletBinding()] param([switch]$Force)'
    $lines += 'if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {'
    $lines += '    Write-Host "[x] Must run as Administrator" -ForegroundColor Red; exit 1'
    $lines += '}'
    $lines += 'if (-not $Force) {'
    $lines += '    $r = Read-Host "Restore Hyper-V / VBS / WSL? type YES to confirm"'
    $lines += '    if ($r -ne "YES") { exit 0 }'
    $lines += '}'
    $lines += 'Write-Host "[+] Restoring bcdedit..." -ForegroundColor Green'
    $lines += 'bcdedit /set hypervisorlaunchtype auto'
    $lines += '$features = @('
    $lines += '    "Microsoft-Hyper-V-All",'
    $lines += '    "HypervisorPlatform",'
    $lines += '    "VirtualMachinePlatform",'
    $lines += '    "Microsoft-Windows-Subsystem-Linux",'
    $lines += '    "Containers"'
    $lines += ')'
    $lines += 'foreach ($f in $features) {'
    $lines += '    Write-Host "[+] enable: $f" -ForegroundColor Green'
    $lines += '    dism /online /enable-feature /featurename:$f /all /norestart /quiet 2>&1 | Out-Null'
    $lines += '}'
    $lines += 'Write-Host "[+] Restoring VBS / HVCI registry..." -ForegroundColor Green'
    $lines += 'reg add "HKLM\SYSTEM\CurrentControlSet\Control\DeviceGuard" /v EnableVirtualizationBasedSecurity /t REG_DWORD /d 1 /f | Out-Null'
    $lines += 'reg add "HKLM\SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios\HypervisorEnforcedCodeIntegrity" /v Enabled /t REG_DWORD /d 1 /f | Out-Null'
    $lines += 'reg add "HKLM\SYSTEM\CurrentControlSet\Control\Lsa" /v LsaCfgFlags /t REG_DWORD /d 1 /f | Out-Null'
    $lines += 'Write-Host "" '
    $lines += 'Write-Host "[!] Reboot required - 60s auto-reboot (Ctrl+C to cancel)" -ForegroundColor Yellow'
    $lines += 'for ($i = 60; $i -gt 0; $i--) { Write-Host -NoNewline ("`r  {0,2}s ..." -f $i); Start-Sleep -Seconds 1 }'
    $lines += 'Restart-Computer -Force'

    try {
        Set-Content -Path $path -Value $lines -Encoding UTF8 -Force
        Ok "Restore script: $path"
    } catch {
        Warn "Restore script generation failed: $($_.Exception.Message)"
    }
}

# ============================================================
# Main
# ============================================================

Write-Host ""
Write-Host "================================================" -ForegroundColor Magenta
Write-Host "  Netr debug prep - disable all hypervisor occupants" -ForegroundColor Magenta
Write-Host "================================================" -ForegroundColor Magenta

if (-not (Test-Admin)) {
    ErrEx "Must run as Administrator."
    Write-Host ""
    Write-Host "  Right-click PowerShell -> Run as administrator, then re-run." -ForegroundColor Yellow
    exit 1
}

$before = Get-VirtualizationStatus
Show-Status "Current state [before]" $before

if ($CheckOnly) {
    Write-Host ""
    Info "CheckOnly mode - no changes made."
    exit 0
}

if (-not $Force) {
    Write-Host ""
    Warn "This script will disable Hyper-V / WSL2 / VBS / HVCI / Windows Sandbox / Docker Desktop."
    Warn "If your workflow depends on them, Ctrl+C now to abort."
    Warn "A restore-virtualization.ps1 will be dropped on the Desktop for one-click undo."
    Write-Host ""
    $r = Read-Host "Continue? type YES to confirm"
    if ($r -ne 'YES') {
        Info "Cancelled."
        exit 0
    }
}

Generate-RestoreScript

Step-BcdeditHypervisor
Step-DisableFeatures
Step-DisableVBS
Step-DisableSmartAppControl
Step-StopWSL
Step-StopServices
Step-DisableKernelDma

$after = Get-VirtualizationStatus
Show-Status "After execution [pre-reboot]" $after

Step "Next steps"
Write-Host "  1. Reboot target machine so bcdedit / DISM take effect" -ForegroundColor Yellow
Write-Host "  2. After reboot: Get-ComputerInfo | Select HyperV*" -ForegroundColor Yellow
Write-Host "     Expect: HyperVisorPresent = False" -ForegroundColor Yellow
Write-Host "  3. If HyperVisorPresent still True:" -ForegroundColor Yellow
Write-Host "       - Enter BIOS, disable Intel TXT / Intel SGX / Boot Guard" -ForegroundColor Yellow
Write-Host "       - Disable Secure Boot" -ForegroundColor Yellow
Write-Host "       - Keep VT-x enabled [needed for VMX]" -ForegroundColor Yellow
Write-Host "       - VT-d can be turned off [does not affect VMX]" -ForegroundColor Yellow
Write-Host "  4. Restore script on Desktop: restore-virtualization.ps1" -ForegroundColor Yellow

if ($NoRestart) {
    Write-Host ""
    Info "NoRestart - run 'shutdown /r /t 0' manually."
    exit 0
}

Write-Host ""
Warn "Auto-reboot in 60 seconds (Ctrl+C to cancel)"
for ($i = 60; $i -gt 0; $i--) {
    Write-Host -NoNewline ("`r  Reboot in {0,2}s ... " -f $i) -ForegroundColor Yellow
    Start-Sleep -Seconds 1
}
Write-Host ""
Write-Host ""
Info "Restarting..."
Restart-Computer -Force
