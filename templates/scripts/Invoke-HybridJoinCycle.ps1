<#
.SYNOPSIS
  Drives the hybrid Microsoft Entra join "sync-join" cycle for the lab clients from the Entra Connect
  server (ms01). On a managed/PHS domain, hybrid join is: the client writes its device cert to its AD
  computer object, an Entra Connect delta sync carries it up, then the next join attempt completes.

.DESCRIPTION
  For each target client: start the device-join tasks remotely (they run as SYSTEM and write the cert),
  run a delta sync here, wait, then repeat. error_missing_device / DeviceRenew / fallback_sync mid-cycle
  is normal.
  Requirements: sign in to the Entra Connect server as a DOMAIN admin (labadmin@<AD domain>, not the local
  labadmin) and WinRM on the clients (the kit enables it on workstations). `dsregcmd /join` is meant to run
  as SYSTEM, so this script starts the SYSTEM tasks instead of calling it in the remote admin session.
  Without WinRM, use the portal instead: client VM -> Run command -> RunPowerShellScript -> dsregcmd /join.
#>
param(
  [Parameter(Mandatory = $true)] [string[]]$ClientNames,   # short hostnames, e.g. lab-cl01
  [int]$WaitSeconds = 300,
  [int]$Cycles = 2
)
$ErrorActionPreference = 'Continue'
Import-Module ADSync -ErrorAction Stop

function Invoke-DeviceJoin { param([string]$Computer)
  try {
    Invoke-Command -ComputerName $Computer -ScriptBlock {
      # both tasks run as SYSTEM; LAB-HybridJoin-Retry (registered by the kit) runs dsregcmd /join
      Start-ScheduledTask -TaskName 'LAB-HybridJoin-Retry' -ErrorAction SilentlyContinue
      Start-ScheduledTask -TaskPath '\Microsoft\Windows\Workplace Join\' -TaskName 'Automatic-Device-Join' -ErrorAction SilentlyContinue
    } -ErrorAction Stop
    Write-Host "  [$Computer] device-join triggered"
  } catch { Write-Warning "  [$Computer] remote trigger failed: $($_.Exception.Message)" }
}

for ($c = 1; $c -le $Cycles; $c++) {
  Write-Host "=== Hybrid join cycle $c of $Cycles ===" -ForegroundColor Cyan
  foreach ($cn in $ClientNames) { Invoke-DeviceJoin -Computer $cn }
  Write-Host "  Running Entra Connect delta sync..."
  try { Start-ADSyncSyncCycle -PolicyType Delta | Out-Null } catch { Write-Warning "  delta sync: $($_.Exception.Message)" }
  Write-Host "  Waiting $WaitSeconds s for the sync + device registration to propagate..."
  Start-Sleep -Seconds $WaitSeconds
}

Write-Host "`nVerifying:" -ForegroundColor Cyan
foreach ($cn in $ClientNames) {
  try {
    $status = Invoke-Command -ComputerName $cn -ScriptBlock { (& dsregcmd /status) -join "`n" } -ErrorAction Stop
    $aadj = ($status | Select-String 'AzureAdJoined\s*:\s*(\w+)').Matches.Groups[1].Value
    $dj = ($status | Select-String 'DomainJoined\s*:\s*(\w+)').Matches.Groups[1].Value
    # AzureAdPrt is per signed-in user, so it is always NO in a remote session - check it on the client itself
    Write-Host ("  [{0}] AzureAdJoined={1} DomainJoined={2}" -f $cn, $aadj, $dj)
  } catch { Write-Warning "  [$cn] status read failed: $($_.Exception.Message)" }
}
Write-Host "If a client still shows AzureAdJoined=NO, run one more cycle — the cert may not have synced yet." -ForegroundColor Yellow
