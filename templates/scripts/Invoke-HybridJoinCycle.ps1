<#
.SYNOPSIS
  Drives the hybrid Microsoft Entra join "sync-join" cycle for the lab clients from the Entra Connect
  server (ms01). On a managed/PHS domain, hybrid join is: the client writes its device cert to its AD
  computer object, an Entra Connect delta sync carries it up, then the next join attempt completes.

.DESCRIPTION
  For each target client: trigger the device-join task remotely (writes the cert), run a delta sync
  here, wait, then trigger the join again. error_missing_device / DeviceRenew / fallback_sync mid-cycle
  is normal (SDL lab lesson #5). Run from ms01 with domain admin rights after Entra Connect's first sync.
#>
param(
  [Parameter(Mandatory = $true)] [string[]]$ClientNames,   # short hostnames, e.g. sdl-cl01
  [int]$WaitSeconds = 300,
  [int]$Cycles = 2
)
$ErrorActionPreference = 'Continue'
Import-Module ADSync -ErrorAction Stop

function Invoke-DeviceJoin { param([string]$Computer)
  try {
    Invoke-Command -ComputerName $Computer -ScriptBlock {
      Start-ScheduledTask -TaskPath '\Microsoft\Windows\Workplace Join\' -TaskName 'Automatic-Device-Join' -ErrorAction SilentlyContinue
      & dsregcmd /join | Out-Null
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
    $prt = ($status | Select-String 'AzureAdPrt\s*:\s*(\w+)').Matches.Groups[1].Value
    Write-Host ("  [{0}] AzureAdJoined={1} AzureAdPrt={2}" -f $cn, $aadj, $prt)
  } catch { Write-Warning "  [$cn] status read failed: $($_.Exception.Message)" }
}
Write-Host "If a client still shows AzureAdJoined=NO, run one more cycle — the cert may not have synced yet." -ForegroundColor Yellow
