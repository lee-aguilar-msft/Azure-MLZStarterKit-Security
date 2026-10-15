param (
  [Parameter(Mandatory = $true)] [string]$DomainName,
  [Parameter(Mandatory = $true)] [string]$DomainNetbiosName,
  [Parameter(Mandatory = $true)] [string]$Role,            # Workstation | MemberServer | EntraConnectServer
  [string]$MdeOnboardingBlob = '',                          # raw onboarding JSON; empty = skip (servers may use MDE.Windows extension instead)
  [string]$HydrationScriptBase64 = '',
  [string]$HydrationIntervalMinutes = '60',
  [string]$CloudSuffix = 'us',                              # 'us' = Azure Government / GCC High; 'com' = commercial
  [string]$EntraConnectDownloadUrl = ''                     # empty = do not pre-install (see the Entra Connect section below)
)

$ErrorActionPreference = 'Continue'
New-Item -ItemType Directory -Path 'C:\LabTools' -Force | Out-Null
Start-Transcript -Path 'C:\LabTools\configure-member.log' -Append | Out-Null

# Wait until the domain join (and its reboot) has landed
$deadline = (Get-Date).AddMinutes(30)
do {
  $cs = Get-CimInstance Win32_ComputerSystem
  if ($cs.PartOfDomain -and $cs.Domain -ieq $DomainName) { break }
  Start-Sleep -Seconds 20
} while ((Get-Date) -lt $deadline)
if (-not ($cs.PartOfDomain -and $cs.Domain -ieq $DomainName)) { Write-Warning 'Domain join not detected; continuing with local configuration only.' }

# --- Local group membership (lets the lab user RDP via Bastion with domain creds, no local admin needed)
$adminGroup = if ($Role -eq 'Workstation') { 'LAB-Workstation-Admins' } else { 'LAB-Server-Admins' }
foreach ($pair in @(@{ Local = 'Administrators'; Domain = $adminGroup }, @{ Local = 'Remote Desktop Users'; Domain = 'LAB-RDP-Users' })) {
  try {
    Add-LocalGroupMember -Group $pair.Local -Member "$DomainNetbiosName\$($pair.Domain)" -ErrorAction Stop
    Write-Output "Added $DomainNetbiosName\$($pair.Domain) to $($pair.Local)"
  } catch { if ($_.Exception.Message -notlike '*already a member*') { Write-Warning "$($pair.Local): $($_.Exception.Message)" } }
}

# --- Defender / MDE onboarding (direct registry method — same thing the onboarding .cmd does) ------
if ($MdeOnboardingBlob) {
  try {
    $status = Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows Advanced Threat Protection\Status' -ErrorAction SilentlyContinue
    if ($status -and $status.OnboardingState -eq 1) { Write-Output 'MDE already onboarded.' }
    else {
      $k = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows Advanced Threat Protection'
      New-Item -Path $k -Force | Out-Null
      New-ItemProperty -Path $k -Name OnboardingInfo -Value $MdeOnboardingBlob -PropertyType String -Force | Out-Null
      # Sample sharing / telemetry defaults used by the official onboarding script
      New-ItemProperty -Path $k -Name AllowSampleCollection -Value 1 -PropertyType DWord -Force | Out-Null
      Set-Service -Name Sense -StartupType Automatic
      Start-Service -Name Sense -ErrorAction SilentlyContinue
      Start-Sleep -Seconds 20
      $status = Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows Advanced Threat Protection\Status' -ErrorAction SilentlyContinue
      Write-Output "MDE OnboardingState = $($status.OnboardingState) (1 = onboarded)"
    }
  } catch { Write-Warning "MDE onboarding: $($_.Exception.Message)" }
}

# Defender AV hardening that the Purview Endpoint DLP / MDE EDR-in-block-mode scenarios expect
try {
  Set-MpPreference -DisableRealtimeMonitoring $false -MAPSReporting Advanced -SubmitSamplesConsent SendAllSamples -CloudBlockLevel High -ErrorAction Stop
  Set-MpPreference -EnableNetworkProtection Enabled -ErrorAction SilentlyContinue
  # ASR rules in AUDIT mode so they generate telemetry without breaking the lab
  $asr = @('56a863a9-875e-4185-98a7-b882c64b5ce5','7674ba52-37eb-4a4f-a9a1-f0f9a1619a2c','d4f940ab-401b-4efc-aadc-ad5f3c50688a','9e6c4e1f-7d60-472f-ba1a-a39ef669e4b2','be9ba2d9-53ea-4cdc-84e5-9b1eeee46550','01443614-cd74-433a-b99e-2ecdc07bfc25','5beb7efe-fd9a-4556-801d-275e5ffc04cc','d3e037e1-3eb8-44c8-a917-57927947596d','3b576869-a4ec-4529-8536-b80a7769e899','75668c1f-73b5-4cf0-bb93-3ecf5cb7cc84','26190899-1602-49e8-8b27-eb1d0a1ce869','e6db77e5-3df2-4cf1-b95a-636979351e5b','d1e49aac-8f56-4280-b9ba-993a6d77406c','b2b3f03d-6a65-4f7b-a9c7-1c7ef74a9ba4','c1db55ab-c21a-4637-bb3f-a12568109d35','92e97fa1-2edf-4476-bdd6-9dd0b4dddc7b','a8f5898e-1dc8-49a9-9878-85004b8a61e6')
  Add-MpPreference -AttackSurfaceReductionRules_Ids $asr -AttackSurfaceReductionRules_Actions AuditMode -ErrorAction SilentlyContinue
  Write-Output 'Defender AV preferences applied (ASR audit mode)'
} catch { Write-Warning "Set-MpPreference: $($_.Exception.Message)" }

# --- Workstations: make hybrid join + Intune enrollment happen without waiting for a logon -------
if ($Role -eq 'Workstation') {
  # Hybrid Entra join is driven by the Automatic-Device-Join scheduled task; kick it so the device
  # writes its certificate to the AD computer object immediately (the sync-join needs an Entra Connect
  # delta sync afterwards — see docs/RUNBOOK.md "Hybrid join recipe").
  try { Start-ScheduledTask -TaskPath '\Microsoft\Windows\Workplace Join\' -TaskName 'Automatic-Device-Join' -ErrorAction Stop } catch {}
  # Re-run the join every 30 min for 7 days: once Entra Connect is configured (the only manual step) and
  # has synced the device, the next attempt completes hybrid join with no further action.
  $joinAction = New-ScheduledTaskAction -Execute 'cmd.exe' -Argument '/c dsregcmd /join >> C:\LabTools\dsregcmd-join.log 2>&1'
  $joinTrigger = New-ScheduledTaskTrigger -Once -At (Get-Date).AddMinutes(10) -RepetitionInterval (New-TimeSpan -Minutes 30) -RepetitionDuration (New-TimeSpan -Days 7)
  Register-ScheduledTask -TaskName 'LAB-HybridJoin-Retry' -Action $joinAction -Trigger $joinTrigger -User 'SYSTEM' -RunLevel Highest -Force | Out-Null
  # MDM auto-enrollment retry (the GPO creates the EnterpriseMgmt task only at the next policy refresh)
  $mdmAction = New-ScheduledTaskAction -Execute 'cmd.exe' -Argument '/c gpupdate /target:computer /force & %windir%\system32\deviceenroller.exe /c /AutoEnrollMDM >> C:\LabTools\autoenroll.log 2>&1'
  $mdmTrigger = New-ScheduledTaskTrigger -Once -At (Get-Date).AddMinutes(20) -RepetitionInterval (New-TimeSpan -Hours 1) -RepetitionDuration (New-TimeSpan -Days 7)
  Register-ScheduledTask -TaskName 'LAB-IntuneAutoEnroll-Retry' -Action $mdmAction -Trigger $mdmTrigger -User 'SYSTEM' -RunLevel Highest -Force | Out-Null
  Write-Output 'Hybrid-join and Intune auto-enroll retry tasks registered'
}

# --- Entra Connect staging on the designated member server -----------------------------------------
if ($Role -eq 'EntraConnectServer') {
  try {
    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
    # TLS 1.2 enforcement required by Entra Connect
    foreach ($p in 'HKLM:\SOFTWARE\Microsoft\.NETFramework\v4.0.30319', 'HKLM:\SOFTWARE\WOW6432Node\Microsoft\.NETFramework\v4.0.30319') {
      New-Item -Path $p -Force | Out-Null
      New-ItemProperty -Path $p -Name SystemDefaultTlsVersions -Value 1 -PropertyType DWord -Force | Out-Null
      New-ItemProperty -Path $p -Name SchUseStrongCrypto -Value 1 -PropertyType DWord -Force | Out-Null
    }
    foreach ($side in 'Server', 'Client') {
      $p = "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2\$side"
      New-Item -Path $p -Force | Out-Null
      New-ItemProperty -Path $p -Name Enabled -Value 1 -PropertyType DWord -Force | Out-Null
      New-ItemProperty -Path $p -Name DisabledByDefault -Value 0 -PropertyType DWord -Force | Out-Null
    }
    # The public download link (download.microsoft.com ...AzureADConnect.msi) still serves 2.4.x, which Microsoft
    # retired on 30 Sep 2026 (minimum 2.5.79.0). Current builds are downloaded from the Entra admin center while
    # signed in, so the lab no longer pre-installs anything unless an explicit MSI URL is passed.
    if ($EntraConnectDownloadUrl) {
      $msi = 'C:\LabTools\AzureADConnect.msi'
      if (-not (Test-Path $msi)) { Invoke-WebRequest -Uri $EntraConnectDownloadUrl -OutFile $msi -UseBasicParsing }
      Start-Process msiexec.exe -ArgumentList "/i `"$msi`" /qn /norestart" -Wait
    }
    $portal = if ($CloudSuffix -eq 'us') { 'https://portal.azure.us' } else { 'https://portal.azure.com' }
    $readme = @"
Microsoft Entra Connect Sync - install and configure (needs your Hybrid Identity Administrator / Global Admin + MFA).
Use version 2.5.79.0 or later; older builds were retired on 30 September 2026.
1. On this server open Edge -> $portal -> Microsoft Entra ID -> Microsoft Entra Connect -> Get started -> Manage
   -> 'Download Connect Sync Agent', and run the downloaded installer.
2. Wizard: Customize -> install required components -> Password Hash Synchronization.
3. Connect to Microsoft Entra ID with a Hybrid Identity Administrator / Global Administrator (MFA).
4. Add the forest $DomainName with $DomainNetbiosName\<domain admin> and let the wizard create the AD DS connector account.
5. If the UPN suffix is not a verified domain: tick 'Continue without matching all UPN suffixes to verified domains'.
6. Domain/OU filtering: sync ONLY the lab root OU. Device options: nothing needed (the deployment wrote the hybrid-join SCP).
7. Tick 'Start the synchronization process when configuration completes'.
8. After the first sync: C:\LabTools\Invoke-HybridJoinCycle.ps1 -ClientNames <prefix>-cl01,<prefix>-cl02,<prefix>-cl03
BEFORE enabling sync, create the cloud-only break-glass Global Admin and exclude it from Conditional Access.
"@
    Set-Content -Path 'C:\LabTools\README-EntraConnect.txt' -Value $readme
    Write-Output 'Entra Connect: TLS 1.2 set and README-EntraConnect.txt written (install from the Entra admin center)'
  } catch { Write-Warning "Entra Connect staging: $($_.Exception.Message)" }
}

# --- Hydration noise generator --------------------------------------------------------------------
if ($HydrationScriptBase64) {
  $hyd = 'C:\LabTools\Invoke-LabHydration.ps1'
  [IO.File]::WriteAllBytes($hyd, [Convert]::FromBase64String($HydrationScriptBase64))
  $action = New-ScheduledTaskAction -Execute 'powershell.exe' -Argument "-NoProfile -ExecutionPolicy Bypass -File `"$hyd`" -Role $Role"
  $trigger = New-ScheduledTaskTrigger -Once -At (Get-Date).AddMinutes(15) -RepetitionInterval (New-TimeSpan -Minutes ([int]$HydrationIntervalMinutes))
  Register-ScheduledTask -TaskName 'LAB-Hydration' -Action $action -Trigger $trigger -User 'SYSTEM' -RunLevel Highest -Force | Out-Null
  Write-Output 'Hydration task registered'
}

Write-Output 'CONFIGURE-STATUS: Success'
Stop-Transcript | Out-Null
