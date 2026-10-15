param (
  [Parameter(Mandatory = $true)] [string]$DomainName,
  [Parameter(Mandatory = $true)] [string]$DomainNetbiosName,
  [Parameter(Mandatory = $true)] [string]$OuRoot,            # e.g. LAB
  [string]$UpnSuffix = '',                                   # e.g. contoso.us (verified Entra domain)
  [string]$LabUserName = 'lab.user',
  [string]$LabUserPassword = '',
  [string]$LabUserDisplayName = 'Lab User',
  [string]$DnsForwarders = '',
  [string]$IntuneCredentialType = '1',                       # 1 = user credential, 2 = device credential
  [string]$EnrollmentUrlSuffix = '',                         # 'us' for GCC High / DoD, '' for commercial
  [string]$CreateIntuneGpo = 'true',
  [string]$MdeOnboardingBlob = '',                           # raw onboarding JSON (from WindowsDefenderATPOnboardingScript.cmd); optional
  [string]$HydrationScriptBase64 = '',
  [string]$HydrationIntervalMinutes = '60',
  [string]$TenantId = '',                                    # Entra tenant ID -> hybrid-join SCP
  [string]$TenantDomain = '',                                # verified Entra domain -> hybrid-join SCP (defaults to UpnSuffix)
  [string]$ServerComputers = '',                             # comma list of member-server computer names -> OU=MemberServers
  [string]$WorkstationComputers = ''                         # comma list of client computer names -> OU=Workstations
)

$ErrorActionPreference = 'Stop'
New-Item -ItemType Directory -Path 'C:\LabTools' -Force | Out-Null
Start-Transcript -Path 'C:\LabTools\forest-baseline.log' -Append | Out-Null

function Wait-ForDirectory {
  param([int]$TimeoutMinutes = 40)
  $deadline = (Get-Date).AddMinutes($TimeoutMinutes)
  do {
    try {
      Import-Module ActiveDirectory -ErrorAction Stop
      $d = Get-ADDomain -ErrorAction Stop
      if ($d.DNSRoot -ieq $DomainName) {
        # SYSVOL must be shared before GPOs can be written
        if (Test-Path "\\$env:COMPUTERNAME\SYSVOL\$DomainName\Policies") { return $d }
      }
    } catch { }
    Start-Sleep -Seconds 20
  } while ((Get-Date) -lt $deadline)
  throw "Active Directory did not become available within $TimeoutMinutes minutes."
}

$domain = Wait-ForDirectory
$dn = $domain.DistinguishedName
Write-Output "Domain ready: $($domain.DNSRoot) ($dn)"

# --- DNS forwarders (re-apply; the promotion script may have deferred them) --------------------
$fwdList = @()
if ($DnsForwarders) { $fwdList = $DnsForwarders.Split(',') | ForEach-Object { $_.Trim() } | Where-Object { $_ } }
elseif (Test-Path 'C:\LabTools\dns-forwarders.txt') { $fwdList = (Get-Content 'C:\LabTools\dns-forwarders.txt').Split(',') }
if ($fwdList.Count -gt 0) {
  try {
    Import-Module DnsServer
    Set-DnsServerForwarder -IPAddress $fwdList -UseRootHint $false
    Write-Output "DNS forwarders: $($fwdList -join ', ')"
  } catch { Write-Warning "Could not set forwarders: $($_.Exception.Message)" }
}

# --- OU structure ---------------------------------------------------------------------------------
function Ensure-OU {
  param([string]$Name, [string]$Path)
  $ouDn = "OU=$Name,$Path"
  if (-not (Get-ADOrganizationalUnit -LDAPFilter "(distinguishedName=$ouDn)" -SearchBase $Path -SearchScope OneLevel -ErrorAction SilentlyContinue)) {
    New-ADOrganizationalUnit -Name $Name -Path $Path -ProtectedFromAccidentalDeletion $false | Out-Null
    Write-Output "Created OU $ouDn"
  }
  return $ouDn
}

$rootOu = Ensure-OU -Name $OuRoot -Path $dn
$ouWorkstations   = Ensure-OU -Name 'Workstations'    -Path $rootOu
$ouMemberServers  = Ensure-OU -Name 'MemberServers'   -Path $rootOu
$ouLinuxServers   = Ensure-OU -Name 'LinuxServers'    -Path $rootOu
$ouUsers          = Ensure-OU -Name 'Users'           -Path $rootOu
$ouGroups         = Ensure-OU -Name 'Groups'          -Path $rootOu
$ouServiceAccts   = Ensure-OU -Name 'ServiceAccounts' -Path $rootOu
$ouAdmins         = Ensure-OU -Name 'Admins'          -Path $rootOu

# Redirect default containers so joined machines/users land in managed OUs
try { & redircmp.exe $ouWorkstations | Out-Null } catch { Write-Warning "redircmp: $($_.Exception.Message)" }
try { & redirusr.exe $ouUsers        | Out-Null } catch { Write-Warning "redirusr: $($_.Exception.Message)" }

# The members join the default Computers container (the baseline runs after the joins so it is never
# interrupted by the DC promotion reboot); place them in their OUs here so the OU-linked GPOs apply.
function Move-LabComputers {
  param([string]$Names, [string]$TargetOu)
  foreach ($n in ($Names.Split(',') | ForEach-Object { $_.Trim() } | Where-Object { $_ })) {
    $c = Get-ADComputer -Filter "Name -eq '$n'" -ErrorAction SilentlyContinue
    if (-not $c) { Write-Warning "Computer $n not found in AD (join failed?)"; continue }
    if ($c.DistinguishedName -notlike "*,$TargetOu") {
      Move-ADObject -Identity $c.DistinguishedName -TargetPath $TargetOu
      Write-Output "Moved $n -> $TargetOu"
    }
  }
}
Move-LabComputers -Names $ServerComputers -TargetOu $ouMemberServers
Move-LabComputers -Names $WorkstationComputers -TargetOu $ouWorkstations

# --- Hybrid Microsoft Entra join: Service Connection Point -------------------------------------------
# Same object the Entra Connect wizard's "Configure Hybrid Microsoft Entra join" page writes. With it in
# place the clients discover the tenant on their own; Entra Connect only has to sync the device objects.
$scpDomain = if ($TenantDomain) { $TenantDomain } else { $UpnSuffix }
if ($TenantId -and $scpDomain) {
  $configNc = (Get-ADRootDSE).configurationNamingContext
  $drcDn = "CN=Device Registration Configuration,CN=Services,$configNc"
  if (-not (Get-ADObject -Filter "distinguishedName -eq '$drcDn'" -SearchBase "CN=Services,$configNc" -ErrorAction SilentlyContinue)) {
    New-ADObject -Name 'Device Registration Configuration' -Type container -Path "CN=Services,$configNc"
  }
  $scpName = '62a0ff2e-97b9-4513-943f-0d221bd30080'
  $scpDn = "CN=$scpName,$drcDn"
  $keywords = @("azureADName:$scpDomain", "azureADId:$TenantId")
  if (Get-ADObject -Filter "distinguishedName -eq '$scpDn'" -SearchBase $drcDn -ErrorAction SilentlyContinue) {
    Set-ADObject -Identity $scpDn -Replace @{ keywords = $keywords }
  } else {
    New-ADObject -Name $scpName -Type serviceConnectionPoint -Path $drcDn -OtherAttributes @{ keywords = $keywords }
  }
  Write-Output "Hybrid join SCP: azureADName=$scpDomain azureADId=$TenantId"
} else { Write-Warning 'TenantId/TenantDomain not supplied - hybrid join SCP not written (Entra Connect wizard will write it).' }

# --- UPN suffix (lets synced users keep a routable UPN that matches a verified Entra domain) ---
if ($UpnSuffix -and $UpnSuffix -ine $DomainName) {
  $forest = Get-ADForest
  if ($forest.UPNSuffixes -notcontains $UpnSuffix) {
    Set-ADForest -Identity $forest.Name -UPNSuffixes @{Add = $UpnSuffix }
    Write-Output "Added UPN suffix $UpnSuffix"
  }
}

# --- AD Recycle Bin -------------------------------------------------------------------------------
try {
  $rb = Get-ADOptionalFeature -Filter 'name -like "Recycle Bin Feature"'
  if (-not $rb.EnabledScopes) {
    Enable-ADOptionalFeature -Identity 'Recycle Bin Feature' -Scope ForestOrConfigurationSet -Target (Get-ADForest).Name -Confirm:$false
    Write-Output 'AD Recycle Bin enabled'
  }
} catch { Write-Warning "Recycle bin: $($_.Exception.Message)" }

# --- Groups ----------------------------------------------------------------------------------------
$groups = @(
  @{ Name = 'LAB-Workstation-Admins'; Desc = 'Local administrators on lab workstations' },
  @{ Name = 'LAB-Server-Admins';      Desc = 'Local administrators on lab member servers' },
  @{ Name = 'LAB-RDP-Users';          Desc = 'Remote Desktop Users on lab machines' },
  @{ Name = 'LAB-Intune-Enroll';      Desc = 'Users whose devices auto-enroll in Intune (scope for the MDM user scope)' },
  @{ Name = 'LAB-Hybrid-Join-Devices';Desc = 'Computer accounts targeted by hybrid Entra join GPO' },
  @{ Name = 'LAB-SOC-Analysts';       Desc = 'Hunting / Sentinel analysts' }
)
foreach ($g in $groups) {
  if (-not (Get-ADGroup -Filter "name -eq '$($g.Name)'" -ErrorAction SilentlyContinue)) {
    New-ADGroup -Name $g.Name -GroupScope Global -GroupCategory Security -Path $ouGroups -Description $g.Desc | Out-Null
    Write-Output "Created group $($g.Name)"
  }
}

# --- Lab user (CREATED ENABLED — lesson from the SDL lockout incident) ----------------------------
if ($LabUserName) {
  $pwd = if ($LabUserPassword) { $LabUserPassword } else { 'L@b' + [guid]::NewGuid().ToString('N').Substring(0, 14) + '!' }
  $upn = if ($UpnSuffix) { "$LabUserName@$UpnSuffix" } else { "$LabUserName@$DomainName" }
  $existing = Get-ADUser -Filter "sAMAccountName -eq '$LabUserName'" -ErrorAction SilentlyContinue
  if (-not $existing) {
    New-ADUser -Name $LabUserDisplayName -SamAccountName $LabUserName -UserPrincipalName $upn -DisplayName $LabUserDisplayName `
      -GivenName ($LabUserDisplayName.Split(' ')[0]) -Surname ($LabUserDisplayName.Split(' ')[-1]) -Path $ouUsers `
      -AccountPassword (ConvertTo-SecureString $pwd -AsPlainText -Force) -Enabled $true -PasswordNeverExpires $true -ChangePasswordAtLogon $false | Out-Null
    Write-Output "Created lab user $upn (enabled)"
    foreach ($gn in 'LAB-Workstation-Admins', 'LAB-RDP-Users', 'LAB-Intune-Enroll', 'LAB-SOC-Analysts') {
      Add-ADGroupMember -Identity $gn -Members $LabUserName -ErrorAction SilentlyContinue
    }
  }
  else {
    if (-not $existing.Enabled) { Enable-ADAccount -Identity $LabUserName }
  }
}

# --- Group Policy ----------------------------------------------------------------------------------
Import-Module GroupPolicy

function Ensure-Gpo {
  param([string]$Name, [string]$LinkTarget)
  $gpo = Get-GPO -Name $Name -ErrorAction SilentlyContinue
  if (-not $gpo) { $gpo = New-GPO -Name $Name; Write-Output "Created GPO $Name" }
  $links = (Get-GPInheritance -Target $LinkTarget).GpoLinks | Where-Object { $_.DisplayName -eq $Name }
  if (-not $links) { New-GPLink -Name $Name -Target $LinkTarget -LinkEnabled Yes | Out-Null }
  return $gpo
}

# Restricted groups equivalent: add lab groups to local Administrators / Remote Desktop Users via GPP is
# complex to script; we use the simpler "Add-LocalGroupMember" in the client configuration run command.

# Intune automatic MDM enrollment (hybrid-joined devices). On GCC High the device registration and
# enrollment endpoints are the .us endpoints; the registry values below are the documented ADMX policy
# "Enable automatic MDM enrollment using default Microsoft Entra credentials".
if ($CreateIntuneGpo -ieq 'true') {
  $gpo = Ensure-Gpo -Name "$OuRoot - Intune Auto-Enrollment" -LinkTarget $ouWorkstations
  $mdmKey = 'HKLM\SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\MDM'
  Set-GPRegistryValue -Name $gpo.DisplayName -Key $mdmKey -ValueName 'AutoEnrollMDM' -Type DWord -Value 1 | Out-Null
  Set-GPRegistryValue -Name $gpo.DisplayName -Key $mdmKey -ValueName 'UseAADCredentialType' -Type DWord -Value ([int]$IntuneCredentialType) | Out-Null
  # GCC High / DoD note: the MDM enrollment URLs come from the tenant's "Microsoft Intune" mobility
  # (MDM) configuration, which must point at the .us endpoints (Prepare-Tenant.ps1 sets them).
  # $EnrollmentUrlSuffix is recorded for the verification script.
  Set-Content -Path 'C:\LabTools\cloud-suffix.txt' -Value $EnrollmentUrlSuffix
  Write-Output "Intune auto-enrollment GPO linked to $ouWorkstations (credential type $IntuneCredentialType)"
}

# Audit policy + PowerShell logging GPO — makes the lab noisy in the right way for hunting
$auditGpo = Ensure-Gpo -Name "$OuRoot - Security Auditing and Logging" -LinkTarget $dn
$psKey = 'HKLM\SOFTWARE\Policies\Microsoft\Windows\PowerShell'
Set-GPRegistryValue -Name $auditGpo.DisplayName -Key "$psKey\ScriptBlockLogging" -ValueName 'EnableScriptBlockLogging' -Type DWord -Value 1 | Out-Null
Set-GPRegistryValue -Name $auditGpo.DisplayName -Key "$psKey\ModuleLogging" -ValueName 'EnableModuleLogging' -Type DWord -Value 1 | Out-Null
Set-GPRegistryValue -Name $auditGpo.DisplayName -Key "$psKey\ModuleLogging\ModuleNames" -ValueName '*' -Type String -Value '*' | Out-Null
Set-GPRegistryValue -Name $auditGpo.DisplayName -Key "$psKey\Transcription" -ValueName 'EnableTranscripting' -Type DWord -Value 1 | Out-Null
Set-GPRegistryValue -Name $auditGpo.DisplayName -Key "$psKey\Transcription" -ValueName 'OutputDirectory' -Type String -Value 'C:\LabTools\PSTranscripts' | Out-Null
# Process creation auditing with command line
Set-GPRegistryValue -Name $auditGpo.DisplayName -Key 'HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit' -ValueName 'ProcessCreationIncludeCmdLine_Enabled' -Type DWord -Value 1 | Out-Null
# Advanced audit policy via audit.csv in the GPO SYSVOL folder (applies the "force subcategory" model)
Set-GPRegistryValue -Name $auditGpo.DisplayName -Key 'HKLM\SYSTEM\CurrentControlSet\Control\Lsa' -ValueName 'SCENoApplyLegacyAuditPolicy' -Type DWord -Value 1 | Out-Null
$gpoPath = "\\$DomainName\SYSVOL\$DomainName\Policies\{$($auditGpo.Id)}\Machine\Microsoft\Windows NT\Audit"
New-Item -ItemType Directory -Path $gpoPath -Force | Out-Null
$auditCsv = @'
Machine Name,Policy Target,Subcategory,Subcategory GUID,Inclusion Setting,Exclusion Setting,Setting Value
,System,Audit Credential Validation,{0CCE923F-69AE-11D9-BED3-505054503030},Success and Failure,,3
,System,Audit Kerberos Authentication Service,{0CCE9242-69AE-11D9-BED3-505054503030},Success and Failure,,3
,System,Audit Kerberos Service Ticket Operations,{0CCE9240-69AE-11D9-BED3-505054503030},Success and Failure,,3
,System,Audit Computer Account Management,{0CCE9236-69AE-11D9-BED3-505054503030},Success and Failure,,3
,System,Audit Security Group Management,{0CCE9237-69AE-11D9-BED3-505054503030},Success and Failure,,3
,System,Audit User Account Management,{0CCE9235-69AE-11D9-BED3-505054503030},Success and Failure,,3
,System,Audit Other Account Management Events,{0CCE923A-69AE-11D9-BED3-505054503030},Success and Failure,,3
,System,Audit Process Creation,{0CCE922B-69AE-11D9-BED3-505054503030},Success and Failure,,3
,System,Audit Process Termination,{0CCE922C-69AE-11D9-BED3-505054503030},Success,,1
,System,Audit Directory Service Access,{0CCE923B-69AE-11D9-BED3-505054503030},Success and Failure,,3
,System,Audit Directory Service Changes,{0CCE923C-69AE-11D9-BED3-505054503030},Success and Failure,,3
,System,Audit Account Lockout,{0CCE9217-69AE-11D9-BED3-505054503030},Success and Failure,,3
,System,Audit Logoff,{0CCE9216-69AE-11D9-BED3-505054503030},Success,,1
,System,Audit Logon,{0CCE9215-69AE-11D9-BED3-505054503030},Success and Failure,,3
,System,Audit Other Logon/Logoff Events,{0CCE921C-69AE-11D9-BED3-505054503030},Success and Failure,,3
,System,Audit Special Logon,{0CCE921B-69AE-11D9-BED3-505054503030},Success and Failure,,3
,System,Audit Detailed File Share,{0CCE9244-69AE-11D9-BED3-505054503030},Failure,,2
,System,Audit File Share,{0CCE9224-69AE-11D9-BED3-505054503030},Success and Failure,,3
,System,Audit Other Object Access Events,{0CCE9227-69AE-11D9-BED3-505054503030},Success and Failure,,3
,System,Audit Removable Storage,{0CCE9245-69AE-11D9-BED3-505054503030},Success and Failure,,3
,System,Audit Audit Policy Change,{0CCE922F-69AE-11D9-BED3-505054503030},Success and Failure,,3
,System,Audit Authentication Policy Change,{0CCE9230-69AE-11D9-BED3-505054503030},Success,,1
,System,Audit MPSSVC Rule-Level Policy Change,{0CCE9232-69AE-11D9-BED3-505054503030},Success,,1
,System,Audit Sensitive Privilege Use,{0CCE9228-69AE-11D9-BED3-505054503030},Success and Failure,,3
,System,Audit Security State Change,{0CCE9210-69AE-11D9-BED3-505054503030},Success and Failure,,3
,System,Audit Security System Extension,{0CCE9211-69AE-11D9-BED3-505054503030},Success and Failure,,3
,System,Audit System Integrity,{0CCE9212-69AE-11D9-BED3-505054503030},Success and Failure,,3
'@
Set-Content -Path (Join-Path $gpoPath 'audit.csv') -Value $auditCsv -Encoding ASCII
# Register the audit CSE on the GPO (Audit Policy Configuration extension) and bump the version
$gpoObj = Get-ADObject -Identity "CN={$($auditGpo.Id)},CN=Policies,CN=System,$dn" -Properties gPCMachineExtensionNames, versionNumber
$auditCse = '[{F3CCC681-B74C-4060-9F26-CD84525DCA2A}{0F3F3735-573D-9804-99E4-AB2A69BA5FD4}]'
$ext = [string]$gpoObj.gPCMachineExtensionNames
if ($ext -notlike "*F3CCC681-B74C-4060-9F26-CD84525DCA2A*") {
  $newExt = ($ext + $auditCse)
  Set-ADObject -Identity $gpoObj.DistinguishedName -Replace @{ gPCMachineExtensionNames = $newExt }
}
$ver = [int]$gpoObj.versionNumber + 1
Set-ADObject -Identity $gpoObj.DistinguishedName -Replace @{ versionNumber = $ver }
$gptIni = "\\$DomainName\SYSVOL\$DomainName\Policies\{$($auditGpo.Id)}\GPT.INI"
Set-Content -Path $gptIni -Value "[General]`r`nVersion=$ver" -Encoding ASCII
Write-Output 'Audit/logging GPO configured'

# --- MDE onboarding as a startup script GPO (optional; clients also get a direct run-command) ------
if ($MdeOnboardingBlob) {
  $mdeGpo = Ensure-Gpo -Name "$OuRoot - MDE Onboarding" -LinkTarget $dn
  $scriptsPath = "\\$DomainName\SYSVOL\$DomainName\Policies\{$($mdeGpo.Id)}\Machine\Scripts\Startup"
  New-Item -ItemType Directory -Path $scriptsPath -Force | Out-Null
  $onboardPs1 = @"
`$k = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows Advanced Threat Protection'
`$status = Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows Advanced Threat Protection\Status' -ErrorAction SilentlyContinue
if (`$status -and `$status.OnboardingState -eq 1) { exit 0 }
New-Item -Path `$k -Force | Out-Null
`$blob = [System.Text.Encoding]::UTF8.GetString([Convert]::FromBase64String((Get-Content -Raw "`$PSScriptRoot\onboarding.b64")))
New-ItemProperty -Path `$k -Name OnboardingInfo -Value `$blob -PropertyType String -Force | Out-Null
Set-Service -Name Sense -StartupType Automatic
Start-Service -Name Sense -ErrorAction SilentlyContinue
"@
  Set-Content -Path (Join-Path $scriptsPath 'Onboard-MDE.ps1') -Value $onboardPs1 -Encoding ASCII
  Set-Content -Path (Join-Path $scriptsPath 'onboarding.b64') -Value ([Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes($MdeOnboardingBlob))) -Encoding ASCII
  $psScriptsIni = "`r`n[Startup]`r`n0CmdLine=Onboard-MDE.ps1`r`n0Parameters=`r`n"
  Set-Content -Path "\\$DomainName\SYSVOL\$DomainName\Policies\{$($mdeGpo.Id)}\Machine\Scripts\psscripts.ini" -Value $psScriptsIni -Encoding Unicode
  $mdeObj = Get-ADObject -Identity "CN={$($mdeGpo.Id)},CN=Policies,CN=System,$dn" -Properties gPCMachineExtensionNames, versionNumber
  $scriptsCse = '[{42B5FAAE-6536-11D2-AE5A-0000F87571E3}{40B6664F-4972-11D1-A7CA-0000F87571E3}]'
  if ([string]$mdeObj.gPCMachineExtensionNames -notlike '*42B5FAAE-6536-11D2-AE5A-0000F87571E3*') {
    Set-ADObject -Identity $mdeObj.DistinguishedName -Replace @{ gPCMachineExtensionNames = ([string]$mdeObj.gPCMachineExtensionNames + $scriptsCse) }
  }
  $v = [int]$mdeObj.versionNumber + 1
  Set-ADObject -Identity $mdeObj.DistinguishedName -Replace @{ versionNumber = $v }
  Set-Content -Path "\\$DomainName\SYSVOL\$DomainName\Policies\{$($mdeGpo.Id)}\GPT.INI" -Value "[General]`r`nVersion=$v" -Encoding ASCII
  Write-Output 'MDE onboarding startup-script GPO configured'
}

# --- Hydration task on the DC itself (AD-centric noise: group changes, kerberos, LDAP queries) -----
if ($HydrationScriptBase64) {
  $hyd = 'C:\LabTools\Invoke-LabHydration.ps1'
  [IO.File]::WriteAllBytes($hyd, [Convert]::FromBase64String($HydrationScriptBase64))
  $action = New-ScheduledTaskAction -Execute 'powershell.exe' -Argument "-NoProfile -ExecutionPolicy Bypass -File `"$hyd`" -Role DomainController"
  $trigger = New-ScheduledTaskTrigger -Once -At (Get-Date).AddMinutes(5) -RepetitionInterval (New-TimeSpan -Minutes ([int]$HydrationIntervalMinutes))
  Register-ScheduledTask -TaskName 'LAB-Hydration' -Action $action -Trigger $trigger -User 'SYSTEM' -RunLevel Highest -Force | Out-Null
  Write-Output 'Hydration task registered on DC'
}

Write-Output 'BASELINE-STATUS: Success'
Stop-Transcript | Out-Null
