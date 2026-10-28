<#
.SYNOPSIS
  End-to-end detection test for the security lab: runs a small set of safe, documented test actions on the
  lab VMs, then checks Microsoft Sentinel for the alerts and incidents they should raise.

.DESCRIPTION
  The hourly data hydration is deliberately quiet (it feeds hunting, it is not meant to fire alerts). This
  script is the opposite: every action below is chosen to match an analytics rule the kit enables, so you
  can prove the whole chain - VM -> agent -> workspace -> analytics rule / Defender -> incident.

    AD-1  (DC)    disposable user lab.dettest added to Backup Operators, then removed
    AD-2  (DC)    lab.dettest disabled and re-enabled
    AD-3  (DC)    'password never expires' set on lab.dettest
    AD-4  (DC)    6 bad passwords then the right one for lab.dettest
    AD-5  (DC)    25 more bad passwords for lab.dettest inside a minute
    AD-6  (DC)    lab.dettest deleted minutes after it was created
    LNX-1 (ubu01 -> rhel01)  20 SSH password attempts for a user that does not exist
    MDE-1 (cl02)  Microsoft Defender for Endpoint detection test (the documented PowerShell command)
    MDE-2 (cl03)  EICAR antivirus test file
    MDE-3 (ubu01) EICAR antivirus test file + on-demand scan (Defender for Endpoint on Linux)

  The AD actions run as a temporary domain admin (lab.detop) that the script creates and deletes again,
  because several rules only count changes made by a user account (Run command itself runs as SYSTEM).
  Passwords for both disposable accounts are random, generated on the domain controller and never leave it.

  Most matching rules run once a day, so a full result takes up to 24 h: run the script once, then re-run it
  with -VerifyOnly later (it remembers the start time of the last test in ~/.lab-detection-test.json).
  Run from Cloud Shell in PowerShell mode, like Post-Deploy.ps1.

.EXAMPLE
  ./Test-LabDetections.ps1 -SubscriptionId <sub> -ResourceGroupName <prefix>-rg-network -WorkspaceName <workspace>
  ./Test-LabDetections.ps1 -SubscriptionId <sub> -ResourceGroupName <prefix>-rg-network -WorkspaceName <workspace> -VerifyOnly
  ./Test-LabDetections.ps1 ... -Only AD          # re-run just the Active Directory tests
#>
param(
  [Parameter(Mandatory = $true)] [string]$SubscriptionId,
  [Parameter(Mandatory = $true)] [string]$ResourceGroupName,
  [Parameter(Mandatory = $true)] [string]$WorkspaceName,
  [string]$VmPrefix = 'lab',           # VM names: <prefix>-dc01, <prefix>-cl02, ...
  [switch]$VerifyOnly,
  [datetime]$Since,                    # default: start of the last test run recorded in the state file
  [int]$WaitMinutes = 25,              # after the actions, poll this long for the fast detections (0 = no wait)
  [ValidateSet('AD', 'LNX', 'MDE')] [string[]]$Only = @('AD', 'LNX', 'MDE'),   # run / check a subset of the tests
  [ValidateSet('USGov', 'USGovDoD', 'Global')] [string]$Cloud = 'Global'
)
$ErrorActionPreference = 'Stop'
$stateFile = Join-Path $HOME '.lab-detection-test.json'
Set-AzContext -Subscription $SubscriptionId | Out-Null
$defenderPortal = if ($Cloud -eq 'Global') { 'https://security.microsoft.com' } else { 'https://security.microsoft.us' }

# ---------------- what each test should produce ----------------
$tests = @(
  [pscustomobject]@{ Id = 'AD-1';  Host = 'dc01'; Action = 'lab.dettest added to Backup Operators, then removed'
    Rules = @('User account added to built in domain local or global group', 'Account added and removed from privileged groups') }
  [pscustomobject]@{ Id = 'AD-2';  Host = 'dc01'; Action = 'lab.dettest disabled and re-enabled'
    Rules = @('User account enabled and disabled within 10 mins') }
  [pscustomobject]@{ Id = 'AD-3';  Host = 'dc01'; Action = "'Password never expires' set on lab.dettest"
    Rules = @("AD account with Don't Expire Password") }
  [pscustomobject]@{ Id = 'AD-4';  Host = 'dc01'; Action = '6 bad passwords, then the right one'
    Rules = @('SecurityEvent - Multiple authentication failures followed by a success') }
  [pscustomobject]@{ Id = 'AD-5';  Host = 'dc01'; Action = '25 bad passwords inside a minute'
    Rules = @('Failed logon attempts by valid accounts within 10 mins') }
  [pscustomobject]@{ Id = 'AD-6';  Host = 'dc01'; Action = 'lab.dettest deleted minutes after creation'
    Rules = @('User account created and deleted within 10 mins', 'AD user enabled and password not set within 48 hours') }
  [pscustomobject]@{ Id = 'LNX-1'; Host = 'rhel01'; Action = '20 SSH password attempts for a non-existent user (from ubu01)'
    Rules = @('SSH - Potential Brute Force', 'Failed logon attempts in authpriv') }
  [pscustomobject]@{ Id = 'MDE-1'; Host = 'cl02'; Action = 'Defender for Endpoint detection test (documented PowerShell command)'
    Rules = @('*Defender alert on cl02*') }
  [pscustomobject]@{ Id = 'MDE-2'; Host = 'cl03'; Action = 'EICAR antivirus test file'
    Rules = @('*EICAR alert on cl03*') }
  [pscustomobject]@{ Id = 'MDE-3'; Host = 'ubu01'; Action = 'EICAR test file + on-demand scan (Linux)'
    Rules = @('*EICAR alert on ubu01*') }
)

$tests = @($tests | Where-Object { $Only -contains ($_.Id -replace '-\d+$', '') })

# ---------------- remote scripts ----------------
$dcScript = @'
$ErrorActionPreference = 'Stop'
Import-Module ActiveDirectory
function New-LabPassword { $c = 'abcdefghijkmnpqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ23456789'; (-join (1..20 | ForEach-Object { $c[(Get-Random -Maximum $c.Length)] })) + '!7a' }
$dom = Get-ADDomain
$ou = (Get-ADOrganizationalUnit -Filter "name -eq 'Users'" | Select-Object -First 1).DistinguishedName
if (-not $ou) { $ou = $dom.UsersContainer }
foreach ($n in 'lab.dettest', 'lab.detop') { Get-ADUser -Filter "sAMAccountName -eq '$n'" | Remove-ADUser -Confirm:$false }
$lock = (Get-ADDefaultDomainPasswordPolicy).LockoutThreshold
"domain lockout threshold: $lock (0 = never)"

# temporary operator, so the changes below are made by a user account (several rules ignore SYSTEM / machine accounts)
$opPw = New-LabPassword
New-ADUser -Name 'Lab Detection Operator' -SamAccountName 'lab.detop' -UserPrincipalName "lab.detop@$($dom.DNSRoot)" -Path $ou `
  -AccountPassword (ConvertTo-SecureString $opPw -AsPlainText -Force) -Enabled $true
Add-ADGroupMember 'Domain Admins' -Members 'lab.detop'
Start-Sleep -Seconds 15
$cred = New-Object System.Management.Automation.PSCredential ("$($dom.NetBIOSName)\lab.detop", (ConvertTo-SecureString $opPw -AsPlainText -Force))
try {
  Invoke-Command -ComputerName $env:COMPUTERNAME -Credential $cred -ArgumentList $ou -ScriptBlock {
    param($ou)
    $ErrorActionPreference = 'Stop'
    Import-Module ActiveDirectory
    $c = 'abcdefghijkmnpqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ23456789'
    $pw = (-join (1..20 | ForEach-Object { $c[(Get-Random -Maximum $c.Length)] })) + '!7a'
    New-ADUser -Name 'Lab Detection Test' -SamAccountName 'lab.dettest' -Path $ou -AccountPassword (ConvertTo-SecureString $pw -AsPlainText -Force) -Enabled $true
    'AD-1/6 created lab.dettest (enabled)'
    Add-ADGroupMember 'Backup Operators' -Members 'lab.dettest'; Start-Sleep -Seconds 20
    Remove-ADGroupMember 'Backup Operators' -Members 'lab.dettest' -Confirm:$false
    'AD-1   added to and removed from Backup Operators'
    Disable-ADAccount 'lab.dettest'; Start-Sleep -Seconds 10; Enable-ADAccount 'lab.dettest'
    'AD-2   disabled and re-enabled'
    Set-ADUser 'lab.dettest' -PasswordNeverExpires $true
    'AD-3   password never expires set'
    try {
      Start-Sleep -Seconds 15
      Add-Type -AssemblyName System.DirectoryServices.AccountManagement
      # one fresh LDAP connection per attempt: after a run of failed binds the DC drops a reused connection
      # ("The LDAP server is unavailable"), which would abort the test half-way
      function Test-Cred([string]$p) {
        try {
          $pc = New-Object System.DirectoryServices.AccountManagement.PrincipalContext([System.DirectoryServices.AccountManagement.ContextType]::Domain)
          try { $pc.ValidateCredentials('lab.dettest', $p) } finally { $pc.Dispose() }
        } catch { $null }
      }
      1..6 | ForEach-Object { $null = Test-Cred "wrong-$_-$(Get-Random)"; Start-Sleep -Milliseconds 300 }
      $ok = Test-Cred $pw
      "AD-4   6 bad passwords, then the right one (accepted: $ok)"
      $n = 0; 1..25 | ForEach-Object { if ((Test-Cred "wrong-burst-$_-$(Get-Random)") -eq $false) { $n++ }; Start-Sleep -Milliseconds 300 }
      "AD-5   25 bad passwords ($n rejected by the DC)"
      Start-Sleep -Seconds 30
    } finally {
      Remove-ADUser 'lab.dettest' -Confirm:$false
      'AD-6   lab.dettest deleted'
    }
  }
} finally {
  Remove-ADGroupMember 'Domain Admins' -Members 'lab.detop' -Confirm:$false -ErrorAction SilentlyContinue
  Get-ADUser -Filter "sAMAccountName -eq 'lab.detop'" | Remove-ADUser -Confirm:$false
  'temporary operator lab.detop removed'
}
'@

$mdeTestScript = @'
New-Item -ItemType Directory -Path 'C:\test-MDATP-test' -Force | Out-Null
# Microsoft's documented Defender for Endpoint detection test (learn.microsoft.com/defender-endpoint/run-detection-test)
$cmd = '$ErrorActionPreference = ''silentlycontinue'';(New-Object System.Net.WebClient).DownloadFile(''http://127.0.0.1/1.exe'', ''C:\\test-MDATP-test\\invoice.exe'');Start-Process ''C:\\test-MDATP-test\\invoice.exe'''
Start-Process -FilePath powershell.exe -ArgumentList '-ExecutionPolicy', 'Bypass', '-WindowStyle', 'Hidden', '-Command', $cmd -Wait
'MDE-1  detection test command executed'
'@

$eicarWinScript = @'
$d = 'C:\LabTools\detection-test'
New-Item -ItemType Directory -Path $d -Force | Out-Null
# the standard EICAR antivirus test string, assembled at run time
$e = 'X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR' + '-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*'
try { [IO.File]::WriteAllText("$d\eicar.com", $e) } catch { "write blocked: $($_.Exception.Message)" }
Start-Sleep -Seconds 15
"MDE-2  EICAR file written; still on disk after 15 s: $(Test-Path "$d\eicar.com") (False = Defender removed it)"
'@

$eicarLinuxScript = @'
d=/tmp/lab-detection-test; mkdir -p "$d"
printf '%s%s' 'X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR' '-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*' > "$d/eicar.com.txt"
sleep 10
if command -v mdatp >/dev/null 2>&1; then
  echo "real-time protection: $(mdatp health --field real_time_protection_enabled 2>/dev/null)"
  mdatp scan custom --path "$d" 2>&1 | tail -n 3
else
  echo "mdatp not installed on this VM"
fi
echo "MDE-3  EICAR file written and scanned; still present: $(test -e "$d/eicar.com.txt" && echo yes || echo no) (yes = passive mode, detect only)"
rm -rf "$d"
'@

$sshScript = @'
T="$1"
cat > /tmp/lab-askpass.sh <<'EOF'
#!/bin/sh
echo wrong-password
EOF
chmod 700 /tmp/lab-askpass.sh
for i in $(seq 1 20); do
  SSH_ASKPASS=/tmp/lab-askpass.sh SSH_ASKPASS_REQUIRE=force timeout 20 ssh -n \
    -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o PreferredAuthentications=password \
    -o PubkeyAuthentication=no -o NumberOfPasswordPrompts=1 -o ConnectTimeout=10 "labdettest@$T" true >/dev/null 2>&1
done
rm -f /tmp/lab-askpass.sh
echo "LNX-1  20 SSH password attempts for invalid user labdettest -> $T"
'@

function Invoke-LabRun {
  param([string]$Vm, [string]$Script, [string]$Kind = 'Windows', [hashtable]$Parameter)
  $cmd = if ($Kind -eq 'Windows') { 'RunPowerShellScript' } else { 'RunShellScript' }
  $p = @{ ResourceGroupName = $ResourceGroupName; VMName = $Vm; CommandId = $cmd; ScriptString = $Script }
  if ($Parameter) { $p['Parameter'] = $Parameter }
  try {
    $r = Invoke-AzVMRunCommand @p
    ($r.Value | ForEach-Object { $_.Message }) -join "`n" -split "`n" | Where-Object { $_.Trim() -and $_ -notmatch '^\[(stdout|stderr)\]$|^Enable succeeded' } |
      ForEach-Object { "    [$Vm] $_" }
  } catch { Write-Warning "[$Vm] run command failed: $($_.Exception.Message)" }
}

# ---------------- run the actions ----------------
if (-not $VerifyOnly) {
  $start = (Get-Date).ToUniversalTime().AddMinutes(-2)
  @{ start = $start.ToString('o'); workspace = $WorkspaceName; resourceGroup = $ResourceGroupName } | ConvertTo-Json | Set-Content $stateFile
  $vms = Get-AzVM -ResourceGroupName $ResourceGroupName -Status
  $off = $vms | Where-Object { $_.Name -like "$VmPrefix-*" -and $_.PowerState -ne 'VM running' }
  if ($off) { throw "These lab VMs are not running (start them first): $(($off.Name) -join ', ')" }
  $rhel = Get-AzVM -ResourceGroupName $ResourceGroupName -Name "$VmPrefix-rhel01"
  $rhelIp = (Get-AzNetworkInterface -ResourceId $rhel.NetworkProfile.NetworkInterfaces[0].Id).IpConfigurations[0].PrivateIpAddress

  Write-Host "== Lab detection test - actions (started $($start.ToString('u'))) ==" -ForegroundColor Cyan
  if ($Only -contains 'AD') { Write-Host "  domain controller: AD-1..AD-6 (about 3 minutes)"; Invoke-LabRun -Vm "$VmPrefix-dc01" -Script $dcScript }
  if ($Only -contains 'LNX') { Write-Host "  Linux: LNX-1"; Invoke-LabRun -Vm "$VmPrefix-ubu01" -Script $sshScript -Kind Linux -Parameter @{ arg1 = $rhelIp } }
  if ($Only -contains 'MDE') {
    Write-Host "  clients: MDE-1, MDE-2"
    Invoke-LabRun -Vm "$VmPrefix-cl02" -Script $mdeTestScript
    Invoke-LabRun -Vm "$VmPrefix-cl03" -Script $eicarWinScript
    Write-Host "  Linux: MDE-3"; Invoke-LabRun -Vm "$VmPrefix-ubu01" -Script $eicarLinuxScript -Kind Linux
  }
} else {
  if (-not (Test-Path $stateFile) -and -not $Since) { throw "No earlier test recorded in $stateFile - run without -VerifyOnly first, or pass -Since." }
  $start = if ($Since) { $Since.ToUniversalTime() } else { [datetime]::Parse((Get-Content $stateFile | ConvertFrom-Json).start).ToUniversalTime() }
}

# ---------------- verify ----------------
$ws = Get-AzOperationalInsightsWorkspace -ResourceGroupName $ResourceGroupName -Name $WorkspaceName
$ruleFreq = @{}
try {
  $rp = "/subscriptions/$SubscriptionId/resourceGroups/$ResourceGroupName/providers/Microsoft.OperationalInsights/workspaces/$WorkspaceName/providers/Microsoft.SecurityInsights/alertRules?api-version=2023-02-01"
  ((Invoke-AzRestMethod -Path $rp -Method GET).Content | ConvertFrom-Json).value |
    Where-Object { $_.properties.displayName } |
    ForEach-Object { $ruleFreq[$_.properties.displayName] = [pscustomobject]@{ Freq = $_.properties.queryFrequency; Enabled = $_.properties.enabled } }
} catch { Write-Warning "Could not read the analytics rules: $($_.Exception.Message)" }

function Format-Freq([string]$iso) {
  switch -regex ($iso) { '^PT(\d+)M$' { "every $($Matches[1]) min"; break } '^PT(\d+)H$' { "every $($Matches[1]) h"; break } '^P1D$' { 'daily'; break } default { $iso } }
}

function Get-LabResults {
  $since = $start.ToString('o')
  $q = @"
let since = datetime($since);
let inc = SecurityIncident | where TimeGenerated >= since | summarize arg_max(TimeGenerated, *) by IncidentNumber
  | mv-expand AlertId = AlertIds to typeof(string) | project AlertId, IncidentNumber;
SecurityAlert | where TimeGenerated >= since
| summarize arg_max(TimeGenerated, *) by SystemAlertId
| join kind=leftouter inc on `$left.SystemAlertId == `$right.AlertId
| project TimeGenerated, AlertName, ProductName, CompromisedEntity, Entities, IncidentNumber
"@
  (Invoke-AzOperationalInsightsQuery -WorkspaceId $ws.CustomerId -Query $q -Timespan (New-TimeSpan -Days 3)).Results
}

function Show-LabResults($alerts) {
  $rows = foreach ($t in $tests) {
    foreach ($rule in $t.Rules) {
      if ($rule -like '`**') {
        $hostName = "$VmPrefix-$($t.Host)"
        $m = $alerts | Where-Object { ($_.CompromisedEntity -like "*$hostName*" -or $_.Entities -like "*$hostName*") -and
          ($_.ProductName -match 'Defender|Endpoint|XDR|365') -and ($t.Id -eq 'MDE-1' -or $_.AlertName -match 'EICAR') }
        $sched = 'Defender (minutes)'
      } else {
        $m = $alerts | Where-Object { $_.AlertName -eq $rule }
        $f = $ruleFreq[$rule]
        $sched = if (-not $f) { 'rule not found' } elseif (-not $f.Enabled) { 'rule disabled' } else { Format-Freq $f.Freq }
      }
      $first = $m | Sort-Object TimeGenerated | Select-Object -First 1
      [pscustomobject]@{
        Test     = $t.Id
        Expected = $rule.Trim('*')
        Runs     = $sched
        Result   = if ($first) { 'ALERT ' + ([datetime]$first.TimeGenerated).ToUniversalTime().ToString('MM-dd HH:mm') + 'Z' + $(if ($first.IncidentNumber) { " incident #$($first.IncidentNumber)" } else { '' }) } else { 'pending' }
      }
    }
  }
  $rows | Format-Table -AutoSize -Wrap | Out-String -Width 220 | Write-Host
  $rows
}

Write-Host "`n== Results since $($start.ToString('u')) ==" -ForegroundColor Cyan
$deadline = (Get-Date).AddMinutes($(if ($VerifyOnly) { 0 } else { $WaitMinutes }))
do {
  $rows = Show-LabResults (Get-LabResults)
  $fastPending = $rows | Where-Object { $_.Result -eq 'pending' -and $_.Runs -match 'Defender|min' }
  if (-not $fastPending -or (Get-Date) -ge $deadline) { break }
  Write-Host "Waiting for the fast detections ($(@($fastPending).Count) pending: Defender, 10-minute rules) - next check in 5 min..." -ForegroundColor DarkGray
  Start-Sleep -Seconds 300
} while ($true)

$pending = @($rows | Where-Object Result -eq 'pending').Count
Write-Host ("{0} of {1} expected detections seen so far." -f (@($rows).Count - $pending), @($rows).Count) -ForegroundColor Green
if ($pending) {
  Write-Host "Rules marked 'daily' or 'every 2 h' evaluate on their own schedule (a daily rule runs once every 24 h from when it was created)." -ForegroundColor Yellow
  Write-Host "Re-check later with the same command plus -VerifyOnly." -ForegroundColor Yellow
}
Write-Host "Incidents: $defenderPortal -> Incidents & alerts -> Incidents (or Azure portal -> Microsoft Sentinel -> Incidents)."
