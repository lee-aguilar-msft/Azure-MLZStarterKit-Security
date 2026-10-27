param (
  [string]$Role = 'Workstation'   # Workstation | MemberServer | DomainController | EntraConnectServer
)

# Lab data hydration: generates benign-but-realistic activity so the Sentinel workspace and MDE have
# material to hunt over. Everything here is ordinary administrative/user behaviour run against the
# lab's own machines and directory — it is noise for detections, not an attack simulation.

$ErrorActionPreference = 'SilentlyContinue'
$stamp = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
$log = 'C:\LabTools\hydration.log'
"[$stamp] hydration tick ($Role)" | Add-Content $log

function New-LabUserActivity {
  # Simulate an interactive user: create files, run common binaries, touch the registry run-keys,
  # make a few web requests to Microsoft endpoints.
  $tmp = Join-Path $env:TEMP ("lab_" + [guid]::NewGuid().ToString('N').Substring(0,8))
  New-Item -ItemType Directory -Path $tmp -Force | Out-Null
  1..5 | ForEach-Object { "sample line $_ $(Get-Random)" | Out-File (Join-Path $tmp "doc$_.txt") }
  Get-Process | Out-File (Join-Path $tmp 'proc.txt')
  Get-Service  | Out-File (Join-Path $tmp 'svc.txt')
  & whoami /all  | Out-Null
  & ipconfig /all | Out-Null
  & nltest /dsgetdc:$env:USERDNSDOMAIN | Out-Null
  try { Invoke-WebRequest -Uri 'https://www.microsoft.com' -UseBasicParsing -TimeoutSec 15 | Out-Null } catch {}
  Remove-Item $tmp -Recurse -Force
}

function New-LabDirectoryActivity {
  Import-Module ActiveDirectory
  # Routine directory reads + a churn user whose group membership flips (generates 4728/4729/4738)
  Get-ADUser -Filter * | Out-Null
  Get-ADComputer -Filter * | Out-Null
  $churn = 'lab.churn'
  if (-not (Get-ADUser -Filter "sAMAccountName -eq '$churn'")) {
    $ou = (Get-ADOrganizationalUnit -Filter "name -eq 'Users'" | Select-Object -First 1).DistinguishedName
    if ($ou) {
      New-ADUser -Name 'Lab Churn' -SamAccountName $churn -Path $ou `
        -AccountPassword (ConvertTo-SecureString ('C'+[guid]::NewGuid().ToString('N').Substring(0,14)+'!') -AsPlainText -Force) `
        -Enabled $true
    }
  }
  $grp = Get-ADGroup -Filter "name -eq 'LAB-SOC-Analysts'"
  if ($grp -and (Get-ADUser -Filter "sAMAccountName -eq '$churn'")) {
    if (Get-ADGroupMember $grp | Where-Object SamAccountName -eq $churn) { Remove-ADGroupMember $grp -Members $churn -Confirm:$false }
    else { Add-ADGroupMember $grp -Members $churn }
  }
  # Two deliberately failing sign-ins for the churn user (4625 / 4771 on the DC). A WMI call with explicit
  # credentials cannot be used here: Windows refuses credentials on local connections without any logon attempt.
  try {
    Add-Type -AssemblyName System.DirectoryServices.AccountManagement
    $pc = New-Object System.DirectoryServices.AccountManagement.PrincipalContext([System.DirectoryServices.AccountManagement.ContextType]::Domain)
    1..2 | ForEach-Object { $pc.ValidateCredentials($churn, 'wrong-password-123') | Out-Null }
    $pc.Dispose()
  } catch {}
}

New-LabUserActivity
if ($Role -eq 'DomainController') { New-LabDirectoryActivity }
"[$stamp] done" | Add-Content $log
