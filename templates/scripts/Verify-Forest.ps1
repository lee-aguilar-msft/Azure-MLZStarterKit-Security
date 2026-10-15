<#
.SYNOPSIS
  Final gate of the VM module (runs on the DC after every member is joined and configured). Fails the
  deployment - instead of letting it report "complete" - when the forest is not actually usable.
#>
param(
  [Parameter(Mandatory = $true)] [string]$DomainName,
  [Parameter(Mandatory = $true)] [string]$OuRoot,
  [string]$ServerComputers = '',
  [string]$WorkstationComputers = '',
  [string]$RequireScp = 'true'
)
$ErrorActionPreference = 'Stop'
Import-Module ActiveDirectory, GroupPolicy
$problems = New-Object System.Collections.Generic.List[string]
$dn = (Get-ADDomain).DistinguishedName
$root = "OU=$OuRoot,$dn"

foreach ($ou in 'Workstations', 'MemberServers', 'Users', 'Groups') {
  if (-not (Get-ADOrganizationalUnit -LDAPFilter "(ou=$ou)" -SearchBase $root -SearchScope OneLevel -ErrorAction SilentlyContinue)) { $problems.Add("OU=$ou,$root missing") }
}
function Test-Placement([string]$Names, [string]$Ou) {
  foreach ($n in ($Names.Split(',') | ForEach-Object { $_.Trim() } | Where-Object { $_ })) {
    $c = Get-ADComputer -Filter "Name -eq '$n'" -ErrorAction SilentlyContinue
    if (-not $c) { $problems.Add("$n is not joined to $DomainName"); continue }
    if ($c.DistinguishedName -notlike "*,OU=$Ou,$root") { $problems.Add("$n is in $($c.DistinguishedName), expected OU=$Ou") }
    else { Write-Output "OK  $n joined, in OU=$Ou" }
  }
}
Test-Placement $ServerComputers 'MemberServers'
Test-Placement $WorkstationComputers 'Workstations'

foreach ($g in "$OuRoot - Intune Auto-Enrollment", "$OuRoot - Security Auditing and Logging") {
  if (-not (Get-GPO -Name $g -ErrorAction SilentlyContinue)) { $problems.Add("GPO '$g' missing") } else { Write-Output "OK  GPO $g" }
}
if ($RequireScp -ieq 'true') {
  $configNc = (Get-ADRootDSE).configurationNamingContext
  $scp = Get-ADObject -Filter "name -eq '62a0ff2e-97b9-4513-943f-0d221bd30080'" -SearchBase "CN=Services,$configNc" -Properties keywords -ErrorAction SilentlyContinue
  if (-not $scp) { $problems.Add('Hybrid join SCP missing') } else { Write-Output "OK  SCP $($scp.keywords -join '; ')" }
}

if ($problems.Count) {
  $problems | ForEach-Object { Write-Output "FAIL $_" }
  throw "Forest verification failed: $($problems.Count) problem(s). See C:\LabTools\forest-baseline.log and C:\LabTools\join-domain.log on the members."
}
Write-Output 'VERIFY-FOREST: Success'
