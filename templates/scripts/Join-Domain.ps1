param (
  [Parameter(Mandatory = $true)] [string]$DomainName,
  [Parameter(Mandatory = $true)] [string]$DomainAdminUsername,
  [Parameter(Mandatory = $true)] [string]$DomainAdminPassword,
  [Parameter(Mandatory = $true)] [string]$DomainControllerIp,
  [string]$OUPath = '',
  [int]$RetryCount = 60
)

$ErrorActionPreference = 'Stop'
New-Item -ItemType Directory -Path 'C:\LabTools' -Force | Out-Null
Start-Transcript -Path 'C:\LabTools\join-domain.log' -Append | Out-Null

$cs = Get-CimInstance -ClassName Win32_ComputerSystem
if ($cs.PartOfDomain -and $cs.Domain -ieq $DomainName) {
  Write-Output "Already joined to '$DomainName'."
  Stop-Transcript | Out-Null
  exit 0
}

# Wait for LDAP and for DNS to answer for the domain (the DC NIC is also the resolver for this VM)
for ($i = 1; $i -le $RetryCount; $i++) {
  $ldap = Test-NetConnection -ComputerName $DomainControllerIp -Port 389 -InformationLevel Quiet -WarningAction SilentlyContinue
  $dns = $false
  try { $dns = [bool](Resolve-DnsName -Name "_ldap._tcp.dc._msdcs.$DomainName" -Type SRV -ErrorAction Stop) } catch {}
  if ($ldap -and $dns) { break }
  if ($i -eq $RetryCount) { throw "Domain controller $DomainControllerIp not ready (LDAP=$ldap DNS=$dns) after $RetryCount attempts." }
  Start-Sleep -Seconds 20
}

$securePassword = ConvertTo-SecureString -String $DomainAdminPassword -AsPlainText -Force
$credential = New-Object System.Management.Automation.PSCredential ("$DomainAdminUsername@$DomainName", $securePassword)

$joined = $false
for ($j = 1; $j -le $RetryCount; $j++) {
  try {
    if ($OUPath) { Add-Computer -DomainName $DomainName -Credential $credential -OUPath $OUPath -ErrorAction Stop }
    else { Add-Computer -DomainName $DomainName -Credential $credential -ErrorAction Stop }
    $joined = $true
    break
  }
  catch {
    Write-Output "Join attempt $j failed: $($_.Exception.Message)"
    if ($j -eq $RetryCount) { throw }
    Start-Sleep -Seconds 20
  }
}

if (-not $joined) { throw "Unable to join '$env:COMPUTERNAME' to '$DomainName'." }
Write-Output "JOIN-STATUS: Success ($env:COMPUTERNAME -> $DomainName, OU=$OUPath)"
Stop-Transcript | Out-Null

shutdown.exe /r /t 15 /f /c "Completing domain join to $DomainName"
