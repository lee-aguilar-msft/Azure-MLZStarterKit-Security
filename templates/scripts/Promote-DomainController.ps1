param (
  [Parameter(Mandatory = $true)]
  [string]$DomainName,

  [Parameter(Mandatory = $true)]
  [string]$DomainNetbiosName,

  [Parameter(Mandatory = $true)]
  [string]$SafeModeAdminPassword,

  # Comma-separated list of upstream DNS forwarders (hub firewall DNS proxy / Azure DNS).
  [string]$DnsForwarders = "168.63.129.16"
)

$ErrorActionPreference = 'Stop'
$log = 'C:\LabTools\promote.log'
New-Item -ItemType Directory -Path 'C:\LabTools' -Force | Out-Null
Start-Transcript -Path $log -Append | Out-Null

try {
  # Lab lesson (SDL Gov build): keep NTDS/SYSVOL on the OS disk. A data disk on v6 NVMe sizes was
  # wiped twice by a host move / resource-disk initialisation bug and took the forest with it.
  if (-not (Get-WindowsFeature -Name 'AD-Domain-Services').Installed) {
    Install-WindowsFeature -Name 'AD-Domain-Services', 'DNS', 'GPMC', 'RSAT-AD-Tools', 'RSAT-DNS-Server' -IncludeManagementTools | Out-Null
  }

  Import-Module ADDSDeployment

  $alreadyDc = $false
  try {
    $cs = Get-CimInstance Win32_ComputerSystem
    if ($cs.DomainRole -ge 4 -and $cs.Domain -ieq $DomainName) { $alreadyDc = $true }
  } catch {}

  if ($alreadyDc) {
    Write-Output "This server is already a domain controller for '$DomainName'. Skipping promotion."
  }
  else {
    $safeMode = ConvertTo-SecureString -String $SafeModeAdminPassword -AsPlainText -Force

    Install-ADDSForest `
      -DomainName $DomainName `
      -DomainNetbiosName $DomainNetbiosName `
      -DatabasePath 'C:\Windows\NTDS' `
      -LogPath 'C:\Windows\NTDS' `
      -SysvolPath 'C:\Windows\SYSVOL' `
      -InstallDNS `
      -Force `
      -NoRebootOnCompletion:$true `
      -SafeModeAdministratorPassword $safeMode | Out-Null
    Write-Output 'PROMOTE-STATUS: Success (reboot pending)'
  }

  # Point the DNS server at the hub (Azure Firewall DNS proxy resolves the MLZ private DNS zones
  # for Azure Monitor / Key Vault / Arc private endpoints). Set the forwarders before the reboot so
  # they are present the first time the DNS service starts as a DC.
  $fwd = $DnsForwarders.Split(',') | ForEach-Object { $_.Trim() } | Where-Object { $_ }
  if ($fwd.Count -gt 0) {
    # The DNS role is installed by the promotion; set forwarders in the registry-backed config.
    try {
      Import-Module DnsServer -ErrorAction Stop
      Set-DnsServerForwarder -IPAddress $fwd -UseRootHint $false -ErrorAction Stop
      Write-Output "DNS forwarders set: $($fwd -join ', ')"
    } catch {
      # DnsServer cmdlets may not work until the service starts post-reboot; persist a marker so the
      # baseline script re-applies them.
      Set-Content -Path 'C:\LabTools\dns-forwarders.txt' -Value ($fwd -join ',')
      Write-Output "Forwarders deferred to baseline: $($_.Exception.Message)"
    }
  }
}
finally {
  Stop-Transcript | Out-Null
}

if (-not $alreadyDc) {
  shutdown.exe /r /t 10 /f /c "Completing domain controller promotion for $DomainName"
}
