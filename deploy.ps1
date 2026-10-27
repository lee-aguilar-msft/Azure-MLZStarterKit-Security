#Requires -Version 7.0
<#
.SYNOPSIS
  Deploys the MLZ Security Lab at subscription scope from a parameters file, prompting for the
  secrets that are intentionally left blank in the committed params files.

.DESCRIPTION
  Wraps `az deployment sub create`. Works in Azure Commercial and Azure Government — pass the matching
  -AzureEnvironment so the correct cloud is selected. Secrets are read with Read-Host -AsSecureString
  and passed inline; they are never written to disk or echoed.

.EXAMPLE
  ./deploy.ps1 -ParametersFile ./params/gov-lab.json -AzureEnvironment AzureUSGovernment `
    -SubscriptionId <subscription-id> -Location usgovvirginia

.NOTES
  Prerequisites (see README): EncryptionAtHost feature registered, Microsoft.ContainerInstance
  provider registered if deploySentinelContentScript=true, and an Entra security group whose object
  ID you pass as entraLoginPrincipalId (or set autoCreateEntraGroup=true in Commercial).
#>
[CmdletBinding()]
param(
  [Parameter(Mandatory)] [string]$ParametersFile,
  [ValidateSet('AzureCloud', 'AzureUSGovernment')] [string]$AzureEnvironment = 'AzureUSGovernment',
  [Parameter(Mandatory)] [string]$SubscriptionId,
  [string]$Location = '',
  [switch]$WhatIf
)
$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $MyInvocation.MyCommand.Path

if (-not (Test-Path $ParametersFile)) { throw "Parameters file not found: $ParametersFile" }
$pf = Get-Content -Raw $ParametersFile | ConvertFrom-Json
if (-not $Location) { $Location = $pf.parameters.location.value }
if (-not $Location) { throw "No location in params file; pass -Location." }

Write-Host "Cloud:        $AzureEnvironment"
Write-Host "Subscription: $SubscriptionId"
Write-Host "Location:     $Location"
Write-Host "Params:       $ParametersFile`n"

az cloud set --name $AzureEnvironment | Out-Null
az account set --subscription $SubscriptionId | Out-Null

function Read-Secret([string]$Prompt) {
  $s = Read-Host -AsSecureString $Prompt
  $b = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($s)
  try { [Runtime.InteropServices.Marshal]::PtrToStringBSTR($b) }
  finally { [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($b) }
}

Write-Host "Enter the deployment secrets (left blank in the params file on purpose):" -ForegroundColor Yellow
$adminPw = Read-Secret "Local/Domain admin password"
$dsrmPw = Read-Secret "DSRM (safe mode) password"
$labPw = Read-Secret "Lab user password (blank = auto-generate)"

$suffix = Get-Date -Format "yyyyMMddHHmm"
$inline = @(
  "adminPassword=$adminPw",
  "safeModeAdminPassword=$dsrmPw",
  "labUserPassword=$labPw"
)

$cmd = @(
  'az', 'deployment', 'sub', ($WhatIf ? 'what-if' : 'create'),
  '--name', "seclab-$suffix",
  '--location', $Location,
  '--template-file', (Join-Path $root 'solution.json'),
  '--parameters', $ParametersFile,
  '--parameters'
) + $inline

Write-Host "`nRunning: az deployment sub $($WhatIf ? 'what-if' : 'create') ..." -ForegroundColor Cyan
& $cmd[0] $cmd[1..($cmd.Count - 1)]
Write-Host "`nDone. If deploySentinel=true, run templates/scripts/Post-Deploy.ps1 in Cloud Shell to finish Sentinel content + hybrid join." -ForegroundColor Green
