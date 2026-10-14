<#
.SYNOPSIS
    Destroys all resources created by the MLZ AD + Entra Starter Kit deployment.

.DESCRIPTION
    Discovers and removes all resource groups whose names start with the MLZ
    naming prefix, subscription-level Defender plans, policy assignments, and
    optionally the Entra security group. Uses dynamic discovery so it works
    regardless of exact MLZ RG naming internals.

.PARAMETER SubscriptionId
    The Azure subscription ID where the deployment was made.

.PARAMETER Identifier
    The MLZ identifier used during deployment (max 3 chars, e.g. "mlz").

.PARAMETER EnvironmentAbbreviation
    The environment abbreviation used during deployment (e.g. "dev", "test", "prod").

.PARAMETER Location
    The Azure region used during deployment (e.g. "eastus", "usgovvirginia").

.PARAMETER EntraGroupName
    Optional. The Entra security group name to delete.

.PARAMETER RemoveDefenderPlans
    Switch. Resets all Defender for Cloud plans to Free tier.

.PARAMETER RemovePolicyAssignments
    Switch. Removes NIST/IL5 policy assignments created by the deployment.

.PARAMETER Force
    Switch. Skips confirmation prompts.

.EXAMPLE
    # Preview what will be deleted (no -Force, answers 'no' to confirm)
    .\destroy.ps1 -SubscriptionId "xxxx" -Identifier "mlz" -EnvironmentAbbreviation "dev" -Location "eastus"

.EXAMPLE
    # Full teardown
    .\destroy.ps1 -SubscriptionId "xxxx" -Identifier "mlz" -EnvironmentAbbreviation "dev" `
        -Location "eastus" -EntraGroupName "mlz-lab-vm-users" `
        -RemoveDefenderPlans -RemovePolicyAssignments -Force
#>

[CmdletBinding(SupportsShouldProcess)]
param(
    [Parameter(Mandatory)]
    [string]$SubscriptionId,

    [Parameter(Mandatory)]
    [string]$Identifier,

    [Parameter(Mandatory)]
    [string]$EnvironmentAbbreviation,

    [Parameter(Mandatory)]
    [string]$Location,

    [string]$EntraGroupName = "",

    [switch]$RemoveDefenderPlans,

    [switch]$RemovePolicyAssignments,

    [switch]$Force
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

# ---------------------------------------------------------------------------
# Location abbreviation map — must match solution.json exactly
# ---------------------------------------------------------------------------
$locationAbbreviations = @{
    "australiacentral"   = "auc";  "australiacentral2"  = "auc2"; "australiaeast"      = "aue"
    "australiasoutheast" = "ause"; "brazilsouth"        = "brs";  "brazilsoutheast"    = "brse"
    "canadacentral"      = "cac";  "canadaeast"         = "cae";  "centralindia"       = "inc"
    "centralus"          = "usc";  "eastasia"           = "ase";  "eastus"             = "use"
    "eastus2"            = "use2"; "francecentral"      = "frc";  "francesouth"        = "frs"
    "germanynorth"       = "den";  "germanywestcentral" = "dewc"; "israelcentral"      = "ilc"
    "italynorth"         = "itn";  "japaneast"          = "jpe";  "japanwest"          = "jpw"
    "jioindiacentral"    = "injc"; "jioindiawest"       = "injw"; "koreacentral"       = "krc"
    "koreasouth"         = "krs";  "northcentralus"     = "usnc"; "northeurope"        = "eun"
    "norwayeast"         = "noe";  "norwaywest"         = "now";  "polandcentral"      = "plc"
    "qatarcentral"       = "qac";  "southafricanorth"   = "zan";  "southafricawest"    = "zaw"
    "southcentralus"     = "ussc"; "southeastasia"      = "asse"; "southindia"         = "ins"
    "swedencentral"      = "sec";  "switzerlandnorth"   = "chn";  "switzerlandwest"    = "chw"
    "uaecentral"         = "aec";  "uaenorth"           = "aen";  "uksouth"            = "uks"
    "ukwest"             = "ukw";  "westcentralus"      = "uswc"; "westeurope"         = "euw"
    "westindia"          = "inw";  "westus"             = "usw";  "westus2"            = "usw2"
    "westus3"            = "usw3"; "chinaeast"          = "cne";  "chinaeast2"         = "cne2"
    "chinanorth"         = "cnn";  "chinanorth2"        = "cnn2"; "usdodcentral"       = "dodc"
    "usdodeast"          = "dode"; "usgovarizona"       = "az";   "usgovtexas"         = "tx"
    "usgovvirginia"      = "va"
}

if (-not $locationAbbreviations.ContainsKey($Location.ToLower())) {
    Write-Error "Unknown location '$Location'. Add it to the locationAbbreviations map in destroy.ps1."
    exit 1
}

$locAbbr  = $locationAbbreviations[$Location.ToLower()]
$idLower  = $Identifier.ToLower()
# All MLZ RGs start with this prefix: e.g. "mlz-dev-use-"
$rgPrefix = "$idLower-$EnvironmentAbbreviation-$locAbbr-"

# ---------------------------------------------------------------------------
# Defender plans that may have been enabled
# ---------------------------------------------------------------------------
$defenderPlans = @(
    "CloudPosture", "VirtualMachines", "StorageAccounts", "SqlServerVirtualMachines",
    "Containers", "AppServices", "KeyVaults", "Arm", "Dns",
    "OpenSourceRelationalDatabases", "CosmosDbs", "Api"
)

# ---------------------------------------------------------------------------
# Policy assignments created by this deployment
# ---------------------------------------------------------------------------
$policyAssignments = @(
    "assign-nist-800-53",
    "assign-nist-800-171",
    "assign-dod-il5"
)

# ---------------------------------------------------------------------------
# Set subscription context
# ---------------------------------------------------------------------------
Write-Host ""
Write-Host "========================================" -ForegroundColor Cyan
Write-Host " MLZ Starter Kit - Destroy Script" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""
Write-Host "Subscription : $SubscriptionId"
Write-Host "Identifier   : $Identifier"
Write-Host "Environment  : $EnvironmentAbbreviation"
Write-Host "Location     : $Location ($locAbbr)"
Write-Host "RG prefix    : $rgPrefix"
Write-Host ""

Write-Host "Setting subscription context..." -ForegroundColor Cyan
az account set --subscription $SubscriptionId
if ($LASTEXITCODE -ne 0) { Write-Error "Failed to set subscription context."; exit 1 }

# ---------------------------------------------------------------------------
# Discover all matching resource groups dynamically
# ---------------------------------------------------------------------------
Write-Host "Discovering resource groups with prefix '$rgPrefix'..." -ForegroundColor Cyan
$discoveredRgsJson = az group list --query "[?starts_with(name,'$rgPrefix')].name" -o json 2>$null
$discoveredRgs = @($discoveredRgsJson | ConvertFrom-Json)  # @() forces array even when result is null/single item

if ($discoveredRgs.Count -eq 0) {
    Write-Host "  No resource groups found matching prefix '$rgPrefix'." -ForegroundColor Yellow
    Write-Host "  Nothing to delete. Verify your Identifier/EnvironmentAbbreviation/Location inputs." -ForegroundColor Yellow
} else {
    Write-Host ""
    Write-Host "Found $($discoveredRgs.Count) resource group(s) to delete:" -ForegroundColor Yellow
    $discoveredRgs | ForEach-Object { Write-Host "  - $_" -ForegroundColor White }
}

if ($RemoveDefenderPlans)     { Write-Host "  + Defender for Cloud plans will be reset to Free" -ForegroundColor Yellow }
if ($RemovePolicyAssignments) { Write-Host "  + Policy assignments will be removed" -ForegroundColor Yellow }
if ($EntraGroupName)          { Write-Host "  + Entra group '$EntraGroupName' will be deleted" -ForegroundColor Yellow }
Write-Host ""

if (-not $Force) {
    $confirm = Read-Host "Type 'yes' to proceed with destruction"
    if ($confirm -ne "yes") {
        Write-Host "Aborted." -ForegroundColor Red
        exit 0
    }
}

# ---------------------------------------------------------------------------
# 1. Delete resource groups in parallel
# ---------------------------------------------------------------------------
Write-Host "`n[1/4] Deleting resource groups..." -ForegroundColor Cyan

$jobs = @()
foreach ($rg in $discoveredRgs) {
    Write-Host "  Queuing deletion: $rg" -ForegroundColor Yellow
    $jobs += Start-Job -ScriptBlock {
        param($rgName, $sub)
        az group delete --name $rgName --subscription $sub --yes 2>&1
    } -ArgumentList $rg, $SubscriptionId
}

if ($jobs.Count -gt 0) {
    Write-Host "  Waiting for all deletions to complete (can take 15-30 minutes)..." -ForegroundColor Yellow
    $jobs | Wait-Job | Receive-Job
    $jobs | Remove-Job
    Write-Host "  All resource group deletions completed." -ForegroundColor Green
} else {
    Write-Host "  No resource groups to delete." -ForegroundColor Gray
}

# ---------------------------------------------------------------------------
# 2. Reset Defender for Cloud plans to Free
# ---------------------------------------------------------------------------
if ($RemoveDefenderPlans) {
    Write-Host "`n[2/4] Resetting Defender for Cloud plans to Free..." -ForegroundColor Cyan
    foreach ($plan in $defenderPlans) {
        az security pricing create --name $plan --tier Free 2>$null
        if ($LASTEXITCODE -eq 0) {
            Write-Host "  Reset: $plan" -ForegroundColor Green
        } else {
            Write-Host "  Skipped (not enabled or no permission): $plan" -ForegroundColor Gray
        }
    }
} else {
    Write-Host "`n[2/4] Skipping Defender plan reset (use -RemoveDefenderPlans to enable)" -ForegroundColor Gray
}

# ---------------------------------------------------------------------------
# 3. Remove policy assignments
# ---------------------------------------------------------------------------
if ($RemovePolicyAssignments) {
    Write-Host "`n[3/4] Removing policy assignments..." -ForegroundColor Cyan
    foreach ($pa in $policyAssignments) {
        $exists = az policy assignment show --name $pa --query "name" -o tsv 2>$null
        if ($exists) {
            az policy assignment delete --name $pa
            Write-Host "  Removed: $pa" -ForegroundColor Green
        } else {
            Write-Host "  Not found (skipping): $pa" -ForegroundColor Gray
        }
    }
} else {
    Write-Host "`n[3/4] Skipping policy assignment removal (use -RemovePolicyAssignments to enable)" -ForegroundColor Gray
}

# ---------------------------------------------------------------------------
# 4. Delete Entra security group
# ---------------------------------------------------------------------------
if ($EntraGroupName) {
    Write-Host "`n[4/4] Removing Entra security group '$EntraGroupName'..." -ForegroundColor Cyan
    $groupId = az ad group show --group $EntraGroupName --query "id" -o tsv 2>$null
    if ($groupId) {
        az ad group delete --group $groupId
        Write-Host "  Deleted: $EntraGroupName" -ForegroundColor Green
    } else {
        Write-Host "  Not found (skipping): $EntraGroupName" -ForegroundColor Gray
    }
} else {
    Write-Host "`n[4/4] Skipping Entra group removal (use -EntraGroupName to enable)" -ForegroundColor Gray
}

# ---------------------------------------------------------------------------
# Done — verify
# ---------------------------------------------------------------------------
Write-Host ""
Write-Host "========================================" -ForegroundColor Green
Write-Host " Destroy complete." -ForegroundColor Green
Write-Host "========================================" -ForegroundColor Green
Write-Host ""
Write-Host "Verify remaining resources:" -ForegroundColor Yellow
Write-Host "  az group list --query `"[?starts_with(name,'$rgPrefix')]`" -o table" -ForegroundColor White
Write-Host ""
