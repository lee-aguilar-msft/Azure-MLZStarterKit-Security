<#
.SYNOPSIS
  Post-deployment orchestrator for the security lab. Run in Azure Cloud Shell (GCC High: portal.azure.us
  -> Cloud Shell) after the solution deployment finishes. Enables Sentinel content/analytics/UEBA,
  prints the hybrid-join / Entra Connect checklist, and (optionally) nudges the hybrid-join cycle.

.NOTES
  Interactive steps that need MFA (Entra Connect configuration, break-glass GA creation, Conditional
  Access exclusions) are NOT automated here by design — the script tells you exactly what to do.
#>
param(
  [Parameter(Mandatory = $true)] [string]$SubscriptionId,
  [Parameter(Mandatory = $true)] [string]$ResourceGroupName,
  [Parameter(Mandatory = $true)] [string]$WorkspaceName,
  [switch]$EnableXdrConnector,
  [switch]$SkipSentinelContent,
  [string]$DefenderForServersPlan = 'P2',  # '' to leave the plan alone
  [switch]$PrepareTenant,                   # also run Prepare-Tenant.ps1 (Intune MDM URLs/scope, Intune Enrollment SP, CA report)
  [ValidateSet('USGov', 'USGovDoD', 'Global')] [string]$Cloud = 'USGov'
)
$ErrorActionPreference = 'Stop'
$here = Split-Path -Parent $MyInvocation.MyCommand.Path

Write-Host "== Security lab post-deploy ==" -ForegroundColor Cyan
az account set --subscription $SubscriptionId | Out-Null

if (-not $SkipSentinelContent) {
  Write-Host "`n[1/3] Enabling Sentinel Content Hub solutions, analytics rules and UEBA..." -ForegroundColor Cyan
  # hashtable splat (an array splat passes switches positionally; $args is also a PowerShell automatic variable)
  $contentParams = @{ SubscriptionId = $SubscriptionId; ResourceGroupName = $ResourceGroupName; WorkspaceName = $WorkspaceName }
  if ($EnableXdrConnector) { $contentParams['EnableXdrConnector'] = $true }
  & (Join-Path $here 'Enable-SentinelContent.ps1') @contentParams
}

Write-Host "`n[1b] Defender for Cloud plans on the subscription:" -ForegroundColor Cyan
# Seen once in Azure Government: the template's VirtualMachines pricing succeeded, yet the plan read back
# as Free afterwards. Re-assert Defender for Servers here so the lab never runs without it.
if ($DefenderForServersPlan) {
  $vm = az security pricing show -n VirtualMachines --query "{tier:pricingTier,subPlan:subPlan}" -o json | ConvertFrom-Json
  if ($vm.tier -ne 'Standard' -or $vm.subPlan -ne $DefenderForServersPlan) {
    Write-Host "  Defender for Servers was $($vm.tier)/$($vm.subPlan) - re-enabling Standard/$DefenderForServersPlan" -ForegroundColor Yellow
    az security pricing create -n VirtualMachines --tier Standard --subplan $DefenderForServersPlan -o none
  }
}
az security pricing list --query "value[?pricingTier=='Standard'].{plan:name,tier:pricingTier,subPlan:subPlan}" -o table

if ($PrepareTenant) {
  Write-Host "`n[2/3] Tenant preparation for hybrid join + Intune (Prepare-Tenant.ps1, device-code sign-in)..." -ForegroundColor Cyan
  & (Join-Path $here 'Prepare-Tenant.ps1') -Cloud $Cloud
} else {
  Write-Host "`n[2/3] Tenant preparation (run once per tenant):" -ForegroundColor Yellow
  Write-Host "  ./Prepare-Tenant.ps1 -Cloud $Cloud   # Intune MDM URLs (.us in GCC High) + MDM scope, Intune Enrollment SP, CA report"
}

Write-Host "`n[3/3] The one interactive step - Microsoft Entra Connect on <prefix>-ms01 (needs your MFA):" -ForegroundColor Yellow
@'
  0. Break-glass first: a cloud-only Global Admin, excluded from all Conditional Access policies.
  1. Bastion -> <prefix>-ms01 -> VM password, user <admin>@<AD domain> (UPN form; Bastion rejects CORP\<admin>).
  2. Start "Microsoft Entra Connect" (already installed) -> Customize -> Password Hash Synchronization.
  3. Sign in to Entra with a Hybrid Identity / Global Admin (MFA). Add the forest with CORP\<admin>.
  4. Domain/OU filtering: the lab root OU only. Device options: nothing to do - the deployment already
     wrote the hybrid-join Service Connection Point (re-running "Configure Hybrid join" is harmless).
  5. Finish with "Start the synchronization process".
  After the first sync everything else is automatic: the clients retry hybrid join every 30 min
  (LAB-HybridJoin-Retry) and Intune auto-enrollment hourly (LAB-IntuneAutoEnroll-Retry) for 7 days.
  Sign in once to a client as the synced lab user so the user-credential enrollment has a PRT.
  To speed it up: C:\LabTools\Invoke-HybridJoinCycle.ps1 -ClientNames <prefix>-cl01,<prefix>-cl02,<prefix>-cl03
  Then: ./Prepare-Tenant.ps1 -Cloud <cloud> -LabUserUpn <lab user UPN>   # license the synced user
'@ | Write-Host

Write-Host "`nPost-deploy orchestration complete." -ForegroundColor Green
