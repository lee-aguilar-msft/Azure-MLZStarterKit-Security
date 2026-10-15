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
  [switch]$SkipSentinelContent
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

Write-Host "`n[2/3] Break-glass + Conditional Access checklist (manual, needs Global Admin + MFA):" -ForegroundColor Yellow
@'
  1. Create a cloud-only break-glass Global Admin and store its credentials offline.
     Exclude it from ALL Conditional Access policies. (Do this BEFORE enabling Entra Connect sync.)
  2. Ensure a Conditional Access policy that would block interactive MDM enrollment EXCLUDES the
     "Microsoft Intune Enrollment" app (d4ebce55-015a-49b5-a083-c84d1797ae8c). In GCC High the app
     may need its service principal created first:
       Connect-MgGraph -Environment USGov -Scopes Application.ReadWrite.All
       New-MgServicePrincipal -AppId d4ebce55-015a-49b5-a083-c84d1797ae8c
     (AADSTS50076 / interaction_required on silent enrollment = this exclusion is missing.)
  3. Assign the lab user an Entra ID P1/P2 + Intune license so auto-enrollment can proceed.
'@ | Write-Host

Write-Host "`n[3/3] Entra Connect + hybrid join (on the ms01 member server, via Bastion):" -ForegroundColor Yellow
@'
  1. RDP to <prefix>-ms01 through Bastion with your Entra account.
  2. Configure Microsoft Entra Connect (installer is pre-staged at C:\LabTools\AzureADConnect.msi):
       Password Hash Sync, OU filter = the lab root OU only, Hybrid Entra join enabled.
  3. After the first sync, run the hybrid-join cycle for each client:
       Invoke-HybridJoinCycle.ps1  (writes device cert -> delta sync -> re-join)
  4. Verify on a client:  dsregcmd /status   (want AzureAdJoined: YES, AzureAdPrt: YES)
'@ | Write-Host

Write-Host "`nPost-deploy orchestration complete." -ForegroundColor Green
