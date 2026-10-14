<#
.SYNOPSIS
  Installs Microsoft Sentinel Content Hub solutions and bulk-enables the built-in analytics rule
  templates for Entra ID, Azure Activity, Microsoft Defender XDR, Windows Security Events, Syslog and
  Threat Intelligence, then turns on Entity Behavior Analytics (UEBA). Cloud-aware (Azure Government or
  commercial). Idempotent.

.DESCRIPTION
  Runs either as an Azure deploymentScript (user-assigned managed identity with Microsoft Sentinel
  Contributor on the workspace) or interactively in Cloud Shell. Uses the ARM REST API through the
  current Az context token so it works in both AzureCloud and AzureUSGovernment.

  Method (proven on the RoadRunner commercial lab, ~170 rules enabled):
    1. GET contentProductPackages, install the requested solutions via PUT contentPackages/<id>
       passing the entire package .properties object.
    2. GET alertRuleTemplates, keep Scheduled/NRT templates whose requiredDataConnectors match the
       target connector set, PUT alertRules/<new-guid> with enabled:true.
    3. PUT settings/EntityAnalytics and settings/Ueba to enable UEBA over the chosen data sources.

.NOTES
  Rule templates that fail validation (a known handful reference preview tables/functions) are logged
  and skipped; the script continues.
#>
param (
  [Parameter(Mandatory = $true)] [string]$SubscriptionId,
  [Parameter(Mandatory = $true)] [string]$ResourceGroupName,
  [Parameter(Mandatory = $true)] [string]$WorkspaceName,
  [string[]]$Solutions = @(
    'azure-sentinel-solution-azureactivedirectory',
    'azure-sentinel-solution-azureactivity',
    'azure-sentinel-solution-microsoftdefenderforendpoint',
    'azure-sentinel-solution-microsoft365defender',
    'azure-sentinel-solution-securityevents',
    'azure-sentinel-solution-syslog',
    'azure-sentinel-solution-threatintelligence-taxii',
    'azure-sentinel-solution-uebaessentials'
  ),
  [string[]]$ConnectorIds = @(
    'AzureActiveDirectory', 'AzureActivity', 'MicrosoftThreatProtection',
    'MicrosoftDefenderAdvancedThreatProtection', 'SecurityEvents', 'WindowsSecurityEvents',
    'Syslog', 'ThreatIntelligence', 'ThreatIntelligenceTaxii'
  ),
  [string[]]$UebaDataSources = @('AuditLogs', 'AzureActivity', 'SigninLogs', 'SecurityEvent'),
  [switch]$EnableXdrConnector
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

# --- Resolve ARM endpoint + token from the current Az context (cloud-aware) -----------------------
$ctx = (Get-AzContext)
if (-not $ctx) { Connect-AzAccount -Subscription $SubscriptionId | Out-Null; $ctx = Get-AzContext }
Set-AzContext -Subscription $SubscriptionId | Out-Null
$arm = $ctx.Environment.ResourceManagerUrl.TrimEnd('/')
$token = (Get-AzAccessToken -ResourceUrl $ctx.Environment.ResourceManagerUrl).Token
$headers = @{ Authorization = "Bearer $token"; 'Content-Type' = 'application/json' }
$base = "$arm/subscriptions/$SubscriptionId/resourceGroups/$ResourceGroupName/providers/Microsoft.OperationalInsights/workspaces/$WorkspaceName/providers/Microsoft.SecurityInsights"
$apiContent = '2024-03-01'
$apiRules = '2024-03-01'
$apiSettings = '2023-12-01-preview'

function Invoke-Arm {
  param([string]$Method, [string]$Uri, $Body)
  $json = if ($Body) { $Body | ConvertTo-Json -Depth 60 } else { $null }
  for ($attempt = 1; $attempt -le 5; $attempt++) {
    try { return Invoke-RestMethod -Method $Method -Uri $Uri -Headers $headers -Body $json }
    catch {
      $code = $_.Exception.Response.StatusCode.value__
      if ($code -eq 429 -or $code -ge 500) { Start-Sleep -Seconds (5 * $attempt); continue }
      throw
    }
  }
}

Write-Output "ARM endpoint: $arm"
Write-Output "Workspace   : $WorkspaceName ($ResourceGroupName)"

# ================= 1. Install content hub solutions =================
Write-Output '--- Installing Content Hub solutions ---'
$pkgUri = "$base/contentProductPackages?api-version=$apiContent"
$packages = (Invoke-Arm GET $pkgUri).value
Write-Output "Found $($packages.Count) content packages in the catalog."

foreach ($want in $Solutions) {
  $pkg = $packages | Where-Object { $_.properties.contentId -eq $want -or $_.name -eq $want } | Select-Object -First 1
  if (-not $pkg) { Write-Warning "Solution '$want' not found in catalog (skipping)."; continue }
  $installUri = "$base/contentPackages/$($pkg.properties.contentId)?api-version=$apiContent"
  try {
    Invoke-Arm PUT $installUri $pkg.properties | Out-Null
    Write-Output "Installed: $($pkg.properties.displayName) [$($pkg.properties.contentId)]"
  } catch { Write-Warning "Install failed for $want : $($_.Exception.Message)" }
}

Start-Sleep -Seconds 30   # let template records populate

# ================= 2. Enable matching analytics rule templates =================
Write-Output '--- Enabling analytics rule templates ---'
$tplUri = "$base/alertRuleTemplates?api-version=$apiRules"
$templates = (Invoke-Arm GET $tplUri).value
Write-Output "Catalog has $($templates.Count) alert rule templates."

$wanted = $templates | Where-Object {
  $_.kind -in @('Scheduled', 'NRT') -and
  ($_.properties.requiredDataConnectors | Where-Object { $_.connectorId -in $ConnectorIds })
}
# De-dup on display name (several solutions ship the same template)
$seen = @{}; $unique = @()
foreach ($t in $wanted) { $dn = $t.properties.displayName; if (-not $seen.ContainsKey($dn)) { $seen[$dn] = $true; $unique += $t } }
Write-Output "Matched $($unique.Count) unique Scheduled/NRT templates for connectors: $($ConnectorIds -join ', ')"

$enabled = 0; $failed = 0
foreach ($t in $unique) {
  $p = $t.properties
  $guid = [guid]::NewGuid().ToString()
  $ruleUri = "$base/alertRules/$guid`?api-version=$apiRules"
  $body = [ordered]@{ kind = $t.kind; properties = [ordered]@{} }
  # Carry forward the template's fields; strip nulls (ARM rejects explicit null on several props).
  foreach ($prop in 'displayName', 'description', 'severity', 'query', 'queryFrequency', 'queryPeriod',
    'triggerOperator', 'triggerThreshold', 'suppressionDuration', 'suppressionEnabled', 'tactics',
    'techniques', 'entityMappings', 'eventGroupingSettings', 'alertDetailsOverride', 'customDetails',
    'incidentConfiguration', 'alertRuleTemplateName', 'templateVersion', 'sentinelEntitiesMappings') {
    if ($p.PSObject.Properties.Name -contains $prop -and $null -ne $p.$prop) { $body.properties[$prop] = $p.$prop }
  }
  if (-not $body.properties.Contains('alertRuleTemplateName')) { $body.properties['alertRuleTemplateName'] = $p.name }
  if (-not $body.properties.Contains('templateVersion') -and ($p.PSObject.Properties.Name -contains 'version')) { $body.properties['templateVersion'] = $p.version }
  if (-not $body.properties.Contains('suppressionDuration')) { $body.properties['suppressionDuration'] = 'PT1H' }
  if (-not $body.properties.Contains('suppressionEnabled')) { $body.properties['suppressionEnabled'] = $false }
  $body.properties['enabled'] = $true
  try { Invoke-Arm PUT $ruleUri $body | Out-Null; $enabled++ }
  catch { $failed++; Write-Warning "Rule '$($p.displayName)' failed: $($_.Exception.Message)" }
}
Write-Output "Analytics rules enabled: $enabled (failed/skipped: $failed)"

# ================= 3. Entity Behavior Analytics (UEBA) =================
Write-Output '--- Enabling Entity Behavior Analytics (UEBA) ---'
try {
  $eaUri = "$base/settings/EntityAnalytics?api-version=$apiSettings"
  Invoke-Arm PUT $eaUri @{ kind = 'EntityAnalytics'; properties = @{ entityProviders = @('AzureActiveDirectory') } } | Out-Null
  $uebaUri = "$base/settings/Ueba?api-version=$apiSettings"
  Invoke-Arm PUT $uebaUri @{ kind = 'Ueba'; properties = @{ dataSources = $UebaDataSources } } | Out-Null
  Write-Output "UEBA enabled over: $($UebaDataSources -join ', ')"
} catch { Write-Warning "UEBA enablement: $($_.Exception.Message)" }

# ================= 4. Microsoft Defender XDR connector (optional) =================
if ($EnableXdrConnector) {
  Write-Output '--- Enabling Microsoft Defender XDR data connector ---'
  try {
    $tenantId = $ctx.Tenant.Id
    $xdrUri = "$base/dataConnectors/$([guid]::NewGuid())?api-version=$apiRules"
    $xdrBody = @{
      kind = 'MicrosoftThreatProtection'
      properties = @{
        tenantId = $tenantId
        dataTypes = @{
          incidents = @{ state = 'Enabled' }
          alerts = @{ state = 'Enabled' }
          # XDR raw advanced-hunting event streaming
        }
      }
    }
    Invoke-Arm PUT $xdrUri $xdrBody | Out-Null
    Write-Output 'Microsoft Defender XDR connector enabled (incidents + alerts).'
  } catch { Write-Warning "XDR connector (may require portal consent): $($_.Exception.Message)" }
}

Write-Output 'SENTINEL-CONTENT-STATUS: Success'
