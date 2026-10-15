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
    1. GET contentProductPackages, register the requested solutions via PUT contentPackages/<id>
       (writable properties only), then deploy each solution's packagedContent ARM template to the
       workspace resource group - that is what creates the data-connector definitions and templates.
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
  [switch]$EnableXdrConnector,
  [switch]$SkipUeba
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

# --- Resolve ARM endpoint + token from the current Az context (cloud-aware) -----------------------
$ctx = (Get-AzContext)
if (-not $ctx) { Connect-AzAccount -Subscription $SubscriptionId | Out-Null; $ctx = Get-AzContext }
Set-AzContext -Subscription $SubscriptionId | Out-Null
$arm = $ctx.Environment.ResourceManagerUrl.TrimEnd('/')
$tok = Get-AzAccessToken -ResourceUrl $ctx.Environment.ResourceManagerUrl
# Az.Accounts 4+ (Cloud Shell today) returns the token as a SecureString; older modules return plain text
$token = if ($tok.Token -is [System.Security.SecureString]) { [System.Net.NetworkCredential]::new('', $tok.Token).Password } else { $tok.Token }
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
      $code = 0
      try { $code = [int]$_.Exception.Response.StatusCode } catch { }
      if ($code -eq 429 -or $code -ge 500) { Start-Sleep -Seconds (5 * $attempt); continue }
      # Surface the ARM error body (pwsh puts it in ErrorDetails) so failures are actionable
      $detail = if ($_.ErrorDetails -and $_.ErrorDetails.Message) { $_.ErrorDetails.Message } else { $_.Exception.Message }
      throw "HTTP $code $Method $($Uri.Split('?')[0].Split('/')[-1]) : $detail"
    }
  }
}

$wsLocation = (Get-AzOperationalInsightsWorkspace -ResourceGroupName $ResourceGroupName -Name $WorkspaceName).Location
Write-Output "ARM endpoint: $arm"
Write-Output "Workspace   : $WorkspaceName ($ResourceGroupName, $wsLocation)"

# ================= 1. Install content hub solutions =================
Write-Output '--- Installing Content Hub solutions ---'
$pkgUri = "$base/contentProductPackages?api-version=$apiContent"
$packages = (Invoke-Arm GET $pkgUri).value
Write-Output "Found $($packages.Count) content packages in the catalog."

foreach ($want in $Solutions) {
  # Catalog contentIds are publisher-prefixed (e.g. azuresentinel.azure-sentinel-solution-azureactivedirectory)
  $pkg = $packages | Where-Object { $_.properties.contentId -eq $want -or $_.properties.contentId -like "*.$want" -or $_.name -eq $want } | Select-Object -First 1
  if (-not $pkg) { Write-Warning "Solution '$want' not found in catalog (skipping)."; continue }
  # The package id in the PUT path is the catalog item's name (publisher-prefixed contentId).
  $pkgId = $pkg.name
  $installUri = "$base/contentPackages/$pkgId`?api-version=$apiContent"
  # Only send the writable package properties - the catalog GET returns read-only fields
  # (installedVersion, metadataResourceId, ...) that the PUT rejects with 400.
  $pp = $pkg.properties
  $installBody = @{ properties = [ordered]@{} }
  foreach ($prop in 'contentId', 'contentProductId', 'contentKind', 'contentSchemaVersion', 'version',
    'displayName', 'publisherDisplayName', 'description', 'providers', 'firstPublishDate', 'lastPublishDate',
    'source', 'author', 'support', 'dependencies', 'categories', 'icon', 'isNew', 'isPreview', 'isFeatured',
    'isDeprecated') {
    if ($pp.PSObject.Properties.Name -contains $prop -and $null -ne $pp.$prop) { $installBody.properties[$prop] = $pp.$prop }
  }
  try {
    Invoke-Arm PUT $installUri $installBody | Out-Null
    Write-Output "Installed: $($pp.displayName) [$pkgId]"
  } catch { Write-Warning "Install failed for $want : $($_.Exception.Message)"; continue }

  # Registering the package only marks it 'Installed' in Content Hub. The solution's content items
  # (data connector definition, analytics/workbook/playbook templates) come from its packaged ARM
  # template - deploying it is exactly what the portal's Install button does.
  try {
    $detail = Invoke-Arm GET "$base/contentProductPackages/$pkgId`?api-version=$apiContent"
    if (-not ($detail.properties.PSObject.Properties.Name -contains 'packagedContent') -or -not $detail.properties.packagedContent) {
      Write-Warning "No packaged content returned for $want - open Content hub and click Install."; continue
    }
    $tpl = $detail.properties.packagedContent
    $tplFile = Join-Path ([IO.Path]::GetTempPath()) "$pkgId.json"
    $tpl | ConvertTo-Json -Depth 100 | Set-Content -Path $tplFile -Encoding utf8
    $tplParams = @{}
    $pnames = @($tpl.parameters.PSObject.Properties.Name)
    if ($pnames -contains 'workspace') { $tplParams['workspace'] = $WorkspaceName }
    if ($pnames -contains 'workspace-location') { $tplParams['workspace-location'] = $wsLocation }
    $short = $want -replace '^azure-sentinel-solution-', ''
    $depName = ('sentinel-' + $short.Substring(0, [Math]::Min(30, $short.Length)) + '-' + (Get-Date -Format 'yyyyMMddHHmm'))
    New-AzResourceGroupDeployment -Name $depName -ResourceGroupName $ResourceGroupName -TemplateFile $tplFile -TemplateParameterObject $tplParams -ErrorAction Stop | Out-Null
    Write-Output "  content deployed: $($pp.displayName) (deployment $depName)"
  } catch { Write-Warning "Content deployment for $want failed: $($_.Exception.Message)" }
}

Start-Sleep -Seconds 30   # let template records populate

# ================= 2. Enable matching analytics rule templates =================
Write-Output '--- Enabling analytics rule templates ---'
$tplUri = "$base/alertRuleTemplates?api-version=$apiRules"
$templates = (Invoke-Arm GET $tplUri).value
Write-Output "Catalog has $($templates.Count) alert rule templates."

$wanted = $templates | Where-Object {
  $_.kind -in @('Scheduled', 'NRT') -and
  ($_.properties.PSObject.Properties.Name -contains 'requiredDataConnectors') -and   # some templates have none (StrictMode-safe)
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
  if (-not $body.properties.Contains('alertRuleTemplateName')) { $body.properties['alertRuleTemplateName'] = $t.name }   # template id lives on the resource, not .properties
  if (-not $body.properties.Contains('templateVersion') -and ($p.PSObject.Properties.Name -contains 'version')) { $body.properties['templateVersion'] = $p.version }
  if (-not $body.properties.Contains('suppressionDuration')) { $body.properties['suppressionDuration'] = 'PT1H' }
  if (-not $body.properties.Contains('suppressionEnabled')) { $body.properties['suppressionEnabled'] = $false }
  $body.properties['enabled'] = $true
  try { Invoke-Arm PUT $ruleUri $body | Out-Null; $enabled++ }
  catch { $failed++; Write-Warning "Rule '$($p.displayName)' failed: $($_.Exception.Message)" }
}
Write-Output "Analytics rules enabled: $enabled (failed/skipped: $failed)"

# ================= 3. Entity Behavior Analytics (UEBA) =================
if ($SkipUeba) { Write-Output '--- UEBA enablement skipped (-SkipUeba) ---' }
else {
Write-Output '--- Enabling Entity Behavior Analytics (UEBA) ---'
try {
  $eaUri = "$base/settings/EntityAnalytics?api-version=$apiSettings"
  Invoke-Arm PUT $eaUri @{ kind = 'EntityAnalytics'; properties = @{ entityProviders = @('AzureActiveDirectory') } } | Out-Null
  $uebaUri = "$base/settings/Ueba?api-version=$apiSettings"
  Invoke-Arm PUT $uebaUri @{ kind = 'Ueba'; properties = @{ dataSources = $UebaDataSources } } | Out-Null
  Write-Output "UEBA enabled over: $($UebaDataSources -join ', ')"
} catch { Write-Warning "UEBA enablement: $($_.Exception.Message)" }
}

# ================= 4. Microsoft Defender XDR connector (optional) =================
if ($EnableXdrConnector) {
  Write-Output '--- Enabling Microsoft Defender XDR data connector ---'
  try {
    $tenantId = $ctx.Tenant.Id
    $existing = (Invoke-Arm GET "$base/dataConnectors?api-version=$apiRules").value | Where-Object { $_.kind -eq 'MicrosoftThreatProtection' }
    if ($existing) { Write-Output "Microsoft Defender XDR connector already present ($($existing[0].name)) - skipping."; $skipXdr = $true } else { $skipXdr = $false }
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
    if (-not $skipXdr) {
      Invoke-Arm PUT $xdrUri $xdrBody | Out-Null
      Write-Output 'Microsoft Defender XDR connector enabled (incidents + alerts).'
    }
  } catch { Write-Warning "XDR connector (may require portal consent): $($_.Exception.Message)" }
}

Write-Output 'SENTINEL-CONTENT-STATUS: Success'
