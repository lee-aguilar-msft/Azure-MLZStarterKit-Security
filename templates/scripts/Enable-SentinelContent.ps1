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

  Method (proven on the commercial lab, ~170 rules enabled):
    1. GET contentProductPackages, then deploy each requested solution's packagedContent ARM template
       to the workspace resource group - that creates the package record, the data-connector
       definition and the analytics/workbook/playbook templates (what the portal's Install does).
    2. GET alertRuleTemplates, keep Scheduled/NRT templates whose requiredDataConnectors match the
       target connector set, PUT alertRules/<new-guid> with enabled:true.
    3. PUT settings/EntityAnalytics and settings/Ueba to enable UEBA over the chosen data sources.
    4. Optionally PUT the Microsoft Defender XDR data connector (incidents + alerts).
    5. Route Microsoft Entra ID logs (tenant diagnostic setting, microsoft.aadiam) and the Azure
       Activity log (subscription diagnostic setting) to the workspace so those connectors show
       Connected. Skip with -SkipLogRouting.

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
  [switch]$SkipUeba,
  [switch]$SkipLogRouting,
  [string]$DiagnosticSettingName = 'sentinel-lab'
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
$apiConnectors = '2024-01-01-preview'   # MicrosoftThreatProtection connector kind is preview-only

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
function Invoke-ArmList {
  # GET a collection and follow nextLink pages
  param([string]$Uri)
  $all = @(); $next = $Uri
  while ($next) { $page = Invoke-Arm GET $next; $all += @($page.value); $next = if ($page.PSObject.Properties.Name -contains 'nextLink') { $page.nextLink } else { $null } }
  return $all
}

Write-Output "ARM endpoint: $arm"
Write-Output "Workspace   : $WorkspaceName ($ResourceGroupName, $wsLocation)"

# ================= 1. Install content hub solutions =================
Write-Output '--- Installing Content Hub solutions ---'
$pkgUri = "$base/contentProductPackages?api-version=$apiContent"
$packages = @(Invoke-ArmList $pkgUri)
Write-Output "Found $($packages.Count) content packages in the catalog."

foreach ($want in $Solutions) {
  # Catalog contentIds are publisher-prefixed (e.g. azuresentinel.azure-sentinel-solution-azureactivedirectory)
  $pkg = $packages | Where-Object { $_.properties.contentId -eq $want -or $_.properties.contentId -like "*.$want" -or $_.name -eq $want } | Select-Object -First 1
  if (-not $pkg) { Write-Warning "Solution '$want' not found in catalog (skipping)."; continue }
  # Catalog item name = contentProductId (e.g. ...-sl-xptjiwh6w32o6); contentId = azuresentinel.azure-sentinel-solution-x
  $pkgId = $pkg.name
  $pp = $pkg.properties
  $contentId = $pp.contentId

  # A solution is installed by deploying its packaged ARM template (what the portal's Install button
  # does). The template creates the Microsoft.SecurityInsights/contentPackages record itself, plus the
  # data-connector definition and the analytics/workbook/playbook templates. Registering the package
  # by a plain PUT contentPackages/<id> only flips the Content Hub status and then blocks the template
  # with "contentId ... is already associated with another package", so remove any such record first.
  try {
    $installed = @((Invoke-Arm GET "$base/contentPackages?api-version=$apiContent").value)
    foreach ($stale in ($installed | Where-Object { $_.properties.contentId -eq $contentId -and $_.name -ne $contentId })) {
      Write-Output "  removing stale package record $($stale.name)"
      Invoke-Arm DELETE "$base/contentPackages/$($stale.name)?api-version=$apiContent" | Out-Null
    }
  } catch { Write-Warning "Could not inspect installed packages: $($_.Exception.Message)" }

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
    Write-Output "Installed: $($pp.displayName) [$contentId] via deployment $depName"
  } catch { Write-Warning "Install of $want failed: $($_.Exception.Message)" }
}

Start-Sleep -Seconds 30   # let template records populate

# ================= 2. Enable matching analytics rule templates =================
Write-Output '--- Enabling analytics rule templates ---'
$tplUri = "$base/alertRuleTemplates?api-version=$apiRules"
$templates = @(Invoke-ArmList $tplUri)
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

# Idempotency: rules already created from a template are skipped, and if an earlier run was
# interrupted and left duplicates (same template, several rule ids) the extras are removed.
# @(): a fresh workspace has exactly one rule (Advanced Multistage Attack Detection); PowerShell would
# return it as a scalar and .Count fails under StrictMode
$existingRules = @(Invoke-ArmList "$base/alertRules?api-version=$apiRules")
$haveTemplate = @{}; $dupes = 0
foreach ($r in $existingRules) {
  $tn = if ($r.properties.PSObject.Properties.Name -contains 'alertRuleTemplateName') { $r.properties.alertRuleTemplateName } else { $null }
  if (-not $tn) { continue }
  if ($haveTemplate.ContainsKey($tn)) {
    try { Invoke-Arm DELETE "$base/alertRules/$($r.name)?api-version=$apiRules" | Out-Null; $dupes++ } catch { }
  } else { $haveTemplate[$tn] = $true }
}
Write-Output "Existing rules: $($existingRules.Count) (duplicates removed: $dupes)"

$enabled = 0; $failed = 0; $skipped = 0
foreach ($t in $unique) {
  if ($haveTemplate.ContainsKey($t.name)) { $skipped++; continue }
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
Write-Output "Analytics rules enabled: $enabled new, $skipped already present, $failed templates rejected by the service"

# ================= 3. Entity Behavior Analytics (UEBA) =================
if ($SkipUeba) { Write-Output '--- UEBA enablement skipped (-SkipUeba) ---' }
else {
Write-Output '--- Enabling Entity Behavior Analytics (UEBA) ---'
try {
  # Settings are singletons: an update of an existing one must carry its current ETag.
  function Set-SentinelSetting {
    param([string]$Name, [hashtable]$Body)
    $uri = "$base/settings/$Name`?api-version=$apiSettings"
    try { $cur = Invoke-Arm GET $uri; if ($cur.PSObject.Properties.Name -contains 'etag' -and $cur.etag) { $Body['etag'] = $cur.etag } } catch { }
    Invoke-Arm PUT $uri $Body | Out-Null
  }
  Set-SentinelSetting 'EntityAnalytics' @{ kind = 'EntityAnalytics'; properties = @{ entityProviders = @('AzureActiveDirectory') } }
  Set-SentinelSetting 'Ueba' @{ kind = 'Ueba'; properties = @{ dataSources = $UebaDataSources } }
  Write-Output "UEBA enabled over: $($UebaDataSources -join ', ')"
} catch { Write-Warning "UEBA enablement: $($_.Exception.Message)" }
}

# ================= 4. Microsoft Defender XDR connector (optional) =================
if ($EnableXdrConnector) {
  Write-Output '--- Enabling Microsoft Defender XDR data connector ---'
  try {
    $tenantId = $ctx.Tenant.Id
    $existing = @((Invoke-Arm GET "$base/dataConnectors?api-version=$apiConnectors").value | Where-Object { $_.kind -eq 'MicrosoftThreatProtection' })
    if ($existing.Count) { Write-Output "Microsoft Defender XDR connector already present ($($existing[0].name)) - skipping."; $skipXdr = $true } else { $skipXdr = $false }
    $xdrUri = "$base/dataConnectors/$([guid]::NewGuid())?api-version=$apiConnectors"
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

# ================= 5. Entra ID + Azure Activity log routing (diagnostic settings) =================
# The Entra ID and Azure Activity connectors show "Connected" once their logs are routed to the
# workspace. Both are diagnostic settings: tenant-level (microsoft.aadiam, needs Global/Security
# Administrator) and subscription-level (Activity log). Same calls the connector pages make.
if (-not $SkipLogRouting) {
  $wsId = "/subscriptions/$SubscriptionId/resourceGroups/$ResourceGroupName/providers/Microsoft.OperationalInsights/workspaces/$WorkspaceName"
  Write-Output '--- Routing Microsoft Entra ID logs to the workspace (tenant diagnostic setting) ---'
  $entraCats = @('AuditLogs', 'SignInLogs', 'NonInteractiveUserSignInLogs', 'ServicePrincipalSignInLogs',
    'ManagedIdentitySignInLogs', 'ProvisioningLogs', 'RiskyUsers', 'UserRiskEvents')
  $entraUri = "$arm/providers/microsoft.aadiam/diagnosticSettings/$DiagnosticSettingName`?api-version=2017-04-01-preview"
  $sent = $false
  foreach ($cats in @($entraCats, $entraCats[0..3])) {   # retry with the core categories if a tenant lacks the optional ones
    try {
      $body = @{ name = $DiagnosticSettingName; properties = @{ workspaceId = $wsId; logs = @($cats | ForEach-Object { @{ category = $_; enabled = $true } }) } }
      Invoke-Arm PUT $entraUri $body | Out-Null
      Write-Output "Entra ID logs routed: $($cats -join ', ')"; $sent = $true; break
    } catch { $lastErr = $_.Exception.Message }
  }
  if (-not $sent) { Write-Warning "Entra ID diagnostic setting failed (needs Global/Security Administrator): $lastErr" }

  Write-Output '--- Routing the Azure Activity log to the workspace (subscription diagnostic setting) ---'
  try {
    $actCats = @('Administrative', 'Security', 'ServiceHealth', 'Alert', 'Recommendation', 'Policy', 'Autoscale', 'ResourceHealth')
    $actUri = "$arm/subscriptions/$SubscriptionId/providers/Microsoft.Insights/diagnosticSettings/$DiagnosticSettingName`?api-version=2021-05-01-preview"
    $body = @{ properties = @{ workspaceId = $wsId; logs = @($actCats | ForEach-Object { @{ category = $_; enabled = $true } }) } }
    Invoke-Arm PUT $actUri $body | Out-Null
    Write-Output "Azure Activity log routed for subscription $SubscriptionId"
  } catch { Write-Warning "Azure Activity diagnostic setting failed: $($_.Exception.Message)" }
}

Write-Output 'SENTINEL-CONTENT-STATUS: Success'
