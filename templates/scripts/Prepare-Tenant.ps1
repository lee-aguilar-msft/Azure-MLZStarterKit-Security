<#
.SYNOPSIS
  Tenant-side preparation for the lab's hybrid Microsoft Entra join + Intune auto-enrollment flow.
  Run once per tenant from Cloud Shell (PowerShell) under an account that is Global Administrator (or
  Intune Administrator + Cloud Application Administrator + License Administrator). Idempotent.

.DESCRIPTION
  1. Intune MDM (mobility) settings: MDM user scope + the MDM terms-of-use / discovery / compliance URLs.
     In GCC High / DoD tenants the portal still pre-fills the commercial (.com) URLs even though it
     tells you to use the .us endpoints; Windows auto-enrollment fails until they are changed.
  2. Creates the "Microsoft Intune Enrollment" service principal if the tenant does not have it yet
     (needed before it can be excluded from Conditional Access).
  3. Optionally excludes that app from enabled Conditional Access policies that target all cloud apps
     (-ExcludeIntuneEnrollmentFromCa). Report-only by default.
  4. Optionally assigns an Entra ID P1/P2 + Intune license to the synced lab user (-LabUserUpn), once
     Entra Connect has synced it. Re-run after the first sync if the user is not there yet.
  5. -ConfigureMde: Intune side of Microsoft Defender for Endpoint onboarding - enables the Intune <->
     MDE connector for Windows, creates a dynamic device group of the lab clients and an Endpoint
     detection and response policy with onboarding package "Auto from connector" assigned to it.
     PREREQUISITE (no API, one click): Defender portal (security.microsoft.us in GCC High) -> Settings ->
     Endpoints -> Advanced features -> "Microsoft Intune connection" = On.

.EXAMPLE
  ./Prepare-Tenant.ps1 -Cloud USGov
  ./Prepare-Tenant.ps1 -Cloud USGov -MdmScopeGroupId <entra group id> -LabUserUpn lab.user@contoso.onmicrosoft.us
#>
param(
  [ValidateSet('USGov', 'USGovDoD', 'Global')] [string]$Cloud = 'USGov',
  [string]$MdmScopeGroupId = '',          # empty = MDM user scope "All"; otherwise "Some" with this group
  [string]$LabUserUpn = '',
  [string]$UsageLocation = 'US',
  [switch]$ExcludeIntuneEnrollmentFromCa,
  [switch]$SkipMdm,
  [switch]$ConfigureMde,
  [string]$ClientNamePrefix = 'lab-cl',   # dynamic device group rule: device.displayName -startsWith this
  [string]$DeviceGroupName = 'LAB-Intune-Devices'
)
$ErrorActionPreference = 'Stop'

$intuneEnrollmentAppId = 'd4ebce55-015a-49b5-a083-c84d1797ae8c'
$mdmPolicyId = '0000000a-0000-0000-c000-000000000000'   # "Microsoft Intune" mobility (MDM) application
$host_ = if ($Cloud -eq 'Global') { 'microsoft.com' } else { 'microsoft.us' }
$mdmUrls = @{
  termsOfUseUrl = "https://portal.manage.$host_/TermsofUse.aspx"
  discoveryUrl  = "https://enrollment.manage.$host_/enrollmentserver/discovery.svc"
  complianceUrl = "https://portal.manage.$host_/?portalAction=Compliance"
}

if (-not (Get-Module -ListAvailable Microsoft.Graph.Authentication)) {
  Install-Module Microsoft.Graph.Authentication -Scope CurrentUser -Force -AllowClobber
}
Import-Module Microsoft.Graph.Authentication
$scopes = @('Policy.ReadWrite.MobilityManagement', 'Application.ReadWrite.All', 'Policy.Read.All',
  'Policy.ReadWrite.ConditionalAccess', 'User.ReadWrite.All', 'Organization.Read.All', 'Group.ReadWrite.All',
  'DeviceManagementConfiguration.ReadWrite.All', 'DeviceManagementServiceConfig.ReadWrite.All')
Write-Output "Connecting to Microsoft Graph ($Cloud). Complete the device-code sign-in in your browser."
Connect-MgGraph -Environment $Cloud -Scopes $scopes -UseDeviceCode -NoWelcome
$ctx = Get-MgContext
Write-Output "Signed in as $($ctx.Account) to tenant $($ctx.TenantId)"

# ---------------- 1. Intune MDM user scope + URLs ----------------
if (-not $SkipMdm) {
  $uri = "beta/policies/mobileDeviceManagementPolicies/$mdmPolicyId"
  $cur = Invoke-MgGraphRequest -Method GET -Uri $uri
  Write-Output ("MDM before : scope={0} discovery={1}" -f $cur.appliesTo, $cur.discoveryUrl)
  # Graph rejects one PATCH that changes both the URLs and the policy properties (appliesTo):
  # "Simultaneous patch requests on both URL properties and Policy properties ... are currently not supported".
  # Send them separately, and only what actually differs.
  $scope = if ($MdmScopeGroupId) { 'selected' } else { 'all' }
  if ($cur.appliesTo -ne $scope) {
    Invoke-MgGraphRequest -Method PATCH -Uri $uri -Body (@{ appliesTo = $scope } | ConvertTo-Json) -ContentType 'application/json' | Out-Null
  }
  $urlPatch = @{}
  foreach ($k in $mdmUrls.Keys) { if ($cur[$k] -ne $mdmUrls[$k]) { $urlPatch[$k] = $mdmUrls[$k] } }
  if ($urlPatch.Count) {
    Invoke-MgGraphRequest -Method PATCH -Uri $uri -Body ($urlPatch | ConvertTo-Json) -ContentType 'application/json' | Out-Null
  }
  if ($MdmScopeGroupId) {
    $inc = (Invoke-MgGraphRequest -Method GET -Uri "$uri/includedGroups").value
    if (-not ($inc | Where-Object { $_.id -eq $MdmScopeGroupId })) {
      $ref = @{ '@odata.id' = "https://graph.$host_/beta/groups/$MdmScopeGroupId" } | ConvertTo-Json
      Invoke-MgGraphRequest -Method POST -Uri "$uri/includedGroups/`$ref" -Body $ref -ContentType 'application/json' | Out-Null
    }
  }
  $after = Invoke-MgGraphRequest -Method GET -Uri $uri
  Write-Output ("MDM after  : scope={0}" -f $after.appliesTo)
  Write-Output ("             termsOfUse={0}" -f $after.termsOfUseUrl)
  Write-Output ("             discovery ={0}" -f $after.discoveryUrl)
  Write-Output ("             compliance={0}" -f $after.complianceUrl)
}

# ---------------- 2. Intune Enrollment service principal ----------------
$sp = (Invoke-MgGraphRequest -Method GET -Uri "v1.0/servicePrincipals?`$filter=appId eq '$intuneEnrollmentAppId'").value | Select-Object -First 1
if (-not $sp) {
  $sp = Invoke-MgGraphRequest -Method POST -Uri 'v1.0/servicePrincipals' -Body (@{ appId = $intuneEnrollmentAppId } | ConvertTo-Json) -ContentType 'application/json'
  Write-Output "Created service principal for Microsoft Intune Enrollment ($($sp.id))"
} else { Write-Output "Microsoft Intune Enrollment service principal present ($($sp.id))" }

# ---------------- 3. Conditional Access (report, or exclude with the switch) ----------------
try {
  $policies = (Invoke-MgGraphRequest -Method GET -Uri 'v1.0/identity/conditionalAccess/policies').value | Where-Object { $_.state -eq 'enabled' }   # report-only policies never block enrollment
  $hits = $policies | Where-Object { $_.conditions.applications.includeApplications -contains 'All' -and $_.conditions.applications.excludeApplications -notcontains $intuneEnrollmentAppId }
  if (-not $hits) { Write-Output 'Conditional Access: no enabled all-apps policy is missing the Intune Enrollment exclusion.' }
  foreach ($p in $hits) {
    # Policies that only target guests / external users (e.g. Microsoft-managed "... for Microsoft partners and
    # vendors") never apply to the synced lab user, so they cannot block Intune enrollment.
    $u = $p.conditions.users
    $guestOnly = (@($u.includeUsers) -notcontains 'All') -and -not @($u.includeUsers | Where-Object { $_ -and $_ -ne 'GuestsOrExternalUsers' }) -and
      -not @($u.includeGroups) -and -not @($u.includeRoles) -and ($u.includeGuestsOrExternalUsers -or @($u.includeUsers) -contains 'GuestsOrExternalUsers')
    if ($guestOnly) {
      Write-Output "Conditional Access: '$($p.displayName)' targets guests/external users only - does not affect the lab user."
      continue
    }
    if ($ExcludeIntuneEnrollmentFromCa) {
      $ex = @($p.conditions.applications.excludeApplications) + $intuneEnrollmentAppId
      $patch = @{ conditions = @{ applications = @{ excludeApplications = $ex } } } | ConvertTo-Json -Depth 6
      Invoke-MgGraphRequest -Method PATCH -Uri "v1.0/identity/conditionalAccess/policies/$($p.id)" -Body $patch -ContentType 'application/json' | Out-Null
      Write-Output "Conditional Access: excluded Intune Enrollment from '$($p.displayName)'"
    } else {
      $scope = @(@($u.includeUsers) + @($u.includeGroups | ForEach-Object { "group:$_" }) + @($u.includeRoles | ForEach-Object { "role:$_" })) -join ', '
      Write-Warning "Conditional Access policy '$($p.displayName)' (users: $scope) targets all apps and does not exclude Microsoft Intune Enrollment ($intuneEnrollmentAppId). Re-run with -ExcludeIntuneEnrollmentFromCa or exclude it in the portal."
    }
  }
} catch { Write-Warning "Conditional Access check skipped: $($_.Exception.Message)" }

# ---------------- 4. License for the synced lab user ----------------
if ($LabUserUpn) {
  $user = (Invoke-MgGraphRequest -Method GET -Uri "v1.0/users?`$filter=userPrincipalName eq '$LabUserUpn'&`$select=id,userPrincipalName,usageLocation,onPremisesSyncEnabled").value | Select-Object -First 1
  if (-not $user) { Write-Warning "$LabUserUpn not found yet (has Entra Connect synced it?). Re-run after the first sync." }
  else {
    if (-not $user.usageLocation) {
      Invoke-MgGraphRequest -Method PATCH -Uri "v1.0/users/$($user.id)" -Body (@{ usageLocation = $UsageLocation } | ConvertTo-Json) -ContentType 'application/json' | Out-Null
    }
    $skus = (Invoke-MgGraphRequest -Method GET -Uri 'v1.0/subscribedSkus').value
    $want = $skus | Where-Object { ($_.servicePlans.servicePlanName -contains 'INTUNE_A') -and (($_.servicePlans.servicePlanName -contains 'AAD_PREMIUM') -or ($_.servicePlans.servicePlanName -contains 'AAD_PREMIUM_P2')) -and ($_.prepaidUnits.enabled -gt $_.consumedUnits) } | Select-Object -First 1
    if (-not $want) { $want = $skus | Where-Object { ($_.servicePlans.servicePlanName -contains 'INTUNE_A') -and ($_.prepaidUnits.enabled -gt $_.consumedUnits) } | Select-Object -First 1 }
    if (-not $want) { Write-Warning 'No SKU with an Intune (INTUNE_A) service plan and free seats found - assign a license manually.' }
    else {
      $has = (Invoke-MgGraphRequest -Method GET -Uri "v1.0/users/$($user.id)/licenseDetails").value | Where-Object { $_.skuId -eq $want.skuId }
      if (-not $has) {
        $lic = @{ addLicenses = @(@{ skuId = $want.skuId; disabledPlans = @() }); removeLicenses = @() } | ConvertTo-Json -Depth 4
        Invoke-MgGraphRequest -Method POST -Uri "v1.0/users/$($user.id)/assignLicense" -Body $lic -ContentType 'application/json' | Out-Null
      }
      Write-Output "License $($want.skuPartNumber) assigned to $LabUserUpn"
    }
  }
}

# ---------------- 5. Microsoft Defender for Endpoint via Intune (connector + EDR policy) ----------------
if ($ConfigureMde) {
  $mdeConnectorId = 'fc780465-2017-40d4-a0c5-307022471b92'   # Microsoft Defender for Endpoint MTD connector
  $cUri = "beta/deviceManagement/mobileThreatDefenseConnectors/$mdeConnectorId"
  $conn = $null
  try { $conn = Invoke-MgGraphRequest -Method GET -Uri $cUri } catch { }
  $cBody = @{ windowsEnabled = $true } | ConvertTo-Json
  if ($conn) { Invoke-MgGraphRequest -Method PATCH -Uri $cUri -Body $cBody -ContentType 'application/json' | Out-Null }
  else {
    $cBody = @{ id = $mdeConnectorId; windowsEnabled = $true } | ConvertTo-Json
    Invoke-MgGraphRequest -Method POST -Uri 'beta/deviceManagement/mobileThreatDefenseConnectors' -Body $cBody -ContentType 'application/json' | Out-Null
  }
  $conn = Invoke-MgGraphRequest -Method GET -Uri $cUri
  Write-Output ("MDE connector: windowsEnabled={0} partnerState={1}" -f $conn.windowsEnabled, $conn.partnerState)
  if ($conn.partnerState -notin @('enabled', 'available')) {
    Write-Warning 'MDE connector partner state is not enabled yet - turn on "Microsoft Intune connection" in the Defender portal (Settings > Endpoints > Advanced features); it can take up to 15 minutes to show as enabled.'
  }

  # Dynamic device group for the lab clients
  $grp = (Invoke-MgGraphRequest -Method GET -Uri "v1.0/groups?`$filter=displayName eq '$DeviceGroupName'").value | Select-Object -First 1
  if (-not $grp) {
    $gBody = @{
      displayName = $DeviceGroupName; description = 'Lab Windows clients (dynamic) - Intune EDR / compliance targeting'
      mailEnabled = $false; mailNickname = ($DeviceGroupName -replace '[^A-Za-z0-9]', ''); securityEnabled = $true
      groupTypes = @('DynamicMembership'); membershipRule = "(device.displayName -startsWith `"$ClientNamePrefix`")"; membershipRuleProcessingState = 'On'
    } | ConvertTo-Json
    $grp = Invoke-MgGraphRequest -Method POST -Uri 'v1.0/groups' -Body $gBody -ContentType 'application/json'
    Write-Output "Created dynamic device group $DeviceGroupName ($($grp.id))"
  } else { Write-Output "Device group $DeviceGroupName present ($($grp.id))" }

  # Endpoint detection and response policy - onboarding package "Auto from connector"
  $edrName = 'LAB - Defender for Endpoint onboarding (auto from connector)'
  $existing = (Invoke-MgGraphRequest -Method GET -Uri "beta/deviceManagement/configurationPolicies?`$filter=name eq '$edrName'").value | Select-Object -First 1
  if ($existing) { Write-Output "EDR policy present ($($existing.id))" }
  else {
    try {
      $tpl = (Invoke-MgGraphRequest -Method GET -Uri "beta/deviceManagement/configurationPolicyTemplates?`$filter=templateFamily eq 'endpointSecurityEndpointDetectionAndResponse'").value |
        Where-Object { $_.platforms -match 'windows' -and $_.lifecycleState -eq 'active' } | Select-Object -First 1
      $st = (Invoke-MgGraphRequest -Method GET -Uri "beta/deviceManagement/configurationPolicyTemplates('$($tpl.id)')/settingTemplates?`$expand=settingDefinitions").value
      $cfgType = $st | Where-Object { $_.settingInstanceTemplate.settingDefinitionId -eq 'device_vendor_msft_windowsadvancedthreatprotection_configurationtype' } | Select-Object -First 1
      $body = @{
        name = $edrName; description = 'Created by Prepare-Tenant.ps1 (MLZ Security Lab)'; platforms = 'windows10'; technologies = 'mdm,microsoftSense'
        templateReference = @{ templateId = $tpl.id }
        settings = @(@{
          '@odata.type' = '#microsoft.graph.deviceManagementConfigurationSetting'
          settingInstance = @{
            '@odata.type' = '#microsoft.graph.deviceManagementConfigurationChoiceSettingInstance'
            settingDefinitionId = 'device_vendor_msft_windowsadvancedthreatprotection_configurationtype'
            settingInstanceTemplateReference = @{ settingInstanceTemplateId = $cfgType.settingInstanceTemplate.settingInstanceTemplateId }
            choiceSettingValue = @{
              value = 'device_vendor_msft_windowsadvancedthreatprotection_configurationtype_autofromconnector'
              settingValueTemplateReference = @{ settingValueTemplateId = $cfgType.settingInstanceTemplate.choiceSettingValueTemplate.settingValueTemplateId }
              children = @(@{
                '@odata.type' = '#microsoft.graph.deviceManagementConfigurationSimpleSettingInstance'
                settingDefinitionId = 'device_vendor_msft_windowsadvancedthreatprotection_onboarding_fromconnector'
                simpleSettingValue = @{ '@odata.type' = '#microsoft.graph.deviceManagementConfigurationSecretSettingValue'; value = 'Microsoft ATP connector enabled'; valueState = 'notEncrypted' }
              })
            }
          }
        })
      } | ConvertTo-Json -Depth 20
      $edr = Invoke-MgGraphRequest -Method POST -Uri 'beta/deviceManagement/configurationPolicies' -Body $body -ContentType 'application/json'
      $assign = @{ assignments = @(@{ target = @{ '@odata.type' = '#microsoft.graph.groupAssignmentTarget'; groupId = $grp.id } }) } | ConvertTo-Json -Depth 6
      Invoke-MgGraphRequest -Method POST -Uri "beta/deviceManagement/configurationPolicies/$($edr.id)/assign" -Body $assign -ContentType 'application/json' | Out-Null
      Write-Output "Created EDR policy '$edrName' ($($edr.id)) assigned to $DeviceGroupName"
    } catch {
      Write-Warning "EDR policy not created automatically: $($_.Exception.Message)"
      Write-Warning "Create it in Intune: Endpoint security > Endpoint detection and response > Create policy > Windows > EDR > 'Microsoft Defender for Endpoint client configuration package type' = Auto from connector; assign to $DeviceGroupName."
    }
  }
}

Write-Output 'PREPARE-TENANT-STATUS: Success'
