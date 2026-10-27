#!/usr/bin/env python3
"""Generate templates/security-lab.json (resource-group scoped).

Onboards Microsoft Sentinel on the workspace, wires Azure Monitor data collection for Windows Security
Events (all) and Linux Syslog through AMA, associates every lab VM, and (optionally, default off)
runs Enable-SentinelContent.ps1 as a deploymentScript to install Content Hub solutions, enable all
matching built-in analytics rules, and turn on UEBA. The reliable automation path for the content
script is the 90-day GitHub Action / Cloud Shell; the in-template deploymentScript is opt-in because
it needs ACI reachability in a locked MLZ network.
"""
import json, os

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SCRIPTS = os.path.join(ROOT, "templates", "scripts")
with open(os.path.join(SCRIPTS, "Enable-SentinelContent.ps1"), encoding="utf-8") as f:
    content_script = f.read()

t = {
    "$schema": "https://schema.management.azure.com/schemas/2019-04-01/deploymentTemplate.json#",
    "contentVersion": "1.0.0.0",
    "metadata": {"description": "Microsoft Sentinel onboarding, AMA data collection rules + associations, and optional Content Hub / analytics-rule / UEBA enablement."},
    "parameters": {
        "location": {"type": "string"},
        "prefix": {"type": "string"},
        "workspaceName": {"type": "string"},
        "createWorkspace": {"type": "bool", "defaultValue": True},
        "retentionInDays": {"type": "int", "defaultValue": 90},
        "dailyQuotaGb": {"type": "int", "defaultValue": -1},
        "vmNames": {"type": "array", "defaultValue": [], "metadata": {"description": "Windows VM names to associate with the Security Events DCR. Empty = derive the six kit names from prefix."}},
        "linuxVmNames": {"type": "array", "defaultValue": [], "metadata": {"description": "Linux VM names to associate with the Syslog DCR. Empty = derive the three kit names from prefix when deployLinuxVms is true."}},
        "deployLinuxVms": {"type": "bool", "defaultValue": True},
        "usePrivateIngestion": {"type": "bool", "defaultValue": False, "metadata": {"description": "Create a Data Collection Endpoint for private-link ingestion and bind the DCRs to it."}},
        "deploySentinelContentScript": {"type": "bool", "defaultValue": False, "metadata": {"description": "Run the Content Hub / analytics-rule / UEBA enablement inline via a deploymentScript (needs ACI reachability). Default off — the GitHub Action / Cloud Shell path is preferred."}},
        "deployUeba": {"type": "bool", "defaultValue": True},
        "enableXdrConnector": {"type": "bool", "defaultValue": True},
        "subscriptionId": {"type": "string", "defaultValue": "[subscription().subscriptionId]"},
        "resourceGroupName": {"type": "string", "defaultValue": "[resourceGroup().name]"},
    },
    "variables": {
        "enableContentScript": content_script,
        "dceName": "[format('{0}-dce-sentinel', parameters('prefix'))]",
        "winDcrName": "[format('{0}-dcr-windows-security', parameters('prefix'))]",
        "linuxDcrName": "[format('{0}-dcr-linux-syslog', parameters('prefix'))]",
        "uamiName": "[format('{0}-uami-sentinel-content', parameters('prefix'))]",
        "workspaceResourceId": "[resourceId('Microsoft.OperationalInsights/workspaces', parameters('workspaceName'))]",
        "winNames": "[if(empty(parameters('vmNames')), createArray(format('{0}-dc01', parameters('prefix')), format('{0}-ms01', parameters('prefix')), format('{0}-ms02', parameters('prefix')), format('{0}-cl01', parameters('prefix')), format('{0}-cl02', parameters('prefix')), format('{0}-cl03', parameters('prefix'))), parameters('vmNames'))]",
        "lnxNames": "[if(empty(parameters('linuxVmNames')), if(parameters('deployLinuxVms'), createArray(format('{0}-rhel01', parameters('prefix')), format('{0}-ubu01', parameters('prefix')), format('{0}-sles01', parameters('prefix'))), createArray()), parameters('linuxVmNames'))]",
        # Microsoft Sentinel Contributor
        "sentinelContributorRoleId": "[subscriptionResourceId('Microsoft.Authorization/roleDefinitions', 'ab8e14d6-4a74-4a29-9ba8-549422addade')]",
    },
    "resources": [],
}
R = t["resources"]

# --- Workspace (optional) ---
R.append({
    "type": "Microsoft.OperationalInsights/workspaces", "apiVersion": "2023-09-01",
    "name": "[parameters('workspaceName')]", "location": "[parameters('location')]",
    "condition": "[parameters('createWorkspace')]",
    "properties": {
        "retentionInDays": "[parameters('retentionInDays')]",
        "sku": {"name": "PerGB2018"},
        "workspaceCapping": {"dailyQuotaGb": "[parameters('dailyQuotaGb')]"},
        "features": {"enableLogAccessUsingOnlyResourcePermissions": True},
    },
})

# --- Sentinel onboarding ---
R.append({
    "type": "Microsoft.SecurityInsights/onboardingStates", "apiVersion": "2024-03-01",
    "scope": "[format('Microsoft.OperationalInsights/workspaces/{0}', parameters('workspaceName'))]",
    "name": "default",
    "dependsOn": ["[variables('workspaceResourceId')]"],
    "properties": {"customerManagedKey": False},
})

# --- Sentinel solution (legacy OMS solution record; harmless, speeds portal) ---
R.append({
    "type": "Microsoft.OperationsManagement/solutions", "apiVersion": "2015-11-01-preview",
    "name": "[format('SecurityInsights({0})', parameters('workspaceName'))]", "location": "[parameters('location')]",
    "dependsOn": ["[variables('workspaceResourceId')]"],
    "plan": {"name": "[format('SecurityInsights({0})', parameters('workspaceName'))]", "product": "OMSGallery/SecurityInsights", "publisher": "Microsoft", "promotionCode": ""},
    "properties": {"workspaceResourceId": "[variables('workspaceResourceId')]"},
})

# --- Data collection endpoint (optional, for private ingestion) ---
R.append({
    "type": "Microsoft.Insights/dataCollectionEndpoints", "apiVersion": "2022-06-01",
    "name": "[variables('dceName')]", "location": "[parameters('location')]",
    "condition": "[parameters('usePrivateIngestion')]",
    "properties": {"networkAcls": {"publicNetworkAccess": "Disabled"}},
})

# --- DCR: Windows Security Events (ALL) ---
R.append({
    "type": "Microsoft.Insights/dataCollectionRules", "apiVersion": "2022-06-01",
    "name": "[variables('winDcrName')]", "location": "[parameters('location')]",
    # The DCE is conditional; ARM ignores dependsOn entries for resources that are not deployed.
    "dependsOn": [
        "[variables('workspaceResourceId')]",
        "[resourceId('Microsoft.Insights/dataCollectionEndpoints', variables('dceName'))]",
    ],
    "kind": "Windows",
    "properties": {
        "dataCollectionEndpointId": "[if(parameters('usePrivateIngestion'), resourceId('Microsoft.Insights/dataCollectionEndpoints', variables('dceName')), null())]",
        "dataSources": {
            "windowsEventLogs": [{
                "name": "securityEventsAll",
                "streams": ["Microsoft-SecurityEvent"],
                "xPathQueries": ["Security!*", "Microsoft-Windows-Sysmon/Operational!*", "Microsoft-Windows-PowerShell/Operational!*", "Windows PowerShell!*", "System!*", "Application!*"],
            }],
        },
        "destinations": {"logAnalytics": [{"name": "law", "workspaceResourceId": "[variables('workspaceResourceId')]"}]},
        "dataFlows": [{"streams": ["Microsoft-SecurityEvent"], "destinations": ["law"]}],
    },
})

# --- DCR: Linux Syslog (all facilities) ---
R.append({
    "type": "Microsoft.Insights/dataCollectionRules", "apiVersion": "2022-06-01",
    "name": "[variables('linuxDcrName')]", "location": "[parameters('location')]",
    "condition": "[not(empty(variables('lnxNames')))]",
    # The DCE is conditional; ARM ignores dependsOn entries for resources that are not deployed.
    "dependsOn": [
        "[variables('workspaceResourceId')]",
        "[resourceId('Microsoft.Insights/dataCollectionEndpoints', variables('dceName'))]",
    ],
    "kind": "Linux",
    "properties": {
        "dataCollectionEndpointId": "[if(parameters('usePrivateIngestion'), resourceId('Microsoft.Insights/dataCollectionEndpoints', variables('dceName')), null())]",
        "dataSources": {
            "syslog": [{
                "name": "syslogAll",
                "streams": ["Microsoft-Syslog"],
                "facilityNames": ["auth", "authpriv", "cron", "daemon", "kern", "syslog", "user", "local0", "local1", "local2", "local3", "local4", "local5", "local6", "local7"],
                "logLevels": ["Debug", "Info", "Notice", "Warning", "Error", "Critical", "Alert", "Emergency"],
            }],
        },
        "destinations": {"logAnalytics": [{"name": "law", "workspaceResourceId": "[variables('workspaceResourceId')]"}]},
        "dataFlows": [{"streams": ["Microsoft-Syslog"], "destinations": ["law"]}],
    },
})

# --- DCR associations (Windows) ---
R.append({
    "type": "Microsoft.Insights/dataCollectionRuleAssociations", "apiVersion": "2022-06-01",
    # extension resource: single-segment name + scope (a 3-segment name is rejected by ARM validation)
    "name": "[format('{0}-assoc', variables('winDcrName'))]",
    "scope": "[format('Microsoft.Compute/virtualMachines/{0}', variables('winNames')[copyIndex()])]",
    "copy": {"name": "winAssocLoop", "count": "[length(variables('winNames'))]"},
    "dependsOn": ["[resourceId('Microsoft.Insights/dataCollectionRules', variables('winDcrName'))]"],
    "properties": {"dataCollectionRuleId": "[resourceId('Microsoft.Insights/dataCollectionRules', variables('winDcrName'))]"},
})

# --- DCR associations (Linux) ---
R.append({
    "type": "Microsoft.Insights/dataCollectionRuleAssociations", "apiVersion": "2022-06-01",
    "name": "[format('{0}-assoc', variables('linuxDcrName'))]",
    "scope": "[format('Microsoft.Compute/virtualMachines/{0}', variables('lnxNames')[copyIndex()])]",
    "condition": "[not(empty(variables('lnxNames')))]",
    "copy": {"name": "lnxAssocLoop", "count": "[max(1, length(variables('lnxNames')))]"},
    "dependsOn": ["[resourceId('Microsoft.Insights/dataCollectionRules', variables('linuxDcrName'))]"],
    "properties": {"dataCollectionRuleId": "[resourceId('Microsoft.Insights/dataCollectionRules', variables('linuxDcrName'))]"},
})

# --- UAMI for the content deploymentScript (optional) ---
R.append({
    "type": "Microsoft.ManagedIdentity/userAssignedIdentities", "apiVersion": "2023-01-31",
    "name": "[variables('uamiName')]", "location": "[parameters('location')]",
    "condition": "[parameters('deploySentinelContentScript')]",
})
R.append({
    "type": "Microsoft.Authorization/roleAssignments", "apiVersion": "2022-04-01",
    "name": "[guid(variables('workspaceResourceId'), variables('uamiName'), variables('sentinelContributorRoleId'))]",
    "condition": "[parameters('deploySentinelContentScript')]",
    "scope": "[format('Microsoft.OperationalInsights/workspaces/{0}', parameters('workspaceName'))]",
    "dependsOn": [
        "[resourceId('Microsoft.ManagedIdentity/userAssignedIdentities', variables('uamiName'))]",
        "[variables('workspaceResourceId')]",
    ],
    "properties": {
        "roleDefinitionId": "[variables('sentinelContributorRoleId')]",
        "principalId": "[reference(resourceId('Microsoft.ManagedIdentity/userAssignedIdentities', variables('uamiName')), '2023-01-31').principalId]",
        "principalType": "ServicePrincipal",
    },
})
R.append({
    "type": "Microsoft.Resources/deploymentScripts", "apiVersion": "2023-08-01",
    "name": "[format('{0}-enable-sentinel-content', parameters('prefix'))]", "location": "[parameters('location')]",
    "kind": "AzurePowerShell",
    "condition": "[parameters('deploySentinelContentScript')]",
    "identity": {"type": "UserAssigned", "userAssignedIdentities": {"[resourceId('Microsoft.ManagedIdentity/userAssignedIdentities', variables('uamiName'))]": {}}},
    "dependsOn": [
        "[resourceId('Microsoft.Authorization/roleAssignments', guid(variables('workspaceResourceId'), variables('uamiName'), variables('sentinelContributorRoleId')))]",
        "[resourceId('Microsoft.SecurityInsights/onboardingStates', 'default')]",
    ],
    "properties": {
        "azPowerShellVersion": "11.0",
        "retentionInterval": "P1D",
        "cleanupPreference": "OnSuccess",
        "timeout": "PT1H",
        "arguments": "[format('-SubscriptionId {0} -ResourceGroupName {1} -WorkspaceName {2} {3} {4}', parameters('subscriptionId'), parameters('resourceGroupName'), parameters('workspaceName'), if(parameters('enableXdrConnector'), '-EnableXdrConnector', ''), if(parameters('deployUeba'), '', '-SkipUeba'))]",
        "scriptContent": "[variables('enableContentScript')]",
    },
})

t["outputs"] = {
    "workspaceResourceId": {"type": "string", "value": "[variables('workspaceResourceId')]"},
    "windowsDcrId": {"type": "string", "value": "[resourceId('Microsoft.Insights/dataCollectionRules', variables('winDcrName'))]"},
}

out = os.path.join(ROOT, "templates", "security-lab.json")
with open(out, "w", encoding="utf-8") as f:
    json.dump(t, f, indent=2)
print("wrote", out, os.path.getsize(out), "bytes")
