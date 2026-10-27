#!/usr/bin/env python3
"""Rewire solution.json: add firewall rule collection groups, Linux VMs, Arc private link, the
security-lab (Sentinel content + DCR) module, and all the new lab parameters. Idempotent — it edits
the committed solution.json in place from the structure already present."""
import json, os, collections

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SOL = os.path.join(ROOT, "solution.json")
s = json.load(open(SOL), object_pairs_hook=collections.OrderedDict)
P = s["parameters"]
V = s["variables"]

FW_SRC = "[parameters('virtualNetworkAddressPrefix')]"

def https(port=443):
    return [{"protocolType": "Https", "port": port}]

def app_both(port_https=True, port_http=False):
    pr = []
    if port_https: pr.append({"protocolType": "Https", "port": 443})
    if port_http: pr.append({"protocolType": "Http", "port": 80})
    return pr

# ---- cloud-variant FQDN lists (held as variables so the rules stay readable) ----
V["mdeFqdnsGov"] = ["*.endpoint.security.microsoft.us", "*.securitycenter.microsoft.us", "*.gcc.securitycenter.microsoft.us",
    "unitedstates1.ss.wd.microsoft.us", "unitedstates2.ss.wd.microsoft.us", "unitedstates4.ss.wd.microsoft.us",
    "*.blob.core.usgovcloudapi.net", "config.ecs.gov.teams.microsoft.us", "config.ecs.dod.teams.microsoft.us",
    "crl.microsoft.com", "ctldl.windowsupdate.com", "www.microsoft.com", "*.wns.windows.com", "login.microsoftonline.us", "login.live.com"]
V["mdeFqdnsCom"] = ["*.endpoint.security.microsoft.com", "*.securitycenter.windows.com", "*.securitycenter.microsoft.com",
    "*.wd.microsoft.com", "*.blob.core.windows.net", "events.data.microsoft.com", "*.events.data.microsoft.com",
    "crl.microsoft.com", "ctldl.windowsupdate.com", "www.microsoft.com", "*.wns.windows.com", "login.microsoftonline.com", "login.live.com"]
V["intuneFqdnsGov"] = ["*.manage.microsoft.us", "portal.manage.microsoft.us", "enrollment.manage.microsoft.us", "intune.microsoft.us",
    "portal.azure.us", "graph.microsoft.us", "*.dm.microsoft.us", "enterpriseregistration.microsoftonline.us", "*.events.data.microsoft.com"]
V["intuneFqdnsCom"] = ["*.manage.microsoft.com", "*.dm.microsoft.com", "enterpriseregistration.windows.net", "intune.microsoft.com", "*.events.data.microsoft.com"]
V["arcFqdnsGov"] = ["login.microsoftonline.us", "management.usgovcloudapi.net", "pasff.usgovcloudapi.net", "*.his.arc.azure.us",
    "*.guestconfiguration.azure.us", "guestnotificationservice.azure.us", "*.guestnotificationservice.azure.us",
    "*.servicebus.usgovcloudapi.net", "*.blob.core.usgovcloudapi.net", "packages.microsoft.com", "download.microsoft.com", "www.microsoft.com"]
V["arcFqdnsCom"] = ["login.microsoftonline.com", "*.login.microsoft.com", "pas.windows.net", "management.azure.com", "*.his.arc.azure.com",
    "*.guestconfiguration.azure.com", "guestnotificationservice.azure.com", "*.guestnotificationservice.azure.com",
    "*.servicebus.windows.net", "packages.microsoft.com", "download.microsoft.com", "www.microsoft.com"]
V["entraFqdnsGov"] = ["login.microsoftonline.us", "device.login.microsoftonline.us", "enterpriseregistration.microsoftonline.us",
    "autologon.microsoftazuread-sso.com", "*.wns.windows.com", "login.live.com"]
V["entraFqdnsCom"] = ["login.microsoftonline.com", "device.login.microsoftonline.com", "enterpriseregistration.windows.net",
    "autologon.microsoftazuread-sso.com", "login.live.com"]
# Administration from inside the lab: the Azure portal (to download Entra Connect Sync from the Entra admin
# center) and the Entra Connect Sync service endpoints. Portal list = learn.microsoft.com "Allow the Azure
# portal URLs on your firewall or proxy server" (U.S. Government Cloud tab); Entra Connect list = "Hybrid identity
# considerations for Azure Government cloud" + "Hybrid Identity required ports and protocols".
V["adminFqdnsGov"] = ["*.applicationinsights.us", "*.azure.us", "azure.us", "*.azureedge.net", "*.azureedge.us",
    "*.loganalytics.us", "*.microsoft.us", "*.microsoftonline.us", "*.msauth.net", "*.msidentity.us", "*.s-microsoft.com",
    "*.usgovcloudapi.net", "*.usgovtrafficmanager.net", "*.windowsazure.us", "graph.microsoftazure.us",
    "main.ff.marketplacedataprovider.azure.us",
    "*.msappproxy.us", "login.windows.us", "secure.aadcdn.microsoftonline-p.com", "*.microsoftonline-p.us",
    "*.msauthimages.net", "*.msecnd.net", "*.msftauth.net", "*.msftauthimages.net", "*.phonefactor.net",
    "enterpriseregistration.windows.net", "policykeyservice.dc.ad.msft.net", "ocsp.msocsp.us", "ctldl.windowsupdate.us",
    "download.microsoft.com", "*.download.microsoft.com", "go.microsoft.com", "aka.ms"]
V["adminFqdnsCom"] = ["login.microsoft.com", "login.microsoftonline.com", "login.live.com", "*.aadcdn.msftauth.net",
    "*.aadcdn.msftauthimages.net", "*.aadcdn.msauthimages.net", "*.logincdn.msftauth.net", "*.msauth.net",
    "*.aadcdn.microsoftonline-p.com", "*.microsoftonline-p.com", "*.portal.azure.com", "portal.azure.com",
    "*.hosting.portal.azure.net", "*.hosting-ms.portal.azure.net", "*.reactblade.portal.azure.net", "management.azure.com",
    "*.ext.azure.com", "*.graph.windows.net", "*.graph.microsoft.com", "hosting.partners.azure.net",
    "*.microsoftonline.com", "*.msappproxy.net", "*.servicebus.windows.net", "*.msftauth.net", "*.msecnd.net",
    "download.microsoft.com", "*.download.microsoft.com", "go.microsoft.com", "aka.ms", "catalogartifact.azureedge.net"]
V["linuxRepoFqdns"] = ["packages.microsoft.com",
    # Azure RHUI (RHEL PAYG images pull everything from here; blocked = AADSSHLoginForLinux install fails)
    "rhui-1.microsoft.com", "rhui-2.microsoft.com", "rhui-3.microsoft.com", "rhui-4.microsoft.com",
    "rhui4-1.microsoft.com", "rhui4-2.microsoft.com", "rhui4-3.microsoft.com",
    "security.ubuntu.com", "archive.ubuntu.com", "*.archive.ubuntu.com",
    "azure.archive.ubuntu.com", "changelogs.ubuntu.com",
    # Ubuntu apt hooks (ESM/apt-news/motd) also call these; a silently dropped call stalls apt-get update
    "*.ubuntu.com", "esm.ubuntu.com", "motd.ubuntu.com", "contracts.canonical.com", "*.snapcraft.io", "cdn.redhat.com", "*.cdn.redhat.com", "subscription.rhsm.redhat.com",
    "*.akamaiedge.net", "*.akamaitechnologies.com", "scc.suse.com", "*.susecloud.net", "updates.suse.com"]
V["pkiFqdns"] = ["crl.microsoft.com", "*.crl.microsoft.com", "www.microsoft.com", "ctldl.windowsupdate.com",
    "oneocsp.microsoft.com", "ocsp.digicert.com", "*.digicert.com", "cacerts.digicert.com"]

def net_rule(name, tags=None, fqdns=None, protocols=("TCP",), ports=("443",)):
    r = {"name": name, "ruleType": "NetworkRule", "ipProtocols": list(protocols),
         "sourceAddresses": [FW_SRC], "sourceIpGroups": [], "destinationPorts": list(ports),
         "destinationIpGroups": []}
    r["destinationAddresses"] = tags or []
    r["destinationFqdns"] = fqdns or []
    return r

def app_rule(name, fqdn_tags=None, target_fqdns=None, protocols=None):
    return {"name": name, "ruleType": "ApplicationRule",
            "protocols": protocols or app_both(True, False),
            "fqdnTags": fqdn_tags or [], "webCategories": [],
            "targetFqdns": target_fqdns if target_fqdns is not None else [],
            "targetUrls": [], "terminateTLS": False, "sourceAddresses": [FW_SRC], "sourceIpGroups": []}

network_rules = [
    net_rule("Allow-Azure-ServiceTags-TCP",
             tags=["AzureActiveDirectory", "AzureResourceManager", "AzureKeyVault", "Storage", "AzureMonitor",
                   "AzureFrontDoor.Frontend", "AzureFrontDoor.MicrosoftSecurity", "MicrosoftContainerRegistry",
                   "GuestAndHybridManagement", "AzureArcInfrastructure", "EventHub"]),
    net_rule("Allow-KMS-Activation", fqdns=["[format('azkms.{0}', environment().suffixes.storage)]",
                                            "[format('kms.{0}', environment().suffixes.storage)]"], ports=["1688"]),
    net_rule("Allow-NTP", fqdns=["time.windows.com"], protocols=["UDP"], ports=["123"]),
]
# optional AzureCloud catch-all ("all Azure tags") — one broad allow to every Azure service
azurecloud_collection = {
    "name": "LAB-AzureCloud-CatchAll", "priority": 405, "ruleCollectionType": "FirewallPolicyFilterRuleCollection",
    "action": {"type": "Allow"},
    "rules": [net_rule("Allow-AzureCloud-All", tags=["AzureCloud"], protocols=["TCP"], ports=["443", "1688", "5671", "5672"])],
}

application_rules = [
    app_rule("Allow-FQDNTags", fqdn_tags=["WindowsUpdate", "MicrosoftIntune", "Windows365", "WindowsDiagnostics",
                                          "MicrosoftActiveProtectionService", "AzureBackup"]),
    app_rule("Allow-MDE", target_fqdns="[if(equals(environment().name, 'AzureUSGovernment'), variables('mdeFqdnsGov'), variables('mdeFqdnsCom'))]"),
    app_rule("Allow-Intune", target_fqdns="[if(equals(environment().name, 'AzureUSGovernment'), variables('intuneFqdnsGov'), variables('intuneFqdnsCom'))]"),
    app_rule("Allow-Arc", target_fqdns="[if(equals(environment().name, 'AzureUSGovernment'), variables('arcFqdnsGov'), variables('arcFqdnsCom'))]"),
    app_rule("Allow-Entra-DeviceReg", target_fqdns="[if(equals(environment().name, 'AzureUSGovernment'), variables('entraFqdnsGov'), variables('entraFqdnsCom'))]"),
    app_rule("Allow-Linux-Repos", target_fqdns="[variables('linuxRepoFqdns')]", protocols=app_both(True, True)),
    app_rule("Allow-PKI-CRL-OCSP", target_fqdns="[variables('pkiFqdns')]", protocols=app_both(True, True)),
    app_rule("Allow-Admin-Portal-EntraConnect", target_fqdns="[if(equals(environment().name, 'AzureUSGovernment'), variables('adminFqdnsGov'), variables('adminFqdnsCom'))]", protocols=app_both(True, True)),
]

lab_group = {
    "name": "LAB-SecurityCollectionGroup",
    "properties": {
        "priority": 400,
        "ruleCollections": [
            {"name": "LAB-NetworkRules", "priority": 410, "ruleCollectionType": "FirewallPolicyFilterRuleCollection",
             "action": {"type": "Allow"}, "rules": network_rules},
            {"name": "LAB-ApplicationRules", "priority": 420, "ruleCollectionType": "FirewallPolicyFilterRuleCollection",
             "action": {"type": "Allow"}, "rules": application_rules},
        ],
    },
}
# The catch-all collection is appended into the same group's ruleCollections only when enabled.
V["labRuleCollectionsBase"] = lab_group["properties"]["ruleCollections"]
V["labRuleCollectionsWithCatchAll"] = [azurecloud_collection] + lab_group["properties"]["ruleCollections"]
V["labFirewallRuleCollectionGroups"] = [{
    "name": "LAB-SecurityCollectionGroup",
    "properties": {
        "priority": 400,
        "ruleCollections": "[if(parameters('allowAllAzureServiceTags'), variables('labRuleCollectionsWithCatchAll'), variables('labRuleCollectionsBase'))]",
    },
}]

# ---- new parameters ----
def add_param(name, spec):
    if name not in P: P[name] = spec

add_param("deployFirewallRules", {"type": "bool", "defaultValue": True, "metadata": {"description": "Add the lab firewall rule collection group (Intune/MDE/Arc/Entra/Linux/PKI + Azure service tags) to the MLZ hub firewall policy."}})
add_param("allowAllAzureServiceTags", {"type": "bool", "defaultValue": True, "metadata": {"description": "Also allow the workload subnet outbound to the AzureCloud service tag (all Azure services). Broad; appropriate for a lab."}})
add_param("cloudSuffix", {"type": "string", "defaultValue": "us", "allowedValues": ["us", "com"], "metadata": {"description": "'us' = Azure Government / GCC High; 'com' = commercial."}})
add_param("dnsForwarders", {"type": "string", "defaultValue": "168.63.129.16", "metadata": {"description": "Upstream DNS the DC forwards to (hub firewall private IP when DNS proxy is on, else 168.63.129.16)."}})
add_param("ouRoot", {"type": "string", "defaultValue": "LAB"})
add_param("upnSuffix", {"type": "string", "defaultValue": ""})
add_param("labUserName", {"type": "string", "defaultValue": "lab.user"})
add_param("labUserPassword", {"type": "secureString", "defaultValue": ""})
add_param("intuneCredentialType", {"type": "string", "defaultValue": "1", "allowedValues": ["1", "2"]})
add_param("mdeOnboardingBlob", {"type": "secureString", "defaultValue": ""})
add_param("deployHydration", {"type": "bool", "defaultValue": True})
add_param("hydrationIntervalMinutes", {"type": "string", "defaultValue": "60"})
add_param("autoShutdownTime", {"type": "string", "defaultValue": "0300"})
add_param("autoShutdownTimeZone", {"type": "string", "defaultValue": "UTC"})
add_param("deployLinuxVms", {"type": "bool", "defaultValue": True})
add_param("linuxVmSize", {"type": "string", "defaultValue": "Standard_D2ads_v6"})
add_param("deployArcPrivateLink", {"type": "bool", "defaultValue": False, "metadata": {"description": "Deploy the Azure Arc Private Link Scope + Arc private DNS zones (preview API)."}})
add_param("deployPrivateDnsResolver", {"type": "bool", "defaultValue": False})
add_param("resolverSubnetAddressPrefix", {"type": "string", "defaultValue": "10.60.0.128/28"})
add_param("usePrivateIngestion", {"type": "bool", "defaultValue": False})
add_param("deploySentinelContentScript", {"type": "bool", "defaultValue": False})
add_param("enableSentinelAnalytics", {"type": "bool", "defaultValue": True, "metadata": {"description": "Install Content Hub solutions and enable all matching built-in analytics rules + UEBA (via the in-template deploymentScript when deploySentinelContentScript is true, otherwise run by the GitHub Action / Cloud Shell)."}})
add_param("enableXdrConnector", {"type": "bool", "defaultValue": True})

# tighten subnet defaults so there is room for the resolver subnet (vnet /24, lab /25)
if P.get("subnetAddressPrefix", {}).get("defaultValue") == "10.60.0.0/24":
    P["subnetAddressPrefix"]["defaultValue"] = "10.60.0.0/25"

# make the Linux/MDE params already present line up (serverVmSize etc already exist)
# ---- new deployment name variables ----
V["securityLabDeploymentName"] = "[format('deploy-security-lab-{0}', parameters('deploymentNameSuffix'))]"
V["arcDeploymentName"] = "[format('deploy-arc-pls-{0}', parameters('deploymentNameSuffix'))]"
V["labWorkspaceName"] = "[if(not(empty(parameters('customWorkspaceName'))), parameters('customWorkspaceName'), format('{0}-law-lab', parameters('prefix')))]"

json.dump(s, open(SOL, "w"), indent=2)
print("stage 1 (params+vars) written:", os.path.getsize(SOL), "bytes;", len(P), "params", len(V), "vars")
