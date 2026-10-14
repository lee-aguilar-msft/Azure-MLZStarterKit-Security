#!/usr/bin/env python3
"""Stage 2: wire solution.json resources — firewall passthrough to tier3, Linux/lab params to the VM
module, replace the inline Sentinel deployment with the security-lab module, add the Arc PLS module."""
import json, os, collections

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SOL = os.path.join(ROOT, "solution.json")
s = json.load(open(SOL), object_pairs_hook=collections.OrderedDict)
res = s["resources"]

def find(pred):
    for r in res:
        if pred(r): return r
    return None

def val(x): return {"value": x}

tier3 = find(lambda r: r["type"].endswith("deployments") and r["name"] == "[variables('tier3DeploymentName')]")
labvm = find(lambda r: r["type"].endswith("deployments") and r["name"] == "[variables('labVmDeploymentName')]")
sentinel = find(lambda r: r["type"].endswith("deployments") and r["name"] == "[variables('sentinelDeploymentName')]")

# ---- tier3: firewall rules + resolver subnet ----
tp = tier3["properties"]["parameters"]
tp["customFirewallRuleCollectionGroups"] = val("[if(parameters('deployFirewallRules'), variables('labFirewallRuleCollectionGroups'), createArray())]")
tp["additionalSubnets"] = val("[if(parameters('deployPrivateDnsResolver'), createArray(createObject('name', 'snet-dnspr', 'properties', createObject('addressPrefix', parameters('resolverSubnetAddressPrefix'), 'delegations', createArray(createObject('name', 'dnspr', 'properties', createObject('serviceName', 'Microsoft.Network/dnsResolvers')))))), createArray())]")

# ---- labVm: drop old linux params, add the new lab/linux params ----
lp = labvm["properties"]["parameters"]
for dead in ("deployLinuxVm", "linuxFlavor"):
    lp.pop(dead, None)
lp["dnsForwarders"] = val("[parameters('dnsForwarders')]")
lp["ouRoot"] = val("[parameters('ouRoot')]")
lp["upnSuffix"] = val("[parameters('upnSuffix')]")
lp["labUserName"] = val("[parameters('labUserName')]")
lp["labUserPassword"] = val("[parameters('labUserPassword')]")
lp["cloudSuffix"] = val("[parameters('cloudSuffix')]")
lp["intuneCredentialType"] = val("[parameters('intuneCredentialType')]")
lp["mdeOnboardingBlob"] = val("[parameters('mdeOnboardingBlob')]")
lp["deployHydration"] = val("[parameters('deployHydration')]")
lp["hydrationIntervalMinutes"] = val("[parameters('hydrationIntervalMinutes')]")
lp["autoShutdownTime"] = val("[parameters('autoShutdownTime')]")
lp["autoShutdownTimeZone"] = val("[parameters('autoShutdownTimeZone')]")
lp["deployLinuxVms"] = val("[parameters('deployLinuxVms')]")
lp["linuxVmSize"] = val("[parameters('linuxVmSize')]")
lp["deployMde"] = val("[parameters('deployDefenderForServers')]")

# ---- replace the Sentinel inline deployment with the security-lab module ----
tier3rg = "[format('/subscriptions/{0}/resourceGroups/{1}', subscription().subscriptionId, variables('tier3ResourceGroupName'))]"
labvm_ref = "reference(resourceId(variables('tier3ResourceGroupName'), 'Microsoft.Resources/deployments', variables('labVmDeploymentName')), '2025-04-01')"
security_lab = collections.OrderedDict([
    ("condition", "[parameters('deploySentinel')]"),
    ("type", "Microsoft.Resources/deployments"),
    ("apiVersion", "2025-04-01"),
    ("name", "[variables('securityLabDeploymentName')]"),
    ("resourceGroup", "[variables('tier3ResourceGroupName')]"),
    ("dependsOn", [
        "[resourceId('Microsoft.Resources/deployments', variables('tier3DeploymentName'))]",
        "[resourceId('Microsoft.Resources/deployments', variables('labVmDeploymentName'))]",
    ]),
    ("properties", collections.OrderedDict([
        ("expressionEvaluationOptions", {"scope": "inner"}),
        ("mode", "Incremental"),
        ("templateLink", {"uri": "[uri(deployment().properties.templateLink.uri, 'templates/security-lab.json')]", "contentVersion": "1.0.0.0"}),
        ("parameters", collections.OrderedDict([
            ("location", val("[parameters('location')]")),
            ("prefix", val("[parameters('prefix')]")),
            ("workspaceName", val("[variables('labWorkspaceName')]")),
            ("createWorkspace", val("[empty(parameters('existingWorkspaceResourceId'))]")),
            ("retentionInDays", val(90)),
            ("vmNames", val("[" + labvm_ref + ".outputs.windowsVmNames.value]")),
            ("linuxVmNames", val("[" + labvm_ref + ".outputs.linuxVmNames.value]")),
            ("usePrivateIngestion", val("[parameters('usePrivateIngestion')]")),
            ("deploySentinelContentScript", val("[and(parameters('deploySentinelContentScript'), parameters('enableSentinelAnalytics'))]")),
            ("deployUeba", val("[parameters('enableSentinelAnalytics')]")),
            ("enableXdrConnector", val("[parameters('enableXdrConnector')]")),
            ("subscriptionId", val("[subscription().subscriptionId]")),
            ("resourceGroupName", val("[variables('tier3ResourceGroupName')]")),
        ])),
    ])),
])
res[res.index(sentinel)] = security_lab

# ---- add the Arc private link module (after security lab) ----
arc = collections.OrderedDict([
    ("condition", "[parameters('deployArcPrivateLink')]"),
    ("type", "Microsoft.Resources/deployments"),
    ("apiVersion", "2025-04-01"),
    ("name", "[variables('arcDeploymentName')]"),
    ("resourceGroup", "[variables('tier3ResourceGroupName')]"),
    ("dependsOn", ["[resourceId('Microsoft.Resources/deployments', variables('tier3DeploymentName'))]"]),
    ("properties", collections.OrderedDict([
        ("expressionEvaluationOptions", {"scope": "inner"}),
        ("mode", "Incremental"),
        ("templateLink", {"uri": "[uri(deployment().properties.templateLink.uri, 'templates/arc-private-link.json')]", "contentVersion": "1.0.0.0"}),
        ("parameters", collections.OrderedDict([
            ("location", val("[parameters('location')]")),
            ("prefix", val("[parameters('prefix')]")),
            ("privateEndpointSubnetResourceId", val("[reference(resourceId('Microsoft.Resources/deployments', variables('tier3DeploymentName')), '2025-04-01').outputs.tier.value.subnetResourceId]")),
            ("workloadVirtualNetworkResourceId", val("[split(reference(resourceId('Microsoft.Resources/deployments', variables('tier3DeploymentName')), '2025-04-01').outputs.tier.value.subnetResourceId, '/subnets/')[0]]")),
            ("hubVirtualNetworkResourceId", val("[reference(resourceId('Microsoft.Resources/deployments', variables('coreDeploymentName')), '2025-04-01').outputs.hubVirtualNetworkResourceId.value]")),
            ("deployPrivateDnsResolver", val("[parameters('deployPrivateDnsResolver')]")),
            ("resolverSubnetResourceId", val("[if(parameters('deployPrivateDnsResolver'), format('{0}/subnets/snet-dnspr', split(reference(resourceId('Microsoft.Resources/deployments', variables('tier3DeploymentName')), '2025-04-01').outputs.tier.value.subnetResourceId, '/subnets/')[0]), '')]")),
        ])),
    ])),
])
res.insert(res.index(security_lab) + 1, arc)

json.dump(s, open(SOL, "w"), indent=2)
print("stage 2 written:", os.path.getsize(SOL), "bytes;", len(res), "resources")
