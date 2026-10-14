#!/usr/bin/env python3
"""Add a 'Lab Options' step to uiDefinition.json and wire the new solution parameters into the UI
outputs so the portal deploy buttons expose the forest/Linux/Arc/Sentinel toggles."""
import json, os, collections

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
UI = os.path.join(ROOT, "uiDefinition.json")
u = json.load(open(UI), object_pairs_hook=collections.OrderedDict)

def get_steps():
    return u["view"]["properties"]["steps"]

st = get_steps()
names = [s["name"] for s in st]

lab_step = {
    "name": "labOptions",
    "label": "Lab Options",
    "elements": [
        {"name": "cloudInfo", "type": "Microsoft.Common.InfoBox", "visible": True,
         "options": {"icon": "Info", "text": "Primary target is Azure Government (GCC High). Choose the cloud so firewall rules, MDE/Intune/Arc endpoints and device-registration URLs resolve to the right (.us vs .com) hosts."}},
        {"name": "cloudSuffix", "type": "Microsoft.Common.DropDown", "label": "Target cloud endpoints", "defaultValue": "Azure Government (GCC High / DoD)",
         "toolTip": "Selects the .us (Government) or .com (commercial) service endpoints used by the firewall rules and in-guest configuration.",
         "constraints": {"allowedValues": [
             {"label": "Azure Government (GCC High / DoD)", "value": "us"},
             {"label": "Azure Commercial", "value": "com"}]}},
        {"name": "upnSuffix", "type": "Microsoft.Common.TextBox", "label": "UPN suffix (verified Entra domain)", "defaultValue": "",
         "toolTip": "Added as an AD UPN suffix so synced users keep a routable UPN that matches a verified Entra domain. Leave blank to use the AD domain name.",
         "constraints": {"required": False}},
        {"name": "labUserName", "type": "Microsoft.Common.TextBox", "label": "Lab user sAMAccountName", "defaultValue": "lab.user",
         "toolTip": "A domain user created ENABLED with a password (so a soft-match to a live cloud identity does not sync 'disabled').",
         "constraints": {"required": False}},
        {"name": "deployLinuxVms", "type": "Microsoft.Common.CheckBox", "label": "Deploy 3 Linux servers (RHEL / Ubuntu / SLES) with Entra SSH login", "defaultValue": True},
        {"name": "deployFirewallRules", "type": "Microsoft.Common.CheckBox", "label": "Add lab firewall rules (Intune / MDE / Arc / Entra / Linux repos / PKI)", "defaultValue": True},
        {"name": "allowAllAzureServiceTags", "type": "Microsoft.Common.CheckBox", "label": "Also allow the workload subnet to the AzureCloud service tag (broad — lab convenience)", "defaultValue": True},
        {"name": "enableSentinelAnalytics", "type": "Microsoft.Common.CheckBox", "label": "Enable all matching built-in Sentinel analytics rules + UEBA (run post-deploy or inline)", "defaultValue": True},
        {"name": "deploySentinelContentScript", "type": "Microsoft.Common.CheckBox", "label": "Run the Sentinel content/analytics enablement inline (needs Container Instance provider + ACI reachability)", "defaultValue": False},
        {"name": "deployArcPrivateLink", "type": "Microsoft.Common.CheckBox", "label": "Deploy Azure Arc Private Link Scope + Arc private DNS zones", "defaultValue": False},
        {"name": "deployPrivateDnsResolver", "type": "Microsoft.Common.CheckBox", "label": "Deploy an Azure Private DNS Resolver inbound endpoint", "defaultValue": False},
        {"name": "mdeBlobHeader", "type": "Microsoft.Common.TextBlock", "visible": True,
         "options": {"text": "Optional: paste the raw contents of your Defender onboarding package (WindowsDefenderATPOnboardingScript JSON). Applied to the Windows clients and as a startup-script GPO. Leave blank to onboard servers via the Defender for Servers extension only."}},
        {"name": "mdeOnboardingBlob", "type": "Microsoft.Common.TextBox", "label": "MDE onboarding blob (optional)", "defaultValue": "", "multiLine": True,
         "constraints": {"required": False}},
    ],
}

# insert after securityCompliance (or append)
if "labOptions" not in names:
    idx = names.index("securityCompliance") + 1 if "securityCompliance" in names else len(st)
    st.insert(idx, lab_step)

# ---- wire outputs ----
outs = u["view"]["outputs"]["parameters"]
for stale in ("deployMde", "deployLinuxVm", "linuxFlavor"):
    outs.pop(stale, None)
outs["cloudSuffix"] = "[steps('labOptions').cloudSuffix]"
outs["upnSuffix"] = "[steps('labOptions').upnSuffix]"
outs["labUserName"] = "[steps('labOptions').labUserName]"
outs["labUserPassword"] = ""
outs["deployLinuxVms"] = "[steps('labOptions').deployLinuxVms]"
outs["linuxVmSize"] = "[steps('remoteAccess').linuxVmSize]"
outs["deployFirewallRules"] = "[steps('labOptions').deployFirewallRules]"
outs["allowAllAzureServiceTags"] = "[steps('labOptions').allowAllAzureServiceTags]"
outs["enableSentinelAnalytics"] = "[steps('labOptions').enableSentinelAnalytics]"
outs["deploySentinelContentScript"] = "[steps('labOptions').deploySentinelContentScript]"
outs["enableXdrConnector"] = True
outs["usePrivateIngestion"] = False
outs["deployArcPrivateLink"] = "[steps('labOptions').deployArcPrivateLink]"
outs["deployPrivateDnsResolver"] = "[steps('labOptions').deployPrivateDnsResolver]"
outs["resolverSubnetAddressPrefix"] = "10.60.0.128/28"
outs["mdeOnboardingBlob"] = "[steps('labOptions').mdeOnboardingBlob]"
outs["deployHydration"] = True
outs["hydrationIntervalMinutes"] = "60"
outs["intuneCredentialType"] = "1"
outs["autoShutdownTime"] = "0300"
outs["autoShutdownTimeZone"] = "UTC"
outs["dnsForwarders"] = "168.63.129.16"
outs["ouRoot"] = "LAB"

json.dump(u, open(UI, "w"), indent=2)
print("ui written:", os.path.getsize(UI), "bytes; steps:", [s["name"] for s in get_steps()])
