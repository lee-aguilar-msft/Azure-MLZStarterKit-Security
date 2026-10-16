#!/usr/bin/env python3
"""Build templates/firewall-lab-rules.json: the lab firewall rule collection group on its own, so an existing
lab can pick up firewall rule changes without redeploying the whole solution. Deploy it to the hub resource
group (where the MLZ firewall policy lives). The rules and FQDN lists are copied from solution.json, so run
build/gen_solution.py first."""
import json, os, re, collections

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sol = json.load(open(os.path.join(ROOT, "solution.json")), object_pairs_hook=collections.OrderedDict)
SV = sol["variables"]

# every variable the rule collection group needs, followed transitively through variables('...') references
need, todo = [], ["labRuleCollectionsBase", "labRuleCollectionsWithCatchAll"]
while todo:
    n = todo.pop()
    if n in need:
        continue
    need.append(n)
    todo += re.findall(r"variables\('([^']+)'\)", json.dumps(SV[n]))

params_used = set()
for n in need:
    params_used |= set(re.findall(r"parameters\('([^']+)'\)", json.dumps(SV[n])))
assert params_used <= {"virtualNetworkAddressPrefix"}, params_used

t = collections.OrderedDict()
t["$schema"] = "https://schema.management.azure.com/schemas/2019-04-01/deploymentTemplate.json#"
t["contentVersion"] = "1.0.0.0"
t["metadata"] = {"description": "MLZ Security Lab: (re)apply the LAB-SecurityCollectionGroup firewall rules to the hub firewall policy. Deploy to the hub resource group."}
t["parameters"] = collections.OrderedDict([
    ("firewallPolicyName", {"type": "string", "metadata": {"description": "Name of the MLZ hub firewall policy (Microsoft.Network/firewallPolicies) in this resource group."}}),
    ("virtualNetworkAddressPrefix", {"type": "string", "defaultValue": sol["parameters"]["virtualNetworkAddressPrefix"]["defaultValue"],
                                     "metadata": {"description": "Address prefix of the lab (Tier 3) virtual network - the source of the lab rules."}}),
    ("allowAllAzureServiceTags", {"type": "bool", "defaultValue": True,
                                  "metadata": {"description": "Include the AzureCloud catch-all network rule collection."}}),
])
t["variables"] = collections.OrderedDict((n, SV[n]) for n in sorted(need))
t["resources"] = [{
    "type": "Microsoft.Network/firewallPolicies/ruleCollectionGroups",
    "apiVersion": "2024-03-01",
    "name": "[format('{0}/LAB-SecurityCollectionGroup', parameters('firewallPolicyName'))]",
    "properties": {
        "priority": 400,
        "ruleCollections": "[if(parameters('allowAllAzureServiceTags'), variables('labRuleCollectionsWithCatchAll'), variables('labRuleCollectionsBase'))]",
    },
}]
out = os.path.join(ROOT, "templates", "firewall-lab-rules.json")
json.dump(t, open(out, "w"), indent=2)
print("written", out, os.path.getsize(out), "bytes; variables:", ", ".join(sorted(need)))
