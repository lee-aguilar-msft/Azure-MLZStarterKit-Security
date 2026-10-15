#!/usr/bin/env python3
"""Generate templates/ad-entra-vms.json.

Produces a resource-group-scoped ARM template that deploys the AD forest + Entra lab:
  - 1 domain controller (forest promotion via run-command, NTDS on C:)
  - 2 member servers (ms01 doubles as the Entra Connect staging server)
  - 3 Windows 11 clients
  - 3 Linux servers (RHEL / Ubuntu / SLES) with Entra SSH login
  - Entra login extension on every VM + VM Login RBAC
  - Azure Monitor Agent on every VM (DCR associations are created by the security-lab module)
  - DevTest auto-shutdown at 03:00 local (23:00 ET) on every VM
  - MDE: auto-provisioned by Defender for Servers (no template-declared MDE extensions)
Scripts are embedded inline from templates/scripts so the lab works behind the MLZ firewall.
"""
import json, os, base64

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SCRIPTS = os.path.join(ROOT, "templates", "scripts")


def rd(name):
    with open(os.path.join(SCRIPTS, name), "r", encoding="utf-8") as f:
        return f.read()


def b64(name):
    return base64.b64encode(rd(name).encode("utf-8")).decode("ascii")


promote_ps1 = rd("Promote-DomainController.ps1")
baseline_ps1 = rd("Configure-ForestBaseline.ps1")
join_ps1 = rd("Join-Domain.ps1")
verify_ps1 = rd("Verify-Forest.ps1")
configure_ps1 = rd("Configure-WindowsMember.ps1")
configure_linux_sh = rd("configure-linux.sh")
prep_linux_sh = rd("prep-linux.sh")
hydrate_win_b64 = b64("Invoke-LabHydration.ps1")
hydrate_linux_b64 = b64("hydrate-linux.sh")

tmpl = {
    "$schema": "https://schema.management.azure.com/schemas/2019-04-01/deploymentTemplate.json#",
    "contentVersion": "1.0.0.0",
    "metadata": {"description": "AD forest + Entra lab: DCs, member servers, Windows clients, Linux servers, Entra login, AMA, auto-shutdown (MDE via Defender for Servers auto-provisioning)."},
    "parameters": {
        "location": {"type": "string"},
        "prefix": {"type": "string", "metadata": {"description": "Resource name prefix, e.g. 'sdl' or 'rrs'."}},
        "subnetResourceId": {"type": "string"},
        "domainControllerPrivateIp": {"type": "string", "defaultValue": "10.60.0.10"},
        "dnsForwarders": {"type": "string", "defaultValue": "168.63.129.16", "metadata": {"description": "Upstream DNS the DC forwards to (hub firewall DNS proxy private IP, or 168.63.129.16)."}},
        "additionalDnsServers": {"type": "array", "defaultValue": []},
        "adminUsername": {"type": "string"},
        "adminPassword": {"type": "secureString"},
        "domainName": {"type": "string"},
        "domainNetbiosName": {"type": "string"},
        "safeModeAdminPassword": {"type": "secureString"},
        "ouRoot": {"type": "string", "defaultValue": "LAB", "metadata": {"description": "Top-level OU name for all lab objects."}},
        "upnSuffix": {"type": "string", "defaultValue": "", "metadata": {"description": "Verified Entra domain to add as a UPN suffix so synced users keep a routable UPN. Empty = use domainName."}},
        "labUserName": {"type": "string", "defaultValue": "lab.user"},
        "labUserPassword": {"type": "secureString", "defaultValue": ""},
        "cloudSuffix": {"type": "string", "defaultValue": "us", "allowedValues": ["us", "com"], "metadata": {"description": "'us' = Azure Government / GCC High endpoints; 'com' = commercial."}},
        "intuneCredentialType": {"type": "string", "defaultValue": "1", "allowedValues": ["1", "2"], "metadata": {"description": "1 = user credential auto-enroll, 2 = device credential."}},
        "mdeOnboardingBlob": {"type": "secureString", "defaultValue": "", "metadata": {"description": "Raw MDE onboarding JSON (from the GCC High / commercial onboarding package). Applied to clients via run-command and to all machines via a startup-script GPO. Empty = rely on Defender for Servers auto-provisioning of MDE instead."}},
        "entraLoginPrincipalId": {"type": "string", "defaultValue": "", "metadata": {"description": "Object ID of the Entra user/group granted VM login."}},
        "entraPrincipalType": {"type": "string", "defaultValue": "Group", "allowedValues": ["Group", "User", "ServicePrincipal"]},
        "assignVmAdminRole": {"type": "bool", "defaultValue": True},
        "assignVmUserRole": {"type": "bool", "defaultValue": False},
        "deployLinuxVms": {"type": "bool", "defaultValue": True},
        "deployHydration": {"type": "bool", "defaultValue": True, "metadata": {"description": "Register the benign activity generator that feeds the hunting workspace."}},
        "hydrationIntervalMinutes": {"type": "string", "defaultValue": "60"},
        "autoShutdownTime": {"type": "string", "defaultValue": "0300", "metadata": {"description": "Daily auto-shutdown time (HHmm, VM local). 0300 UTC = 23:00 ET. Empty disables."}},
        "autoShutdownTimeZone": {"type": "string", "defaultValue": "UTC"},
        "serverVmSize": {"type": "string", "defaultValue": "Standard_D4ads_v6"},
        "clientVmSize": {"type": "string", "defaultValue": "Standard_D4ads_v6"},
        "linuxVmSize": {"type": "string", "defaultValue": "Standard_D2ads_v6"},
        "serverImagePublisher": {"type": "string", "defaultValue": "MicrosoftWindowsServer"},
        "serverImageOffer": {"type": "string", "defaultValue": "WindowsServer"},
        "serverImageSku": {"type": "string", "defaultValue": "2022-datacenter-g2"},
        "serverImageVersion": {"type": "string", "defaultValue": "latest"},
        "clientImagePublisher": {"type": "string", "defaultValue": "MicrosoftWindowsDesktop"},
        "clientImageOffer": {"type": "string", "defaultValue": "windows-11"},
        "clientImageSku": {"type": "string", "defaultValue": "win11-23h2-pro"},
        "clientImageVersion": {"type": "string", "defaultValue": "latest"},
    },
    "variables": {
        "promoteScript": promote_ps1,
        "baselineScript": baseline_ps1,
        "joinScript": join_ps1,
        "verifyScript": verify_ps1,
        "configureScript": configure_ps1,
        "configureLinuxScript": configure_linux_sh,
        "prepLinuxScript": prep_linux_sh,
        "hydrateWinB64": hydrate_win_b64,
        "hydrateLinuxB64": hydrate_linux_b64,
        "vmAdminRoleId": "[subscriptionResourceId('Microsoft.Authorization/roleDefinitions', '1c0163c0-47e6-4577-8991-ea5c82e286e4')]",
        "vmUserRoleId": "[subscriptionResourceId('Microsoft.Authorization/roleDefinitions', 'fb879df8-f326-4884-b1cf-06f3ad86be52')]",
        "dnsServerList": "[union(createArray(parameters('domainControllerPrivateIp')), parameters('additionalDnsServers'))]",
        "serverImage": {"publisher": "[parameters('serverImagePublisher')]", "offer": "[parameters('serverImageOffer')]", "sku": "[parameters('serverImageSku')]", "version": "[parameters('serverImageVersion')]"},
        "clientImage": {"publisher": "[parameters('clientImagePublisher')]", "offer": "[parameters('clientImageOffer')]", "sku": "[parameters('clientImageSku')]", "version": "[parameters('clientImageVersion')]"},
        "windowsVms": [
            {"name": "[format('{0}-dc01', parameters('prefix'))]", "size": "[parameters('serverVmSize')]", "image": "[variables('serverImage')]", "role": "DomainController", "isDc": True, "isServer": True},
            {"name": "[format('{0}-ms01', parameters('prefix'))]", "size": "[parameters('serverVmSize')]", "image": "[variables('serverImage')]", "role": "EntraConnectServer", "isDc": False, "isServer": True},
            {"name": "[format('{0}-ms02', parameters('prefix'))]", "size": "[parameters('serverVmSize')]", "image": "[variables('serverImage')]", "role": "MemberServer", "isDc": False, "isServer": True},
            {"name": "[format('{0}-cl01', parameters('prefix'))]", "size": "[parameters('clientVmSize')]", "image": "[variables('clientImage')]", "role": "Workstation", "isDc": False, "isServer": False},
            {"name": "[format('{0}-cl02', parameters('prefix'))]", "size": "[parameters('clientVmSize')]", "image": "[variables('clientImage')]", "role": "Workstation", "isDc": False, "isServer": False},
            {"name": "[format('{0}-cl03', parameters('prefix'))]", "size": "[parameters('clientVmSize')]", "image": "[variables('clientImage')]", "role": "Workstation", "isDc": False, "isServer": False},
        ],
        "linuxVms": [
            {"name": "[format('{0}-rhel01', parameters('prefix'))]", "image": {"publisher": "RedHat", "offer": "RHEL", "sku": "9-lvm-gen2", "version": "latest"}},
            {"name": "[format('{0}-ubu01', parameters('prefix'))]", "image": {"publisher": "Canonical", "offer": "0001-com-ubuntu-server-jammy", "sku": "22_04-lts-gen2", "version": "latest"}},
            {"name": "[format('{0}-sles01', parameters('prefix'))]", "image": {"publisher": "SUSE", "offer": "sles-15-sp5", "sku": "gen2", "version": "latest"}},
        ],
        "memberWinCount": 5,
        # Computer names (15-char NetBIOS) the baseline places into OUs and the verify step checks.
        "serverComputers": "[format('{0},{1}', take(format('{0}-ms01', parameters('prefix')), 15), take(format('{0}-ms02', parameters('prefix')), 15))]",
        "workstationComputers": "[format('{0},{1},{2}', take(format('{0}-cl01', parameters('prefix')), 15), take(format('{0}-cl02', parameters('prefix')), 15), take(format('{0}-cl03', parameters('prefix')), 15))]",
    },
    "resources": [],
}

R = tmpl["resources"]

# ---- Windows NICs ----
R.append({
    "type": "Microsoft.Network/networkInterfaces", "apiVersion": "2023-09-01",
    "name": "[format('{0}-nic', variables('windowsVms')[copyIndex()].name)]",
    "location": "[parameters('location')]",
    # Serial so the DC NIC (index 0, static domainControllerPrivateIp) is allocated before any dynamic NIC
    # can grab that address. The first real run lost 10.60.0.10 to a concurrently created private endpoint.
    "copy": {"name": "winNicLoop", "count": "[length(variables('windowsVms'))]", "mode": "serial", "batchSize": 1},
    "properties": {
        "ipConfigurations": [{
            "name": "ipconfig1",
            "properties": {
                "subnet": {"id": "[parameters('subnetResourceId')]"},
                "privateIPAllocationMethod": "[if(variables('windowsVms')[copyIndex()].isDc, 'Static', 'Dynamic')]",
                "privateIPAddress": "[if(variables('windowsVms')[copyIndex()].isDc, parameters('domainControllerPrivateIp'), null())]",
            },
        }],
        # DC resolves via itself/Azure; the other machines must use the DC for DNS so domain join works.
        "dnsSettings": "[if(variables('windowsVms')[copyIndex()].isDc, null(), createObject('dnsServers', variables('dnsServerList')))]",
    },
})

# ---- Windows VMs ----
R.append({
    "type": "Microsoft.Compute/virtualMachines", "apiVersion": "2023-09-01",
    "name": "[variables('windowsVms')[copyIndex()].name]",
    "location": "[parameters('location')]",
    "copy": {"name": "winVmLoop", "count": "[length(variables('windowsVms'))]"},
    "dependsOn": ["[resourceId('Microsoft.Network/networkInterfaces', format('{0}-nic', variables('windowsVms')[copyIndex()].name))]"],
    "identity": {"type": "SystemAssigned"},
    "properties": {
        "hardwareProfile": {"vmSize": "[variables('windowsVms')[copyIndex()].size]"},
        "osProfile": {
            "computerName": "[take(variables('windowsVms')[copyIndex()].name, 15)]",
            "adminUsername": "[parameters('adminUsername')]",
            "adminPassword": "[parameters('adminPassword')]",
            "windowsConfiguration": {"provisionVMAgent": True, "enableAutomaticUpdates": True},
        },
        "storageProfile": {
            "imageReference": "[variables('windowsVms')[copyIndex()].image]",
            "osDisk": {"createOption": "FromImage", "managedDisk": {"storageAccountType": "Premium_LRS"}},
        },
        "networkProfile": {"networkInterfaces": [{"id": "[resourceId('Microsoft.Network/networkInterfaces', format('{0}-nic', variables('windowsVms')[copyIndex()].name))]", "properties": {"primary": True}}]},
        "securityProfile": {"securityType": "TrustedLaunch", "uefiSettings": {"secureBootEnabled": True, "vTpmEnabled": True}},
    },
})

# ---- DC promotion run-command ----
R.append({
    "type": "Microsoft.Compute/virtualMachines/runCommands", "apiVersion": "2023-09-01",
    "name": "[format('{0}/promote-domain-controller', variables('windowsVms')[0].name)]",
    "location": "[parameters('location')]",
    "dependsOn": ["[resourceId('Microsoft.Compute/virtualMachines', variables('windowsVms')[0].name)]"],
    "properties": {
        # async: the script reboots the DC to finish promotion. Nothing else runs on the DC until every
        # member has joined (the joins wait for LDAP + DNS SRV, which only answer after that reboot), so no
        # later DC step can be killed by the promotion reboot (the run-3 failure).
        "asyncExecution": True,
        "treatFailureAsDeploymentFailure": False,
        "timeoutInSeconds": 3600,
        "source": {"script": "[variables('promoteScript')]"},
        "parameters": [
            {"name": "DomainName", "value": "[parameters('domainName')]"},
            {"name": "DomainNetbiosName", "value": "[parameters('domainNetbiosName')]"},
            {"name": "DnsForwarders", "value": "[parameters('dnsForwarders')]"},
        ],
        "protectedParameters": [{"name": "SafeModeAdminPassword", "value": "[parameters('safeModeAdminPassword')]"}],
    },
})

# ---- forest baseline run-command (after promotion reboot) ----
R.append({
    "type": "Microsoft.Compute/virtualMachines/runCommands", "apiVersion": "2023-09-01",
    "name": "[format('{0}/configure-forest-baseline', variables('windowsVms')[0].name)]",
    "location": "[parameters('location')]",
    "dependsOn": ["joinLoop"],
    "properties": {
        "asyncExecution": False,
        "treatFailureAsDeploymentFailure": True,
        "timeoutInSeconds": 3600,
        "source": {"script": "[variables('baselineScript')]"},
        "parameters": [
            {"name": "DomainName", "value": "[parameters('domainName')]"},
            {"name": "DomainNetbiosName", "value": "[parameters('domainNetbiosName')]"},
            {"name": "OuRoot", "value": "[parameters('ouRoot')]"},
            {"name": "UpnSuffix", "value": "[parameters('upnSuffix')]"},
            {"name": "LabUserName", "value": "[parameters('labUserName')]"},
            {"name": "DnsForwarders", "value": "[parameters('dnsForwarders')]"},
            {"name": "IntuneCredentialType", "value": "[parameters('intuneCredentialType')]"},
            {"name": "EnrollmentUrlSuffix", "value": "[parameters('cloudSuffix')]"},
            {"name": "CreateIntuneGpo", "value": "true"},
            {"name": "HydrationScriptBase64", "value": "[if(parameters('deployHydration'), variables('hydrateWinB64'), '')]"},
            {"name": "HydrationIntervalMinutes", "value": "[parameters('hydrationIntervalMinutes')]"},
            {"name": "TenantId", "value": "[subscription().tenantId]"},
            {"name": "TenantDomain", "value": "[parameters('upnSuffix')]"},
            {"name": "ServerComputers", "value": "[variables('serverComputers')]"},
            {"name": "WorkstationComputers", "value": "[variables('workstationComputers')]"},
        ],
        "protectedParameters": [
            {"name": "LabUserPassword", "value": "[parameters('labUserPassword')]"},
            {"name": "MdeOnboardingBlob", "value": "[parameters('mdeOnboardingBlob')]"},
        ],
    },
})

# ---- domain join run-command (members 1..n, serialised lightly by dependsOn on DC baseline) ----
R.append({
    "type": "Microsoft.Compute/virtualMachines/runCommands", "apiVersion": "2023-09-01",
    "name": "[format('{0}/join-domain', variables('windowsVms')[range(1, variables('memberWinCount'))[copyIndex()]].name)]",
    "location": "[parameters('location')]",
    "copy": {"name": "joinLoop", "count": "[variables('memberWinCount')]"},
    "dependsOn": [
        "[resourceId('Microsoft.Compute/virtualMachines/runCommands', variables('windowsVms')[0].name, 'promote-domain-controller')]",
        "[resourceId('Microsoft.Compute/virtualMachines', variables('windowsVms')[range(1, variables('memberWinCount'))[copyIndex()]].name)]",
    ],
    "properties": {
        # Joins the default Computers container; the baseline (which runs after all joins) moves each
        # machine into OU=MemberServers / OU=Workstations. A failed join now fails the deployment.
        "asyncExecution": False,
        "treatFailureAsDeploymentFailure": True,
        "timeoutInSeconds": 3600,
        "source": {"script": "[variables('joinScript')]"},
        "parameters": [
            {"name": "DomainName", "value": "[parameters('domainName')]"},
            {"name": "DomainAdminUsername", "value": "[parameters('adminUsername')]"},
            {"name": "DomainControllerIp", "value": "[parameters('domainControllerPrivateIp')]"},
        ],
        "protectedParameters": [{"name": "DomainAdminPassword", "value": "[parameters('adminPassword')]"}],
    },
})

# ---- post-join Windows member configuration ----
R.append({
    "type": "Microsoft.Compute/virtualMachines/runCommands", "apiVersion": "2023-09-01",
    "name": "[format('{0}/configure-member', variables('windowsVms')[range(1, variables('memberWinCount'))[copyIndex()]].name)]",
    "location": "[parameters('location')]",
    "copy": {"name": "configureLoop", "count": "[variables('memberWinCount')]"},
    "dependsOn": [
        "[resourceId('Microsoft.Compute/virtualMachines/runCommands', variables('windowsVms')[range(1, variables('memberWinCount'))[copyIndex()]].name, 'join-domain')]",
        "[resourceId('Microsoft.Compute/virtualMachines/runCommands', variables('windowsVms')[0].name, 'configure-forest-baseline')]",
    ],
    "properties": {
        "asyncExecution": True,
        "treatFailureAsDeploymentFailure": False,
        "timeoutInSeconds": 3600,
        "source": {"script": "[variables('configureScript')]"},
        "parameters": [
            {"name": "DomainName", "value": "[parameters('domainName')]"},
            {"name": "DomainNetbiosName", "value": "[parameters('domainNetbiosName')]"},
            {"name": "Role", "value": "[variables('windowsVms')[range(1, variables('memberWinCount'))[copyIndex()]].role]"},
            {"name": "HydrationScriptBase64", "value": "[if(parameters('deployHydration'), variables('hydrateWinB64'), '')]"},
            {"name": "HydrationIntervalMinutes", "value": "[parameters('hydrationIntervalMinutes')]"},
            {"name": "CloudSuffix", "value": "[parameters('cloudSuffix')]"},
        ],
        "protectedParameters": [{"name": "MdeOnboardingBlob", "value": "[if(variables('windowsVms')[range(1, variables('memberWinCount'))[copyIndex()]].isServer, '', parameters('mdeOnboardingBlob'))]"}],
    },
})

# ---- verify-forest: final gate on the DC; fails the deployment if the forest is not usable ----
R.append({
    "type": "Microsoft.Compute/virtualMachines/runCommands", "apiVersion": "2023-09-01",
    "name": "[format('{0}/verify-forest', variables('windowsVms')[0].name)]",
    "location": "[parameters('location')]",
    "dependsOn": ["configureLoop"],
    "properties": {
        "asyncExecution": False,
        "treatFailureAsDeploymentFailure": True,
        "timeoutInSeconds": 900,
        "source": {"script": "[variables('verifyScript')]"},
        "parameters": [
            {"name": "DomainName", "value": "[parameters('domainName')]"},
            {"name": "OuRoot", "value": "[parameters('ouRoot')]"},
            {"name": "ServerComputers", "value": "[variables('serverComputers')]"},
            {"name": "WorkstationComputers", "value": "[variables('workstationComputers')]"},
            {"name": "RequireScp", "value": "[if(empty(parameters('upnSuffix')), 'false', 'true')]"},
        ],
    },
})

# ---- No AADLoginForWindows on the Windows VMs ----
# AADLoginForWindows makes a VM *Microsoft Entra joined*, which cannot coexist with the AD domain join /
# hybrid Entra join this lab is built to exercise. Windows machines get their Entra identity through
# hybrid join (Entra Connect); Bastion sign-in to them uses AD credentials. Entra sign-in through
# Bastion is used for the Linux servers (AADSSHLoginForLinux, GA in the portal).

# ---- AMA (Windows) ----
R.append({
    "type": "Microsoft.Compute/virtualMachines/extensions", "apiVersion": "2023-09-01",
    "name": "[format('{0}/AzureMonitorWindowsAgent', variables('windowsVms')[copyIndex()].name)]",
    "location": "[parameters('location')]",
    "copy": {"name": "amaWinLoop", "count": "[length(variables('windowsVms'))]"},
    "dependsOn": ["[resourceId('Microsoft.Compute/virtualMachines', variables('windowsVms')[copyIndex()].name)]"],
    "properties": {"publisher": "Microsoft.Azure.Monitor", "type": "AzureMonitorWindowsAgent", "typeHandlerVersion": "1.0", "autoUpgradeMinorVersion": True, "enableAutomaticUpgrade": True},
})

# ---- MDE ----
# The MDE.Windows / MDE.Linux extensions are owned by Defender for Cloud: when Defender for Servers is
# Standard on the subscription (deployDefenderForServers), Defender auto-provisions them on every Azure VM
# within ~an hour of creation. Deploying them from a template fails with "Failed to configure Microsoft
# Defender for Endpoint: You cannot call a method on a null-valued expression" (seen in the first real run),
# so the kit no longer declares them. Clients can additionally be onboarded with mdeOnboardingBlob.

# ---- VM login RBAC (Windows) ----
R.append({
    "type": "Microsoft.Authorization/roleAssignments", "apiVersion": "2022-04-01",
    "name": "[guid(resourceId('Microsoft.Compute/virtualMachines', variables('windowsVms')[copyIndex()].name), variables('vmAdminRoleId'), parameters('entraLoginPrincipalId'))]",
    "condition": "[and(parameters('assignVmAdminRole'), not(empty(parameters('entraLoginPrincipalId'))))]",
    "copy": {"name": "winAdminRbac", "count": "[length(variables('windowsVms'))]"},
    "scope": "[format('Microsoft.Compute/virtualMachines/{0}', variables('windowsVms')[copyIndex()].name)]",
    "dependsOn": ["[resourceId('Microsoft.Compute/virtualMachines', variables('windowsVms')[copyIndex()].name)]"],
    "properties": {"roleDefinitionId": "[variables('vmAdminRoleId')]", "principalId": "[parameters('entraLoginPrincipalId')]", "principalType": "[parameters('entraPrincipalType')]"},
})
R.append({
    "type": "Microsoft.Authorization/roleAssignments", "apiVersion": "2022-04-01",
    "name": "[guid(resourceId('Microsoft.Compute/virtualMachines', variables('windowsVms')[copyIndex()].name), variables('vmUserRoleId'), parameters('entraLoginPrincipalId'))]",
    "condition": "[and(parameters('assignVmUserRole'), not(empty(parameters('entraLoginPrincipalId'))))]",
    "copy": {"name": "winUserRbac", "count": "[length(variables('windowsVms'))]"},
    "scope": "[format('Microsoft.Compute/virtualMachines/{0}', variables('windowsVms')[copyIndex()].name)]",
    "dependsOn": ["[resourceId('Microsoft.Compute/virtualMachines', variables('windowsVms')[copyIndex()].name)]"],
    "properties": {"roleDefinitionId": "[variables('vmUserRoleId')]", "principalId": "[parameters('entraLoginPrincipalId')]", "principalType": "[parameters('entraPrincipalType')]"},
})

# ---- auto-shutdown (Windows) ----
R.append({
    "type": "Microsoft.DevTestLab/schedules", "apiVersion": "2018-09-15",
    "name": "[format('shutdown-computevm-{0}', variables('windowsVms')[copyIndex()].name)]",
    "location": "[parameters('location')]",
    "condition": "[not(empty(parameters('autoShutdownTime')))]",
    "copy": {"name": "winShutdownLoop", "count": "[length(variables('windowsVms'))]"},
    "dependsOn": ["[resourceId('Microsoft.Compute/virtualMachines', variables('windowsVms')[copyIndex()].name)]"],
    "properties": {
        "status": "Enabled", "taskType": "ComputeVmShutdownTask",
        "dailyRecurrence": {"time": "[parameters('autoShutdownTime')]"},
        "timeZoneId": "[parameters('autoShutdownTimeZone')]",
        "notificationSettings": {"status": "Disabled", "timeInMinutes": 30},
        "targetResourceId": "[resourceId('Microsoft.Compute/virtualMachines', variables('windowsVms')[copyIndex()].name)]",
    },
})

# ================= Linux =================
R.append({
    "type": "Microsoft.Network/networkInterfaces", "apiVersion": "2023-09-01",
    "name": "[format('{0}-nic', variables('linuxVms')[copyIndex()].name)]",
    "location": "[parameters('location')]",
    "condition": "[parameters('deployLinuxVms')]",
    "copy": {"name": "lnxNicLoop", "count": "[length(variables('linuxVms'))]"},
    "dependsOn": ["winNicLoop"],
    "properties": {
        "ipConfigurations": [{"name": "ipconfig1", "properties": {"subnet": {"id": "[parameters('subnetResourceId')]"}, "privateIPAllocationMethod": "Dynamic"}}],
        "dnsSettings": {"dnsServers": "[variables('dnsServerList')]"},
    },
})
R.append({
    "type": "Microsoft.Compute/virtualMachines", "apiVersion": "2023-09-01",
    "name": "[variables('linuxVms')[copyIndex()].name]",
    "location": "[parameters('location')]",
    "condition": "[parameters('deployLinuxVms')]",
    "copy": {"name": "lnxVmLoop", "count": "[length(variables('linuxVms'))]"},
    "dependsOn": ["[resourceId('Microsoft.Network/networkInterfaces', format('{0}-nic', variables('linuxVms')[copyIndex()].name))]"],
    "identity": {"type": "SystemAssigned"},
    "properties": {
        "hardwareProfile": {"vmSize": "[parameters('linuxVmSize')]"},
        "osProfile": {
            "computerName": "[take(variables('linuxVms')[copyIndex()].name, 15)]",
            "adminUsername": "[parameters('adminUsername')]",
            "adminPassword": "[parameters('adminPassword')]",
            "linuxConfiguration": {"disablePasswordAuthentication": False, "provisionVMAgent": True, "patchSettings": {"patchMode": "ImageDefault"}},
        },
        "storageProfile": {
            "imageReference": "[variables('linuxVms')[copyIndex()].image]",
            "osDisk": {"createOption": "FromImage", "managedDisk": {"storageAccountType": "Premium_LRS"}},
        },
        "networkProfile": {"networkInterfaces": [{"id": "[resourceId('Microsoft.Network/networkInterfaces', format('{0}-nic', variables('linuxVms')[copyIndex()].name))]", "properties": {"primary": True}}]},
        "securityProfile": {"securityType": "TrustedLaunch", "uefiSettings": {"secureBootEnabled": True, "vTpmEnabled": True}},
    },
})
# SLES/RHEL/Ubuntu images that are marketplace "plan" images need a plan block; add it conditionally is
# hard per-image in one copy, so document that SLES BYOS/PAYG plan may be required. The listed SKUs are
# PAYG images that do not require a plan block.
# first-boot settle + repo metadata refresh, so the extension installers below never race the package lock
R.append({
    "type": "Microsoft.Compute/virtualMachines/runCommands", "apiVersion": "2023-09-01",
    "name": "[format('{0}/prep-linux', variables('linuxVms')[copyIndex()].name)]",
    "location": "[parameters('location')]",
    "condition": "[parameters('deployLinuxVms')]",
    "copy": {"name": "lnxPrepLoop", "count": "[length(variables('linuxVms'))]"},
    "dependsOn": ["[resourceId('Microsoft.Compute/virtualMachines', variables('linuxVms')[copyIndex()].name)]"],
    "properties": {
        "asyncExecution": False,
        "treatFailureAsDeploymentFailure": False,
        "timeoutInSeconds": 1500,
        "source": {"script": "[variables('prepLinuxScript')]"},
    },
})
R.append({
    "type": "Microsoft.Compute/virtualMachines/extensions", "apiVersion": "2023-09-01",
    "name": "[format('{0}/AADSSHLoginForLinux', variables('linuxVms')[copyIndex()].name)]",
    "location": "[parameters('location')]",
    "condition": "[parameters('deployLinuxVms')]",
    "copy": {"name": "aadLnxLoop", "count": "[length(variables('linuxVms'))]"},
    "dependsOn": ["[resourceId('Microsoft.Compute/virtualMachines/runCommands', variables('linuxVms')[copyIndex()].name, 'prep-linux')]"],
    "properties": {"publisher": "Microsoft.Azure.ActiveDirectory", "type": "AADSSHLoginForLinux", "typeHandlerVersion": "1.0", "autoUpgradeMinorVersion": True},
})
R.append({
    "type": "Microsoft.Compute/virtualMachines/extensions", "apiVersion": "2023-09-01",
    "name": "[format('{0}/AzureMonitorLinuxAgent', variables('linuxVms')[copyIndex()].name)]",
    "location": "[parameters('location')]",
    "condition": "[parameters('deployLinuxVms')]",
    "copy": {"name": "amaLnxLoop", "count": "[length(variables('linuxVms'))]"},
    "dependsOn": ["[resourceId('Microsoft.Compute/virtualMachines/extensions', variables('linuxVms')[copyIndex()].name, 'AADSSHLoginForLinux')]"],
    "properties": {"publisher": "Microsoft.Azure.Monitor", "type": "AzureMonitorLinuxAgent", "typeHandlerVersion": "1.0", "autoUpgradeMinorVersion": True, "enableAutomaticUpgrade": True},
})
# custom-script configuration (auditd + rsyslog + hydration) via runCommand
R.append({
    "type": "Microsoft.Compute/virtualMachines/runCommands", "apiVersion": "2023-09-01",
    "name": "[format('{0}/configure-linux', variables('linuxVms')[copyIndex()].name)]",
    "location": "[parameters('location')]",
    "condition": "[parameters('deployLinuxVms')]",
    "copy": {"name": "lnxConfigLoop", "count": "[length(variables('linuxVms'))]"},
    "dependsOn": ["[resourceId('Microsoft.Compute/virtualMachines/extensions', variables('linuxVms')[copyIndex()].name, 'AzureMonitorLinuxAgent')]"],
    "properties": {
        "asyncExecution": True,
        "treatFailureAsDeploymentFailure": False,
        "timeoutInSeconds": 1800,
        "source": {"script": "[variables('configureLinuxScript')]"},
        "parameters": [
            {"name": "arg1", "value": "[parameters('cloudSuffix')]"},
            {"name": "arg2", "value": "[if(parameters('deployHydration'), variables('hydrateLinuxB64'), '')]"},
            {"name": "arg3", "value": "[parameters('hydrationIntervalMinutes')]"},
        ],
    },
})
R.append({
    "type": "Microsoft.Authorization/roleAssignments", "apiVersion": "2022-04-01",
    "name": "[guid(resourceId('Microsoft.Compute/virtualMachines', variables('linuxVms')[copyIndex()].name), variables('vmAdminRoleId'), parameters('entraLoginPrincipalId'))]",
    "condition": "[and(parameters('deployLinuxVms'), parameters('assignVmAdminRole'), not(empty(parameters('entraLoginPrincipalId'))))]",
    "copy": {"name": "lnxAdminRbac", "count": "[length(variables('linuxVms'))]"},
    "scope": "[format('Microsoft.Compute/virtualMachines/{0}', variables('linuxVms')[copyIndex()].name)]",
    "dependsOn": ["[resourceId('Microsoft.Compute/virtualMachines', variables('linuxVms')[copyIndex()].name)]"],
    "properties": {"roleDefinitionId": "[variables('vmAdminRoleId')]", "principalId": "[parameters('entraLoginPrincipalId')]", "principalType": "[parameters('entraPrincipalType')]"},
})
R.append({
    "type": "Microsoft.DevTestLab/schedules", "apiVersion": "2018-09-15",
    "name": "[format('shutdown-computevm-{0}', variables('linuxVms')[copyIndex()].name)]",
    "location": "[parameters('location')]",
    "condition": "[and(parameters('deployLinuxVms'), not(empty(parameters('autoShutdownTime'))))]",
    "copy": {"name": "lnxShutdownLoop", "count": "[length(variables('linuxVms'))]"},
    "dependsOn": ["[resourceId('Microsoft.Compute/virtualMachines', variables('linuxVms')[copyIndex()].name)]"],
    "properties": {
        "status": "Enabled", "taskType": "ComputeVmShutdownTask",
        "dailyRecurrence": {"time": "[parameters('autoShutdownTime')]"},
        "timeZoneId": "[parameters('autoShutdownTimeZone')]",
        "notificationSettings": {"status": "Disabled", "timeInMinutes": 30},
        "targetResourceId": "[resourceId('Microsoft.Compute/virtualMachines', variables('linuxVms')[copyIndex()].name)]",
    },
})

# domainDn helper variable
tmpl["variables"]["domainDn"] = "[format('DC={0}', join(split(parameters('domainName'), '.'), ',DC='))]"

# Build the name arrays explicitly (no lambda/map) so the outputs are valid on every ARM language
# version and the security-lab module reliably receives the VM names for DCR associations.
win_names = "[createArray({0})]".format(", ".join(
    "format('{{0}}-{0}', parameters('prefix'))".format(sfx) for sfx in ("dc01", "ms01", "ms02", "cl01", "cl02", "cl03")))
lnx_names = "[if(parameters('deployLinuxVms'), createArray({0}), createArray())]".format(", ".join(
    "format('{{0}}-{0}', parameters('prefix'))".format(sfx) for sfx in ("rhel01", "ubu01", "sles01")))
tmpl["outputs"] = {
    "windowsVmNames": {"type": "array", "value": win_names},
    "linuxVmNames": {"type": "array", "value": lnx_names},
    "domainControllerName": {"type": "string", "value": "[format('{0}-dc01', parameters('prefix'))]"},
}

out = os.path.join(ROOT, "templates", "ad-entra-vms.json")
with open(out, "w", encoding="utf-8") as f:
    json.dump(tmpl, f, indent=2)
print("wrote", out, os.path.getsize(out), "bytes")
