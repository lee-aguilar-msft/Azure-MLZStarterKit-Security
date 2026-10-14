# MLZ Security Lab Starter Kit

A Mission Landing Zone–aligned, one-shot **security lab** for Azure — built and tested primarily for
**Azure Government (GCC High)**, and fully supported in Azure Commercial. It stands up an Active
Directory forest, Entra-integrated Windows and Linux machines, Microsoft Sentinel with the built-in
analytics content enabled, Defender for Cloud/Endpoint, Azure Arc private connectivity, and a steady
stream of hunting telemetry — then tears the whole thing down and rebuilds it on a 90-day cadence.

> **Primary target: Azure Government (GCC High).** The default parameter file is `params/gov-lab.json`
> and the firewall/endpoint logic defaults to the `.us` Government service endpoints. Commercial is a
> first-class secondary target via `params/commercial-lab.json`.

---

## What it deploys

**MLZ core (hub)** — hub VNet, Azure Firewall (Premium) with DNS proxy, Bastion, Log Analytics,
Azure Monitor Private Link Scope, and the MLZ naming/tagging model. Fetched live from upstream
`Azure/missionlz`.

**Tier3 workload network** — spoke VNet peered to the hub, routed through the firewall, with the lab
subnet and (optionally) a delegated subnet for a Private DNS Resolver.

**AD forest + Entra lab** (`templates/ad-entra-vms.json`)
- 1 domain controller — forest promoted via run-command with **NTDS/SYSVOL on the OS disk** (a
  deliberate choice after two data-disk losses to the v6 NVMe host-move bug), DNS forwarders pointed
  at the hub.
- 2 member servers — `ms01` doubles as the **Entra Connect** staging server (installer pre-staged;
  configuration is interactive because it needs MFA).
- 3 Windows 11 clients — joined, with hybrid-join and Intune auto-enrollment retry tasks.
- 3 Linux servers — **RHEL, Ubuntu, SLES** — each with **Entra SSH login** (`AADSSHLoginForLinux`),
  auditd + rsyslog wired for the Syslog pipeline.
- Entra login + VM Login RBAC on every VM; Azure Monitor Agent on every VM; MDE auto-provisioned by Defender for Servers;
  DevTest auto-shutdown at 03:00 UTC (23:00 ET).
- Forest baseline: OU tree, security groups, a lab user **created enabled with a password** (so a
  soft-match to a live cloud identity doesn't sync "disabled"), UPN suffix, AD Recycle Bin, an
  advanced audit-policy + PowerShell-logging GPO, an Intune auto-enrollment GPO, and an optional
  MDE-onboarding startup-script GPO.

**Security operations** (`templates/security-lab.json`)
- Microsoft Sentinel onboarded on a dedicated lab workspace.
- Data Collection Rules for **Windows Security Events (all) + Sysmon/PowerShell/System/Application**
  and **Linux Syslog (all facilities)**, associated to every VM through AMA.
- Content Hub solutions installed and **all matching built-in analytics rules enabled** for Entra ID,
  Azure Activity, Microsoft Defender XDR, Defender for Endpoint, Windows Security Events, Syslog and
  Threat Intelligence, plus **Entity Behavior Analytics (UEBA)** and the Defender **XDR** connector.
  (Run post-deploy via the GitHub Action / Cloud Shell, or inline via an opt-in deploymentScript.)

**Azure Arc private connectivity** (`templates/arc-private-link.json`)
- Azure Arc **Private Link Scope** + private endpoint (`hybridcompute`) and the Arc private DNS zones
  (`privatelink.his.arc.azure.us|com`, `privatelink.guestconfiguration.azure.us|com`,
  `privatelink.dp.kubernetesconfiguration.azure.us|com`), linked to the hub and workload VNets.
- Optional Azure **Private DNS Resolver** inbound endpoint.

**Firewall rules** — a lab rule collection group added to the hub firewall policy with network rules
on the needed Azure **service tags** and application rules (FQDN tags + explicit, cloud-aware FQDN
lists) for **Intune, MDE, Azure Arc, Entra device registration, Linux package repos, and PKI/CRL/OCSP**.
An optional broad `AzureCloud` service-tag allow is included for lab convenience.

**Data hydration** — benign, realistic admin/user activity (file/process/registry/web activity, a
churning group membership, deliberate failed logons, Linux sudo/auth noise) on a schedule so the
workspace and MDE always have material to hunt over.

**CSPM coverage sample** — SQL DB, storage + container, ACR, **Key Vault**, **App Service (B1 plan + web
app)**, **API Management + a sample API** (optionally onboarded to Defender for APIs), and a
nested-deployment sample — so Defender for SQL, Storage, Containers, Key Vault, App Service, APIs and
Resource Manager each have a resource to assess. Each piece is a toggle (`deployCspm*`).

---

## Deploy

### Option A — Portal (blue button)

Azure Government:

[![Deploy to Azure Gov](https://aka.ms/deploytoazurebutton)](https://portal.azure.us/#blade/Microsoft_Azure_CreateUIDef/CustomDeploymentBlade/uri/https%3A%2F%2Fraw.githubusercontent.com%2Flee-aguilar-msft%2FAzure-MLZStarterKit-Security%2Fmain%2Fsolution.json/uiFormDefinitionUri/https%3A%2F%2Fraw.githubusercontent.com%2Flee-aguilar-msft%2FAzure-MLZStarterKit-Security%2Fmain%2FuiDefinition.json)

Azure Commercial:

[![Deploy to Azure](https://aka.ms/deploytoazurebutton)](https://portal.azure.com/#blade/Microsoft_Azure_CreateUIDef/CustomDeploymentBlade/uri/https%3A%2F%2Fraw.githubusercontent.com%2Flee-aguilar-msft%2FAzure-MLZStarterKit-Security%2Fmain%2Fsolution.json/uiFormDefinitionUri/https%3A%2F%2Fraw.githubusercontent.com%2Flee-aguilar-msft%2FAzure-MLZStarterKit-Security%2Fmain%2FuiDefinition.json)

> Blue buttons require the repository to be **public** so the raw template URIs resolve. The portal
> walks you through Basics → Networking → Security & Compliance → **Lab Options** → Identity → Compute.

### Option B — `deploy.ps1` (params file + secret prompts)

```powershell
# Azure Government (primary)
./deploy.ps1 -ParametersFile ./params/gov-lab.json -AzureEnvironment AzureUSGovernment `
  -SubscriptionId <sub-id> -Location usgovvirginia

# Commercial
./deploy.ps1 -ParametersFile ./params/commercial-lab.json -AzureEnvironment AzureCloud `
  -SubscriptionId <sub-id> -Location eastus
```

The passwords (`adminPassword`, `safeModeAdminPassword`, `labUserPassword`) are intentionally blank in
the params files and are prompted for at deploy time — never commit real secrets. Add `-WhatIf` to
preview.

### Option C — Azure CLI

```bash
az deployment sub create \
  --name seclab-$(date +%Y%m%d%H%M) \
  --location usgovvirginia \
  --template-file ./solution.json \
  --parameters @params/gov-lab.json \
  --parameters adminPassword=<...> safeModeAdminPassword=<...>
```

### Option D — GitHub Action (90-day rebuild)

`.github/workflows/rebuild-lab.yml` rebuilds the lab every ~90 days and on demand using Entra
federated credentials (OIDC — no stored cloud secrets). Configure the repository variables/secrets
listed at the top of the workflow, including `AZURE_ENVIRONMENT = AzureUSGovernment`. The job destroys
the prior build, redeploys, then runs the Sentinel content/analytics/UEBA enablement.

---

## Post-deploy (finishes the identity + Sentinel content)

Some steps need interactive MFA and are deliberately **not** automated. After the deployment, run in
Cloud Shell (Gov: `portal.azure.us` → Cloud Shell):

```powershell
./templates/scripts/Post-Deploy.ps1 -SubscriptionId <sub> -ResourceGroupName <tier3-rg> `
  -WorkspaceName <prefix>-law-lab -EnableXdrConnector
```

It enables the Sentinel content/analytics/UEBA, then prints the checklist for:
1. the cloud-only **break-glass Global Admin** (create and exclude from Conditional Access *before*
   enabling Entra Connect sync),
2. the Conditional Access **exclusion of the "Microsoft Intune Enrollment" app**
   (`d4ebce55-015a-49b5-a083-c84d1797ae8c`) — the fix for the `AADSTS50076 / interaction_required`
   that otherwise blocks silent MDM enrollment in GCC High, and
3. **Entra Connect** configuration + the **hybrid-join cycle** (`Invoke-HybridJoinCycle.ps1`).

---

## Prerequisites

Run once per subscription in Cloud Shell (PowerShell), in the target cloud:

```powershell
# CMK encrypted disks used by MLZ ephemeral VMs
az feature register --name EncryptionAtHost --namespace Microsoft.Compute
az provider register --namespace Microsoft.Compute

# Auto-shutdown schedules
az provider register --namespace Microsoft.DevTestLab
# Azure Arc Private Link Scope (if deployArcPrivateLink = true)
az provider register --namespace Microsoft.HybridCompute
# Private DNS Resolver (if deployPrivateDnsResolver = true)
az provider register --namespace Microsoft.Network
# Inline Sentinel content script only (if deploySentinelContentScript = true)
az provider register --namespace Microsoft.ContainerInstance
# CSPM coverage samples (API Management, App Service, Key Vault)
az provider register --namespace Microsoft.ApiManagement
az provider register --namespace Microsoft.Web
az provider register --namespace Microsoft.KeyVault

# Wait until EncryptionAtHost shows Registered
az feature show --name EncryptionAtHost --namespace Microsoft.Compute --query "properties.state" -o tsv
```

You also need an Entra **security group** for VM login — pass its object ID as `entraLoginPrincipalId`
(in Commercial you can instead set `autoCreateEntraGroup = true`). Licensing for Intune auto-enrollment
(Entra ID P1/P2 + Intune) is a tenant prerequisite, not deployed here.

---

## Destroy (teardown)

`destroy.ps1` discovers every resource group by the MLZ naming prefix and deletes them in parallel —
this removes the hub RGs **and** the tier3 RG containing all VMs, the workspace, DCRs, the Arc Private
Link Scope, private endpoints and private DNS zones, the CSPM resources and the content-script managed
identity. Optional flags reset Defender plans, remove policy assignments, and delete the Entra group.

```powershell
Invoke-WebRequest -Uri "https://raw.githubusercontent.com/lee-aguilar-msft/Azure-MLZStarterKit-Security/main/destroy.ps1" -OutFile destroy.ps1
./destroy.ps1 -SubscriptionId <sub> -Identifier sdl -EnvironmentAbbreviation dev `
  -Location usgovvirginia -RemoveDefenderPlans -RemovePolicyAssignments -Force
```

> **Irreversible.** All VMs, data, networking and associated resources are permanently deleted.

---

## Files

| Path | Purpose |
|------|---------|
| `solution.json` | Subscription-level orchestrator (MLZ core + tier3 + firewall rules + AD/Entra lab + CSPM + Sentinel/DCR module + Arc PLS). |
| `uiDefinition.json` | Portal CreateUiDefinition, including the **Lab Options** step. |
| `params/gov-lab.json` | **Azure Government / GCC High** parameter file (primary). |
| `params/commercial-lab.json` | Azure Commercial parameter file. |
| `deploy.ps1` | Subscription-scope deploy wrapper with secret prompts (Gov or Commercial). |
| `destroy.ps1` | Teardown by naming prefix + optional Defender/policy/Entra cleanup. |
| `templates/tier3.json` | MLZ tier3 fork (adds `managementVirtualMachineSize`; firewall rules + additional subnets flow through). |
| `templates/ad-entra-vms.json` | DCs, member servers, Windows clients, Linux trio, Entra login, AMA, auto-shutdown, run-command automation (MDE via Defender for Servers auto-provisioning). |
| `templates/security-lab.json` | Sentinel onboarding, DCRs + associations, optional content/analytics/UEBA deploymentScript. |
| `templates/arc-private-link.json` | Arc Private Link Scope, private endpoint, Arc private DNS zones, optional Private DNS Resolver. |
| `templates/cspm-coverage.json` | SQL/Storage/ACR/Key Vault/App Service/API Management + nested-deployment samples for Defender coverage. |
| `templates/scripts/*.ps1 / *.sh` | Promotion, join, Windows/Linux configuration, hydration, Sentinel content, hybrid-join, post-deploy. |
| `.github/workflows/rebuild-lab.yml` | 90-day OIDC rebuild pipeline. |
| `build/*.py` | Generators/validator used to assemble and lint the templates (dev-time only). |

---

## Notes & known constraints

- **Gov vs Commercial endpoints** are selected by `cloudSuffix` (`us`/`com`) and by `environment()`
  inside the firewall rules, so the same templates produce the right `.us`/`.com` hosts in each cloud.
- The **inline Sentinel content** deploymentScript needs Azure Container Instance reachability; in a
  locked MLZ network the GitHub Action / Cloud Shell path is more reliable, so it defaults to **off**.
- **Entra Connect** and **hybrid join** are interactive (MFA) and are staged, not fully automated.
- **MDI** (Defender for Identity) sensors are intentionally **out of scope** — installed separately.
- SLES/RHEL/Ubuntu use PAYG marketplace images; if your subscription requires a plan acceptance for a
  given image, accept it (or adjust the image reference) before deploying.
- The CSPM API Management sample defaults to the **Developer** SKU (works in Azure Government; ~30–45 min
  to provision, ~$50/mo). Set `cspmApimSku` to `BasicV2`/`StandardV2` for minutes-fast provisioning where
  those tiers are available, or `deployCspmApiManagement = false` to skip it.
- **Defender for DNS** is no longer offered as a standalone plan (Microsoft retired it; DNS threat detection
  now ships inside Defender for Servers / CSPM), so the kit does not enable it. **Defender for APIs**
  needs an explicit sub-plan — the kit sets `defenderForApisSubPlan = P1` (up to 1M calls/month).
- The standalone **DoD IL5** regulatory initiative has been retired by Microsoft, so the kit assigns the
  **Microsoft cloud security benchmark** (`deployMcsb`, the Defender CSPM baseline) instead, alongside the
  optional NIST 800-53 R5 / 800-171 R2 initiatives. All three exist in Azure Government.
- The portal form is **cloud-aware**: when a `usgov*`/`usdod*` region is selected it hides what Azure
  Government does not offer (Defender for App Service, Defender for APIs, commercial-only VM sizes) and
  derives the `.us`/`.com` endpoint set from the region automatically.
- The Arc Private Link Scope uses a preview API version; keep `deployArcPrivateLink = false` if your
  subscription/region doesn't expose it yet.
