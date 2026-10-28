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

## Prerequisites — do these first

**1. Pick the right cloud and region.** Azure Government: `usgovvirginia` (tested). Azure Commercial:
check which regions the subscription can actually create VMs in *before* deploying — internal, trial and
new subscriptions often have region-level VM restrictions that make every size `NotAvailableForSubscription`
(the Commercial guide, section 2.4, has the SKU-API check; West US 2 worked on the test subscription).

**2. Register features and resource providers** — once per subscription, Cloud Shell in the target cloud:

```bash
# CMK encrypted disks used by MLZ ephemeral VMs
az feature register --name EncryptionAtHost --namespace Microsoft.Compute
# Commercial only: some subscriptions require this for the MLZ public IPs (firewall / Bastion)
az feature register --name AllowBringYourOwnPublicIpAddress --namespace Microsoft.Network
az provider register --namespace Microsoft.Compute
az provider register --namespace Microsoft.Network

# Auto-shutdown schedules
az provider register --namespace Microsoft.DevTestLab
# Azure Arc Private Link Scope (if deployArcPrivateLink = true)
az provider register --namespace Microsoft.HybridCompute
# Inline Sentinel content script only (if deploySentinelContentScript = true)
az provider register --namespace Microsoft.ContainerInstance
# CSPM coverage samples (API Management, App Service, Key Vault)
az provider register --namespace Microsoft.ApiManagement
az provider register --namespace Microsoft.Web
az provider register --namespace Microsoft.KeyVault

# Wait until both features show Registered
az feature show --name EncryptionAtHost --namespace Microsoft.Compute --query "properties.state" -o tsv
az feature show --name AllowBringYourOwnPublicIpAddress --namespace Microsoft.Network --query "properties.state" -o tsv
```

**3. Entra ID**

- A **security group** for Entra VM login — pass its object ID as `entraLoginPrincipalId` (Commercial can
  instead set `autoCreateEntraGroup = true`).
- A cloud-only **break-glass Global Administrator**, excluded from Conditional Access, before Entra Connect
  sync is turned on.
- A **verified domain** for the lab user's UPN suffix (`<tenant>.onmicrosoft.com` is fine) — hybrid
  join and MDM auto-enrollment need the synced user's UPN to resolve in Entra.
- **Licences** for the lab user: Entra ID P1/P2 + Intune (any Microsoft 365 E3/E5-class SKU); Defender
  for Endpoint P2 for the clients (the servers are covered by Defender for Servers P2).

**4. Your account**

- Azure: **Owner** on the subscription (the template assigns RBAC, policy and Defender plans).
- Entra: **Global Administrator** (or Security Administrator + Intune Administrator + Cloud Application
  Administrator + License Administrator) for the post-deploy scripts — Sentinel UEBA refuses anything less
  (`User does not have required admin roles`); **Hybrid Identity Administrator** for the Entra Connect wizard.
  Activate the roles through PIM before step 5 of the guide.

**5. Conditional Access.** Silent Intune enrollment of the hybrid-joined clients fails with `0x8018002A`
(or `AADSTS50076 / interaction_required` in GCC High) while any enabled all-apps policy requires MFA
without excluding the **Microsoft Intune Enrollment** app (`d4ebce55-015a-49b5-a083-c84d1797ae8c`).
`Prepare-Tenant.ps1` reports the policies; add the exclusion with `-ExcludeIntuneEnrollmentFromCa` or in
the portal (policy → Target resources → Exclude).

**6. Cloud Shell in PowerShell mode** for the post-deploy scripts — a `pwsh` started from the Bash shell
has no Azure sign-in.

---

## Deploy

> **New to the kit?** Follow the step-by-step implementation guide for your cloud — each walks an
> operator from an empty subscription to Sentinel connectors, analytics rules and UEBA, with screenshots
> from a real run and a troubleshooting table of every error hit on the way:
>
> - [Implementation Guide — Azure Government (GCC High)](docs/IMPLEMENTATION-GOV.md) ([Word](docs/MLZ-Security-Lab-Implementation-Guide-Gov.docx))
> - [Implementation Guide — Azure Commercial](docs/IMPLEMENTATION-COMMERCIAL.md) ([Word](docs/MLZ-Security-Lab-Implementation-Guide-Commercial.docx))

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

# Commercial — pick a region the subscription can create VMs in first (Commercial guide, section 2.4)
./deploy.ps1 -ParametersFile ./params/commercial-lab.json -AzureEnvironment AzureCloud `
  -SubscriptionId <sub-id> -Location westus2
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

Some steps need interactive MFA and are deliberately **not** automated. After the deployment, in a
**PowerShell-mode** Cloud Shell (Gov: `portal.azure.us`; Commercial: `portal.azure.com`):

```powershell
git clone -q https://github.com/lee-aguilar-msft/Azure-MLZStarterKit-Security.git ~/kit
cd ~/kit/templates/scripts
./Post-Deploy.ps1 -Cloud USGov -SubscriptionId <sub> -ResourceGroupName <tier3-rg> `
  -WorkspaceName <prefix>-law-lab -EnableXdrConnector      # Commercial: -Cloud Global
```

It installs the Content Hub solutions, enables every matching analytics rule, UEBA and the Defender XDR
connector, routes the Entra ID and Activity logs, re-asserts the Defender plans, then prints the
checklist for the identity chain:

1. `./Prepare-Tenant.ps1 -Cloud <USGov|Global> -ConfigureMde` — MDM user scope and URLs, the *Microsoft
   Intune Enrollment* service principal, the Conditional Access report (add `-ExcludeIntuneEnrollmentFromCa`
   to apply the exclusion), the Intune ↔ MDE connector, the `LAB-Intune-Devices` group and the EDR policy.
   One toggle has no API: Defender portal → Settings → Endpoints → Advanced features → **Microsoft Intune
   connection = On**.
2. **Entra Connect** on `ms01` (Bastion, the one wizard that needs your MFA), then
   `./Prepare-Tenant.ps1 -Cloud <cloud> -SkipMdm -LabUserUpn <lab user UPN>` to license the synced user.
3. **Hybrid join** — the clients retry on their own every 30 minutes; `dsregcmd /join` through Run command
   (or `Invoke-HybridJoinCycle.ps1` on `ms01`) does it at once.
4. The lab user registers **MFA** once and signs in once to each client — the auto-enrollment GPO then
   enrolls it in Intune and the EDR policy onboards it to Defender for Endpoint.

Both implementation guides walk through every step with the real output and a troubleshooting table.

---

## Destroy (teardown)

`destroy.ps1` discovers every resource group by the MLZ naming prefix and deletes them in parallel —
this removes the hub RGs **and** the tier3 RG containing all VMs, the workspace, DCRs, the Arc Private
Link Scope, private endpoints and private DNS zones, the CSPM resources and the content-script managed
identity. Optional flags reset Defender plans, remove policy assignments, and delete the Entra group.

```powershell
Invoke-WebRequest -Uri "https://raw.githubusercontent.com/lee-aguilar-msft/Azure-MLZStarterKit-Security/main/destroy.ps1" -OutFile destroy.ps1
./destroy.ps1 -SubscriptionId <sub> -Identifier lab -EnvironmentAbbreviation dev `
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
- **Entra Connect** is interactive (MFA) and staged, not automated; hybrid join and Intune enrollment are
  automatic once the sync, the licence and the Conditional Access exclusion are in place.
- **MDI** (Defender for Identity) sensors are intentionally **out of scope** — installed separately.
- SLES/RHEL/Ubuntu use PAYG marketplace images; if your subscription requires a plan acceptance for a
  given image, accept it (or adjust the image reference) before deploying.
- The CSPM **Azure SQL** sample can be switched off (`deployCspmSql`). New or dev subscriptions are sometimes
  not yet enabled for SQL in a region (`Location 'USGov Virginia' is not accepting creation of new Windows
  Azure SQL Database servers at this time`) — open a support request for the SQL offer, or skip the sample.
- The CSPM API Management sample defaults to the **Developer** SKU (works in Azure Government; ~30–45 min
  to provision, ~$50/mo). Set `cspmApimSku` to `BasicV2`/`StandardV2` for minutes-fast provisioning where
  those tiers are available, or `deployCspmApiManagement = false` to skip it.
- **Defender for DNS** is no longer offered as a standalone plan (Microsoft retired it; DNS threat detection
  now ships inside Defender for Servers / CSPM), so the kit does not enable it. **Defender for APIs**
  needs an explicit sub-plan — the kit sets `defenderForApisSubPlan = P1` (up to 1M calls/month).
- The standalone **DoD IL5** regulatory initiative has been retired by Microsoft, so the kit assigns the
  **Microsoft cloud security benchmark** (`deployMcsb`, the Defender CSPM baseline) instead, alongside the
  optional NIST 800-53 R5 / 800-171 R2 initiatives. All three exist in Azure Government.
- **RHEL PAYG images update from Azure RHUI** (`rhui-*.microsoft.com` / `rhui4-*.microsoft.com`); the lab
  firewall rules allow it. Without that egress the AADSSHLoginForLinux extension fails on RHEL
  (`Failed to download metadata for repo 'rhui-microsoft-azure-rhel9'`). A `prep-linux` run-command also
  waits for cloud-init / the package lock before the Entra SSH and AMA extensions install on every Linux VM.
- The portal form is **cloud-aware**: when a `usgov*`/`usdod*` region is selected it hides what Azure
  Government does not offer (Defender for App Service, Defender for APIs, commercial-only VM sizes) and
  derives the `.us`/`.com` endpoint set from the region automatically.
- The Arc Private Link Scope uses a preview API version; keep `deployArcPrivateLink = false` if your
  subscription/region doesn't expose it yet.
