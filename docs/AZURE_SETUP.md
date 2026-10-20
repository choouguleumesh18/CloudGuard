# CloudGuard Azure Setup Runbook

This runbook configures **read-only inventory first** and only then enables narrowly scoped remediation. Run against a sandbox subscription/resource group before any shared environment.

## 0. Decide the deployment path

- Local laptop + Azure subscription: Azure CLI login and `DefaultAzureCredential`; PostgreSQL can remain Docker-local.
- Azure-hosted API: Azure managed identity / AKS workload identity; Azure Database for PostgreSQL; Key Vault for secrets.
- GitHub Actions: Microsoft Entra workload identity federation (OIDC); no client secret in GitHub.
- Kubernetes acceptance criterion: use AKS or local kind/Minikube. Container Apps is an alternate hosting option, not a substitute for the SRS Kubernetes Job/CronJob requirement.

## 1. Confirm subscription and create a sandbox resource group

```bash
az login
az account list --output table
az account set --subscription "<SUBSCRIPTION_ID>"
az account show --output table
az group create --name rg-cloudguard-sandbox --location eastus
```

Replace `eastus` with a region available to your subscription. Avoid using production resources for remediation tests.

## 1A. Optional Azure resources for a staging deployment (billable)

Only run these commands if you intend to create billable Azure resources. Names such as ACR and Key Vault must be globally unique. Review pricing and cleanup instructions before creating AKS, PostgreSQL or other hosted resources.

```bash
# Register providers if your subscription has not used these services before.
az provider register --namespace Microsoft.ContainerService
az provider register --namespace Microsoft.ContainerRegistry
az provider register --namespace Microsoft.DBforPostgreSQL
az provider register --namespace Microsoft.KeyVault
az provider register --namespace Microsoft.Insights

# Container Registry. Replace the registry name with a globally unique lowercase name.
az acr create --resource-group rg-cloudguard-sandbox --name <UNIQUE_ACR_NAME> --sku Basic

# AKS with OIDC issuer and workload identity. Node VMs and related resources incur charges.
az aks create --resource-group rg-cloudguard-sandbox --name aks-cloudguard-staging --location eastus --node-count 1 --enable-oidc-issuer --enable-workload-identity --attach-acr <UNIQUE_ACR_NAME> --generate-ssh-keys

# Key Vault for secret references; create a unique vault name and use Azure RBAC authorization.
az keyvault create --resource-group rg-cloudguard-sandbox --name <UNIQUE_KEYVAULT_NAME> --location eastus --enable-rbac-authorization true
```

For Azure Database for PostgreSQL Flexible Server, create a server and database using the portal or Azure CLI with your organization's approved private-networking pattern. Configure the AKS VNet/subnet, DNS and firewall/private endpoint rules so only the CloudGuard workload can reach PostgreSQL. Do not open PostgreSQL to `0.0.0.0/0`. Set `DATABASE_URL` to the server's TLS-enabled connection string and test connectivity from the AKS namespace before deployment.

For the GitHub deployment identity, grant `AcrPush` only on the ACR, and the required AKS cluster-user plus namespace deployment permissions only on the staging cluster. Prefer a dedicated staging namespace and restricted Kubernetes RBAC; do not grant subscription-wide Contributor just to make CI/CD work. The exact Azure RBAC assignments depend on whether your AKS cluster uses Azure RBAC for Kubernetes authorization or Kubernetes-native RBAC.

## 2. Local Azure CLI authentication (read-only first)

Install Azure CLI and sign in with an account that can read the sandbox resources:

```bash
az login
az account set --subscription "<SUBSCRIPTION_ID>"
az account get-access-token --resource https://management.azure.com/ --query expiresOn -o tsv
```

Set `.env`:

```dotenv
AZURE_MODE=azure
AZURE_DEFAULT_SUBSCRIPTION_ID=<SUBSCRIPTION_ID>
# Leave AZURE_TENANT_ID/AZURE_CLIENT_ID/AZURE_CLIENT_SECRET blank when using az login locally.
```

`DefaultAzureCredential` will attempt the local Azure CLI credential. The identity must have Azure RBAC `Reader` at the target subscription or resource group. Use `AZURE_MODE=mock` for the default local demo.

## 3. Create a runtime managed identity (recommended for Azure hosting)

Example user-assigned managed identity:

```bash
az identity create --name id-cloudguard-runtime --resource-group rg-cloudguard-sandbox --location eastus
az identity show --name id-cloudguard-runtime --resource-group rg-cloudguard-sandbox --query '{clientId:clientId,principalId:principalId,id:id}' -o json
```

Save the `clientId`, `principalId`, and resource ID. Attach the identity to the host (AKS workload identity or supported Azure compute). For AKS workload identity, enable OIDC issuer/workload identity on the cluster and create a federated credential whose subject is `system:serviceaccount:cloudguard:cloudguard-automation`. The K8s service account must be annotated with the user-assigned identity client ID and the pod template must have `azure.workload.identity/use: "true"`.

Assign **Reader** at the smallest practical scope first:

```bash
az role assignment create --assignee-object-id "<MANAGED_IDENTITY_PRINCIPAL_ID>" --assignee-principal-type ServicePrincipal --role Reader --scope "/subscriptions/<SUBSCRIPTION_ID>"
```

For VM idle detection, also grant Monitoring Reader (or a custom role containing `Microsoft.Insights/metrics/read`) at the same sandbox scope. For Key Vault expiry metadata, grant a custom data-plane role that permits listing secret metadata only, or use an organization-approved role with equivalent limited permissions. Do not grant secret-value read access unless it is explicitly required; this implementation reads expiry metadata, not secret values.

## 4. Least-privilege tag remediation

Start in read-only mode. When ready to test low-risk remediation, create a custom role based on the minimum actions your subscription supports. The following is a starting template; validate operations against your Azure environment and test at resource-group scope:

```json
{
  "Name": "CloudGuard Tag Remediator (Sandbox)",
  "IsCustom": true,
  "Description": "Read resources and update tags for CloudGuard low-risk remediation only.",
  "Actions": [
    "Microsoft.Resources/subscriptions/resources/read",
    "Microsoft.Resources/tags/read",
    "Microsoft.Resources/tags/write"
  ],
  "NotActions": [],
  "DataActions": [],
  "NotDataActions": [],
  "AssignableScopes": ["/subscriptions/<SUBSCRIPTION_ID>/resourceGroups/rg-cloudguard-sandbox"]
}
```

Save as `cloudguard-tag-remediator.json`, replace the subscription ID, then run:

```bash
az role definition create --role-definition @cloudguard-tag-remediator.json
az role assignment create --assignee-object-id "<MANAGED_IDENTITY_PRINCIPAL_ID>" --assignee-principal-type ServicePrincipal --role "CloudGuard Tag Remediator (Sandbox)" --scope "/subscriptions/<SUBSCRIPTION_ID>/resourceGroups/rg-cloudguard-sandbox"
```

The exact tag permissions can vary with the API path used by Azure Resource Manager. If the operation fails, inspect the Azure Activity Log and adjust only the missing operation; do not solve permission errors by assigning Owner/Contributor broadly.

For approved NSG remediation, the runtime identity additionally needs a narrowly scoped network permission to read and update NSGs in the sandbox. The code rechecks the approved rule's name, direction, access, source and destination ports immediately before removing that one rule. Validate role operations and behavior with a non-critical test NSG first.

## 5. Register a subscription in CloudGuard

Start the API, login as the bootstrap Admin, then use Swagger `POST /api/v1/subscriptions`:

```json
{
  "subscription_id": "<SUBSCRIPTION_ID>",
  "name": "CloudGuard Sandbox",
  "environment": "dev"
}
```

For mock mode, the bundled fixture IDs `mock-subscription-001` and `mock-subscription-002` are accepted without registration. For Azure mode, register your actual subscription.

## 6. Azure resource coverage

- Tags: inventory resource tags; low-risk remediation fills missing `Environment=unknown` and `Owner=cloudguard` values. Adjust defaults to your organization's tag policy before enabling it.
- NSGs: reads NSG rules and detects inbound Allow rules exposing ports 22/3389 (or `*`) to broad sources. Live removal is available only through an approved request.
- Disks: detects disks with no `managedBy` resource and flags them for review. It does not delete disks.
- Idle VMs: reads Azure Monitor `Percentage CPU` metrics over seven days when metrics permission is available. Low CPU is a flag only; it does not stop VMs.
- Key Vault: lists secret metadata/expiry dates only. It never reads secret values and does not rotate/delete secrets.

If a resource type is unsupported or its metadata cannot be read, inspect the scan/audit records and Azure Activity Log. A warning is not the same as a compliant result.

## 7. Azure data services and secret storage (production path)

Recommended production components:

1. Azure Database for PostgreSQL Flexible Server, TLS enforced, private networking where practical, backups enabled.
2. Azure Key Vault for runtime secrets such as database URL and JWT signing secret.
3. Managed identity / workload identity to read only the required Key Vault secret names.
4. Azure Monitor / Log Analytics for centralized app and platform logs. Export audit events to a separately controlled immutable store for stronger tamper resistance.
5. ACR for container images; enable managed identity pull (`AcrPull`) for AKS.

Do not commit `.env`, database passwords, client secrets, JWT secrets, or Kubernetes secret YAML files. The `k8s/` files intentionally do not include a Secret object with real values.

## 8. GitHub Actions OIDC for deployment

Create or use a Microsoft Entra application or user-assigned managed identity for GitHub deployment. Add a federated identity credential restricted to the exact repository and branch/environment; use audience `api://AzureADTokenExchange`. Assign only the permissions needed to push to ACR and deploy to the staging AKS cluster/resource group. Prefer GitHub Environment protection and approval for staging/prod deployments.

Create GitHub Environment `staging` and add these secrets/variables:

- `AZURE_CLIENT_ID`: GitHub deployment federated identity client ID
- `AZURE_RUNTIME_CLIENT_ID`: user-assigned managed identity client ID used by AKS pods
- `AZURE_TENANT_ID`: Entra tenant ID
- `AZURE_SUBSCRIPTION_ID`: target subscription ID
- `ACR_NAME`: Azure Container Registry resource name
- `ACR_LOGIN_SERVER`: e.g. `myregistry.azurecr.io`
- `AKS_RESOURCE_GROUP`, `AKS_CLUSTER_NAME`: staging AKS target
- `DATABASE_URL`, `JWT_SECRET`, `BOOTSTRAP_ADMIN_PASSWORD`: deployment runtime secrets (prefer Key Vault references instead of GitHub storage where possible)
- `AUTOMATION_USERNAME`, `AUTOMATION_PASSWORD`: dedicated CloudGuard user with role `AutomationService`, used by the scheduled-scan job to log in and request scans

Official guidance: [Microsoft Learn: Azure OIDC for GitHub Actions](https://learn.microsoft.com/en-us/azure/developer/github/connect-from-azure-openid-connect) and [GitHub: Configure OIDC in Azure](https://docs.github.com/en/actions/how-tos/secure-your-work/security-harden-deployments/oidc-in-azure).

## 9. Validate in this order

1. `AZURE_MODE=mock`: test login, role denial, scans, findings, approval and audit verification.
2. Azure mode with Reader only: run scan and verify inventory; remediation must fail safely if not authorized.
3. Add scoped tag permission: test tag remediation on a disposable resource.
4. Create a test NSG with a deliberately open test rule in a sandbox; request remediation, approve as Security Officer, and confirm only that named rule is removed.
5. Check Azure Activity Log, CloudGuard audit chain, and scan status after each step.
6. Only then configure AKS, CronJob, OIDC deployment and staging secrets.
