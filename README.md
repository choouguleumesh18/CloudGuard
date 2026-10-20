# CloudGuard — Enhanced Capstone Implementation

CloudGuard is a FastAPI/PostgreSQL Azure compliance and remediation API. This iteration adds JWT authentication, role-based authorization, remediation approvals, time-bound exceptions, hash-chained audit records, Azure Resource Manager inventory, a safe mock mode, Docker/Kubernetes assets, CLI, and CI workflows.

## Current implementation status

- Implemented: JWT login/me, Admin-managed users, roles (`Admin`, `CloudEngineer`, `SecurityOfficer`, `AutomationService`); authenticated scan/findings APIs; Admin-only subscription/policy management; high-risk approval queue; low-risk tag remediation; time-bound finding exceptions; audit event chain and verification endpoint; mock and Azure inventory adapters; rules for required tags, open admin NSG ports, unattached disks, Azure Monitor VM CPU metrics, and Key Vault secret expiry metadata; CLI; Alembic migrations; Docker Compose; Kubernetes Job/CronJob templates; CI and AKS deployment workflows.
- Deliberate safety boundary: live remediation supports required tags and removal of the exact risky NSG rule only after approval. VM deallocation, disk deletion, and secret rotation remain manual-review actions. In mock mode actions are simulated and never change Azure.
- Production hardening still required before exposure: run Alembic migrations rather than `create_all`, use Entra ID/OAuth validation or rotate JWT secret securely, seed admin password via secret store, enable immutable external audit storage, use managed identity/workload identity, configure TLS/network controls, and complete live Azure tests.

## Run locally (Windows PowerShell)

1. Extract the ZIP and open the `CloudGuard` folder in VS Code.
2. Copy `.env.example` to `.env`. Set a strong unique `JWT_SECRET` and `BOOTSTRAP_ADMIN_PASSWORD`. For local PostgreSQL, set `POSTGRES_PASSWORD` in your shell to the same password in `DATABASE_URL`.
3. Start the database: `docker compose up -d postgres`
4. Create a venv and install packages:

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
pip install -r requirements.txt
$env:PYTHONPATH = "src"
pytest
uvicorn cloudguard.main:app --reload --app-dir src
```

Alternatively, `docker compose up --build` starts PostgreSQL and the API container. With `AUTO_CREATE_SCHEMA=true`, the first startup creates the schema and seeds a local Admin user. In deployed environments, set `AUTO_CREATE_SCHEMA=false` and run `alembic upgrade head` through the migration Job. Do not expose bootstrap behavior publicly.

Swagger: http://127.0.0.1:8000/docs

## First API flow

1. `POST /api/v1/auth/login` with `{"username":"admin","password":"<BOOTSTRAP_ADMIN_PASSWORD>"}`.
2. Click **Authorize** in Swagger and enter `Bearer <access_token>`.
3. `POST /api/v1/scans` with `{"subscription_id":"mock-subscription-001"}` in mock mode.
4. `GET /api/v1/findings` to view results.
5. For a low-risk finding, `POST /api/v1/findings/{id}/remediate` simulates safe tagging remediation in mock mode; set `AUTO_REMEDIATE_LOW_RISK=true` to enable scan-time auto-remediation for missing tags.
6. For High/Critical finding, the same endpoint creates a pending approval. A `SecurityOfficer` or Admin lists `/api/v1/approvals` and posts `{"decision":"approve","note":"Reviewed change"}` to `/api/v1/approvals/{request_id}/decision`. In mock mode the action is simulated; in Azure mode tag updates and exact approved NSG-rule removal are implemented.
7. Admin can inspect `/api/v1/audit-logs` and verify the hash chain using `/api/v1/audit-logs/verify`.

## Azure-side configuration

### Identity (recommended)

For local development use `az login` and `DefaultAzureCredential`. For Azure-hosted deployment, enable a system-assigned or user-assigned managed identity on the workload and assign the least-privilege role at the intended subscription/resource-group scope. Reader is enough for inventory; tagging remediation needs a custom role or narrowly scoped role that grants resource read plus tag update/write. Do not grant Owner or Contributor broadly just to make the demo work.

To test service-principal authentication, configure `AZURE_TENANT_ID`, `AZURE_CLIENT_ID`, and `AZURE_CLIENT_SECRET` via environment/Key Vault (never commit them). Set `AZURE_MODE=azure`, register the target subscription using an Admin, and ensure the identity has Reader plus the narrow tag-write permission at the subscription/resource-group scope. The secret credential path is optional; managed identity is preferred in Azure.

### Suggested Azure resources

- A non-production resource group/subscription with a few tagged/untagged test resources, one test NSG rule, an unattached test disk, and a test Key Vault with non-sensitive test secrets.
- Azure Container Registry (ACR) to store images.
- Azure Kubernetes Service (AKS) for the strict Kubernetes-job requirement, or local kind/Minikube for development. Azure Container Apps is an alternative deployment target, but does not itself satisfy the Kubernetes-worker acceptance criterion.
- Azure Database for PostgreSQL Flexible Server for production data, private networking where feasible, TLS enforced.
- Azure Key Vault for runtime secrets; workload identity/managed identity grants access to only the required secrets.
- GitHub Actions federated credential in Microsoft Entra ID for OIDC login; avoid long-lived service-principal secrets in GitHub.

### Azure permissions checklist

1. In Entra ID, create/use a managed identity or app registration for CloudGuard; prefer managed identity for runtime and federated credentials for GitHub Actions.
2. Because the adapter lists resources across the subscription, grant read-only `Reader` at subscription scope. For live tag remediation, grant only the required tag/resource permissions through a custom role scoped to a sandbox resource group. Avoid subscription-wide write permissions.
3. Register the subscription in CloudGuard via `POST /api/v1/subscriptions` with Admin JWT.
4. Configure `AZURE_MODE=azure`; for local dev, `az login` then set tenant/subscription context. For managed identity, deploy the app in Azure and let `DefaultAzureCredential` use it.
5. Test only in a sandbox. The live adapter fetches resource inventory, NSG rules, VM CPU metrics and Key Vault secret metadata. It can apply missing tags and remove the exact risky NSG rule only after explicit approval; it does not delete disks, stop VMs or rotate secrets.

## CI/CD

`.github/workflows/ci.yml` runs Ruff, Python compilation, mypy, pytest/coverage and a Docker build on pushes/PRs. `.github/workflows/deploy-aks.yml` is a manually triggered AKS staging deployment using GitHub OIDC; it builds/pushes an immutable image, applies a database migration Job, and deploys the API and scheduled scan CronJob. Set the repository staging environment secrets and pre-create ACR/AKS/PostgreSQL before enabling. Kubernetes manifests are templates; configure the user-assigned managed identity and secret-management integration before deployment.

## API role summary

- Public: `GET /api/v1/health`, `POST /api/v1/auth/login`
- Authenticated: `/auth/me`, scans, findings, subscription/policy listing
- Admin only: user management, create subscriptions/policies, audit logs/verification
- Admin or Cloud Engineer: request remediation; create finding exception
- Admin or Security Officer: list/decide high-risk approval requests

## Acceptance criteria status

| Criterion | Status in this build | Evidence / remaining work |
|---|---|---|
| AC-001 scan inventory + findings | Implemented in mock; Azure adapter added | Run against a sandbox subscription to verify Azure permissions and resource coverage |
| AC-002 low-risk auto-remediation + audit | Mock action and audit implemented; Azure tag remediation implemented | Confirm tag-write permissions in sandbox |
| AC-003 high-risk approval before execution | Implemented | High/Critical creates pending request; not executed until approved |
| AC-004 time-bound exception | Implemented | Expiry is stored and active exceptions are excluded on later scans; expiry re-evaluation is time-based |
| AC-005 failed scheduled scan visible | Scan failure status/error field and API implemented | CronJob is a template; deploy and exercise it in Kubernetes |
| AC-006 retry with backoff | Bounded exponential retry wrapper implemented | Needs injected-failure test and live throttling test before production claim |
| AC-007 idempotent remediation | Resolved findings return no-op | Azure resource re-read/verification should be added before claiming production-grade idempotency |
| AC-008 unauthorized approval denied | Role dependency implemented | Security Officer/Admin only; test with Cloud Engineer token |
| FR-001–018 | Partial-to-implemented | Subscription/policy management, scan/approval workers as Kubernetes Jobs, CronJob schedule, audit and Azure inventory adapters are included; reporting analytics, true Entra ID user sign-in, and live AKS/Azure validation remain follow-up work |

## Important notes

- This ZIP is a development baseline, not a certified production security product.
- Audit hashes are tamper-evident for ordinary modification, but an attacker with database write access could rewrite the chain. For stronger guarantees, export to immutable storage / Azure Monitor and restrict DB permissions.
- Alembic migrations are included (`alembic upgrade head`); validate the Azure SDK behavior against your chosen API versions and run all acceptance tests in a sandbox subscription before production.
