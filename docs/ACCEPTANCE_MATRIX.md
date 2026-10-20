# Acceptance Criteria Validation

Validation run in the build workspace: `python -m compileall -q src tests` and `python -m pytest -q`.

Latest local test run: **26 tests passed**. Targeted coverage reported by pytest-cov: compliance rules 92%; remediation service 91%; combined targeted modules 91%. Azure SDK behavior is mocked in unit tests; this does not replace a sandbox Azure integration run. CI workflow itself has not been run from a GitHub repository in this workspace.

| SRS acceptance criterion | Implementation | Test / validation | Status |
|---|---|---|---|
| AC-001 inventory and findings | Mock fixture or Azure Resource Manager inventory; tag, NSG, disk, VM CPU metric and Key Vault expiry rules | `test_mock_scan_generates_findings...`; fixture normalization test | Implemented; live subscription still to validate |
| AC-002 low-risk auto-remediation and audit | Optional `AUTO_REMEDIATE_LOW_RISK=true` for low-risk tag findings; `/findings/{id}/remediate`; audit events; live tag update | mock remediation and mocked Azure tag SDK tests | Implemented, gated by config for scan-time auto-remediation |
| AC-003 high-risk approval required | High/Critical requests enter `pending_approval`; Security Officer/Admin approval required before execution; Azure NSG rule revalidated before removal | `test_auth_rbac_approval_and_audit_chain`; NSG SDK unit test | Implemented |
| AC-004 time-bound exception | Exception requires future expiry; rescan checks active exceptions for same resource and rule; expiry causes it to stop suppressing findings | `test_mock_scan_generates_findings_and_time_bound_exception_is_applied_on_rescan` | Active exception behavior tested; expiry-boundary test should be added before production |
| AC-005 failed scheduled scan visible | Scan status/error fields exposed by scan API; Kubernetes CronJob triggers scheduled scan; worker marks failed status | scan model/API path and K8s manifests inspected; failure injection not end-to-end tested | Partial: failure status implemented, schedule needs AKS validation |
| AC-006 retries with exponential backoff | Configurable retry limit/base delay in remediation service | retry and exhaustion tests | Implemented for remediation adapter; Azure throttling integration not tested |
| AC-007 idempotent remediation | Already remediated/excepted finding returns `noop`; approved NSG rule missing at execution time returns `noop` | `test_already_resolved_is_noop`; NSG adapter rechecks target rule | Implemented at action level; live rescan idempotency to verify in sandbox |
| AC-008 unauthorized approval denied | Approval endpoints require Admin or SecurityOfficer role | engineer token receives HTTP 403 in integration test | Implemented and tested |

## Important validation boundary

- Mock-mode tests validate business flow, not Azure role assignments, SDK API-version behavior, network connectivity, or actual resource changes.
- Kubernetes manifests and GitHub Actions deployment are templates. The workflow needs Azure OIDC, ACR, AKS, database connectivity, workload identity, and GitHub environment secrets configured before it can deploy.
- For full sign-off, run the acceptance demo in a dedicated sandbox Azure subscription and staging AKS namespace, record screenshots/logs, and test a failure case for each worker.
