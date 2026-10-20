import time
from cloudguard.core.config import settings
from cloudguard.models.finding import Finding

class RemediationService:
    """Only narrow, explicit actions are implemented. High-risk actions must enter approval first."""
    def execute(self, finding: Finding, subscription_id: str, approved: bool = False) -> dict:
        if finding.severity in {"High", "Critical"} and not approved:
            raise PermissionError("High-risk remediation requires explicit Security Officer approval")
        if finding.rule_id == "CG-NSG-001" and not approved:
            raise PermissionError("NSG administrative-rule remediation requires explicit Security Officer approval")
        if finding.status in {"remediated", "excepted"}:
            return {"status": "noop", "message": "Finding is already resolved or excepted"}
        if settings.azure_mode.lower() == "azure" and finding.rule_id not in {"CG-TAG-001", "CG-NSG-001"}:
            raise RuntimeError("Live remediation for this rule is intentionally disabled; use manual remediation runbook")
        last_error = None
        for attempt in range(1, settings.retry_limit + 1):
            try:
                if settings.azure_mode.lower() != "azure":
                    # Mock mode is deterministic and never changes an actual Azure resource.
                    result = {"status": "succeeded", "mode": "mock", "action": self._action_for(finding), "attempt": attempt}
                else:
                    result = self._execute_azure(finding, subscription_id, approved)
                return result
            except Exception as exc:
                last_error = exc
                if attempt < settings.retry_limit:
                    time.sleep(settings.retry_base_seconds * (2 ** (attempt - 1)))
        raise RuntimeError(f"Remediation failed after {settings.retry_limit} attempts: {type(last_error).__name__}") from last_error
    def _action_for(self, finding):
        if finding.rule_id == "CG-TAG-001": return "add_required_tags"
        if finding.rule_id == "CG-NSG-001": return "remove_open_admin_rule_after_approval"
        if finding.rule_id == "CG-DISK-001": return "flag_unattached_disk_for_manual_review"
        return "manual_review"
    def _execute_azure(self, finding, subscription_id, approved=False):
        # Low-risk remediation is limited to applying default governance tags. Destructive NSG changes are intentionally not automated in this MVP adapter.
        from azure.identity import DefaultAzureCredential, ClientSecretCredential
        from azure.mgmt.resource import ResourceManagementClient
        if finding.rule_id == "CG-NSG-001":
            if not approved: raise PermissionError("NSG rule changes require explicit approval")
            from azure.mgmt.network import NetworkManagementClient
            if not finding.details.get("rule_name"): raise RuntimeError("Finding is missing the exact NSG rule name; refusing broad modification")
            if settings.azure_client_id and settings.azure_client_secret and settings.azure_tenant_id:
                credential = ClientSecretCredential(tenant_id=settings.azure_tenant_id, client_id=settings.azure_client_id, client_secret=settings.azure_client_secret)
            else: credential = DefaultAzureCredential()
            parts = finding.resource_id.split("/")
            try: rg = parts[parts.index("resourceGroups") + 1]
            except (ValueError, IndexError): raise RuntimeError("Cannot determine resource group from NSG resource ID")
            nsg_name = parts[-1]
            client = NetworkManagementClient(credential, subscription_id)
            nsg = client.network_security_groups.get(rg, nsg_name)
            rules = list(nsg.security_rules or [])
            target = next((r for r in rules if r.name == finding.details["rule_name"]), None)
            if target is None: return {"status":"noop", "mode":"azure", "action":"nsg_rule_already_absent"}
            sources = list(getattr(target, "source_address_prefixes", None) or [])
            if getattr(target, "source_address_prefix", None): sources.append(target.source_address_prefix)
            ports = list(getattr(target, "destination_port_ranges", None) or [])
            if getattr(target, "destination_port_range", None): ports.append(target.destination_port_range)
            risky_source = any(x in {"*", "0.0.0.0/0", "Internet", "Any"} for x in sources)
            risky_port = any(x in {"22", "3389", "*"} for x in ports)
            if str(target.direction).lower() != "inbound" or str(target.access).lower() != "allow" or not risky_source or not risky_port:
                raise RuntimeError("NSG rule no longer matches the approved risk; refusing modification")
            nsg.security_rules = [r for r in rules if r.name != target.name]
            client.network_security_groups.begin_create_or_update(rg, nsg_name, nsg).result()
            return {"status":"succeeded", "mode":"azure", "action":"remove_approved_open_admin_rule", "rule_name":target.name}
        if finding.rule_id != "CG-TAG-001":
            raise RuntimeError("Live remediation for this rule is intentionally disabled; use manual remediation runbook")
        if settings.azure_client_id and settings.azure_client_secret and settings.azure_tenant_id:
            credential = ClientSecretCredential(tenant_id=settings.azure_tenant_id, client_id=settings.azure_client_id, client_secret=settings.azure_client_secret)
        else: credential = DefaultAzureCredential()
        client = ResourceManagementClient(credential, subscription_id)
        current = client.resources.get_by_id(finding.resource_id, api_version="2021-04-01")
        tags = dict(getattr(current, "tags", None) or {})
        missing_tags = finding.details.get("missing_tags", ["Environment", "Owner"])
        still_missing = [tag for tag in missing_tags if not tags.get(tag)]
        if not still_missing:
            return {"status":"noop", "mode":"azure", "action":"resource_already_compliant"}
        for tag in still_missing:
            default_value = "unknown"
            if tag == "Owner": default_value = "cloudguard"
            tags.setdefault(tag, default_value)
        client.resources.begin_update_by_id(finding.resource_id, "2021-04-01", {"tags": tags}).result()
        return {"status":"succeeded", "mode":"azure", "action":"add_required_tags"}
