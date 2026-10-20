from pathlib import Path
import json
import time
from typing import Any
from cloudguard.core.config import settings

FIXTURE = Path(__file__).resolve().parents[1] / "fixtures" / "azure_resources.json"


class AzureInventory:
    """Azure inventory adapter. Mock mode is safe for local development; Azure mode uses DefaultAzureCredential."""

    def __init__(self, subscription_id: str):
        self.subscription_id = subscription_id

    def list_resources(self) -> list[dict[str, Any]]:
        if settings.azure_mode.lower() != "azure":
            data = json.loads(FIXTURE.read_text(encoding="utf-8"))
            resources = data.get("resources", data) if isinstance(data, dict) else data
            normalized = []
            for raw in resources:
                item = dict(raw)
                item["type"] = item.get("type") or item.get("resource_type") or ""
                props = dict(item.get("properties") or {})
                if "security_rules" in item:
                    props["securityRules"] = [
                        {
                            "name": rule.get("name"),
                            "direction": rule.get("direction"),
                            "access": rule.get("access"),
                            "protocol": rule.get("protocol"),
                            "sourceAddressPrefix": rule.get("source_address_prefix"),
                            "sourceAddressPrefixes": rule.get("source_address_prefixes"),
                            "destinationPortRange": rule.get("destination_port_range"),
                            "destinationPortRanges": rule.get("destination_port_ranges"),
                        }
                        for rule in item.pop("security_rules")
                    ]
                item["properties"] = props
                normalized.append(item)
            return normalized

        last_error = None
        for attempt in range(1, settings.retry_limit + 1):
            try:
                return self._list_azure_resources()
            except Exception as exc:
                last_error = exc
                if attempt < settings.retry_limit:
                    time.sleep(settings.retry_base_seconds * (2 ** (attempt - 1)))
        raise RuntimeError(f"Azure inventory failed after {settings.retry_limit} attempts: {type(last_error).__name__}") from last_error

    def _credential(self):
        from azure.identity import DefaultAzureCredential, ClientSecretCredential
        if settings.azure_client_id and settings.azure_client_secret and settings.azure_tenant_id:
            return ClientSecretCredential(tenant_id=settings.azure_tenant_id, client_id=settings.azure_client_id, client_secret=settings.azure_client_secret)
        return DefaultAzureCredential()

    def _list_azure_resources(self) -> list[dict[str, Any]]:
        from azure.mgmt.resource import ResourceManagementClient
        credential = self._credential()
        client = ResourceManagementClient(credential, self.subscription_id)
        resources = []
        for resource in client.resources.list():
            item = {
                "id": resource.id,
                "name": resource.name,
                "type": resource.type,
                "location": resource.location,
                "tags": resource.tags or {},
                "properties": getattr(resource, "properties", None) or {},
            }
            resource_type = str(resource.type).lower()
            if resource_type == "microsoft.network/networksecuritygroups":
                item["properties"] = self._get_nsg_properties(credential, resource)
            elif resource_type == "microsoft.compute/virtualmachines":
                item["properties"] = self._get_vm_properties(credential, resource, item["properties"])
            elif resource_type == "microsoft.keyvault/vaults":
                item["properties"] = self._get_keyvault_properties(credential, resource, item["properties"])
            resources.append(item)
        return resources

    def _get_nsg_properties(self, credential, resource):
        from azure.mgmt.network import NetworkManagementClient
        parts = resource.id.split("/")
        try:
            resource_group = parts[parts.index("resourceGroups") + 1]
            client = NetworkManagementClient(credential, self.subscription_id)
            nsg = client.network_security_groups.get(resource_group, resource.name)
            rules = []
            for rule in nsg.security_rules or []:
                rules.append(
                    {
                        "name": rule.name,
                        "direction": rule.direction,
                        "access": rule.access,
                        "protocol": rule.protocol,
                        "sourceAddressPrefix": rule.source_address_prefix,
                        "sourceAddressPrefixes": rule.source_address_prefixes,
                        "destinationPortRange": rule.destination_port_range,
                        "destinationPortRanges": rule.destination_port_ranges,
                        "priority": rule.priority,
                    }
                )
            return {"securityRules": rules, "resourceGroup": resource_group}
        except Exception as exc:
            return {"securityRules": [], "inventoryWarning": f"Unable to load NSG rules: {type(exc).__name__}"}

    def _get_vm_properties(self, credential, resource, properties):
        """Attach 7-day average CPU metric when Azure Monitor access is available."""
        try:
            from datetime import timedelta
            from azure.monitor.query import MetricsQueryClient, MetricAggregationType
            client = MetricsQueryClient(credential)
            result = client.query_resource(
                resource.id,
                metric_names=["Percentage CPU"],
                timespan=timedelta(days=7),
                granularity=timedelta(days=1),
                aggregations=[MetricAggregationType.AVERAGE],
            )
            values = []
            for metric in result.metrics:
                for series in metric.timeseries:
                    for point in series.data:
                        if point.average is not None:
                            values.append(float(point.average))
            if values:
                properties["averageCpuPercent7d"] = sum(values) / len(values)
        except Exception as exc:
            properties["inventoryWarning"] = f"CPU metrics unavailable: {type(exc).__name__}"
        return properties

    def _get_keyvault_properties(self, credential, resource, properties):
        """Read only secret metadata (never values) to identify expiries within 30 days."""
        vault_url = properties.get("vaultUri") or properties.get("vault_uri")
        if not vault_url:
            properties["inventoryWarning"] = "Key Vault URI unavailable; secret expiry was not evaluated"
            return properties
        try:
            from azure.keyvault.secrets import SecretClient
            client = SecretClient(vault_url=vault_url, credential=credential)
            secrets = []
            for item in client.list_properties_of_secrets():
                secrets.append({"name": item.name, "expiresOn": item.expires_on.isoformat() if item.expires_on else None})
            properties["secrets"] = secrets
        except Exception as exc:
            properties["inventoryWarning"] = f"Key Vault metadata unavailable: {type(exc).__name__}"
        return properties
