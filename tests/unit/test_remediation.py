from types import SimpleNamespace
import pytest
from cloudguard.services.remediation_service import RemediationService

def finding(severity="High",status="open",rule_id="CG-NSG-001"):
    return SimpleNamespace(severity=severity,status=status,rule_id=rule_id,resource_id="/subscriptions/mock/resourceGroups/rg/providers/Microsoft.Network/networkSecurityGroups/nsg1",details={"rule_name":"open-ssh"})

def test_high_risk_requires_approval():
    with pytest.raises(PermissionError): RemediationService().execute(finding(),"mock-subscription-001")

def test_already_resolved_is_noop():
    result=RemediationService().execute(finding("Low","remediated","CG-TAG-001"),"mock-subscription-001")
    assert result["status"]=="noop"

def test_low_risk_mock_tag_remediation():
    result=RemediationService().execute(finding("Low","open","CG-TAG-001"),"mock-subscription-001")
    assert result["status"]=="succeeded" and result["mode"]=="mock"

def test_low_risk_disk_routes_to_manual_review_in_mock(monkeypatch):
    result=RemediationService().execute(finding("Low","open","CG-DISK-001"),"mock-subscription-001")
    assert result["status"]=="succeeded" and result["action"]=="flag_unattached_disk_for_manual_review"

def test_retry_backoff_retries_transient_failure(monkeypatch):
    import cloudguard.services.remediation_service as module
    monkeypatch.setattr(module.settings,"retry_limit",2)
    monkeypatch.setattr(module.settings,"retry_base_seconds",0)
    calls={"n":0}
    original=RemediationService._action_for
    def flaky(self, item):
        calls["n"] += 1
        if calls["n"] == 1: raise RuntimeError("transient")
        return original(self,item)
    monkeypatch.setattr(RemediationService,"_action_for",flaky)
    # In mock mode _action_for is called inside the retry block.
    result=RemediationService().execute(finding("Low","open","CG-TAG-001"),"mock-subscription-001")
    assert result["status"]=="succeeded" and result["attempt"]==2

def test_unknown_rule_uses_manual_review():
    result=RemediationService().execute(finding("Low","open","UNKNOWN-RULE"),"mock-subscription-001")
    assert result["action"]=="manual_review"

def test_live_azure_tag_remediation_with_mocked_sdk(monkeypatch):
    import sys, types
    import cloudguard.services.remediation_service as module
    monkeypatch.setattr(module.settings,"azure_mode","azure")
    monkeypatch.setattr(module.settings,"azure_client_id",None)
    monkeypatch.setattr(module.settings,"azure_client_secret",None)
    monkeypatch.setattr(module.settings,"azure_tenant_id",None)
    calls={}
    class Credential: pass
    class ResourceOps:
        def get_by_id(self, resource_id, api_version):
            calls["get"]=(resource_id,api_version)
            return types.SimpleNamespace(tags={"CostCenter":"42"})
        def begin_update_by_id(self, resource_id, api_version, body):
            calls["update"]=(resource_id,api_version,body)
            return types.SimpleNamespace(result=lambda: None)
    class Client:
        def __init__(self, credential, subscription_id):
            calls["subscription_id"]=subscription_id; self.resources=ResourceOps()
    azure=types.ModuleType("azure"); azure.__path__=[]
    identity=types.ModuleType("azure.identity"); identity.DefaultAzureCredential=Credential; identity.ClientSecretCredential=Credential
    mgmt=types.ModuleType("azure.mgmt"); mgmt.__path__=[]
    resource=types.ModuleType("azure.mgmt.resource"); resource.ResourceManagementClient=Client
    monkeypatch.setitem(sys.modules,"azure",azure)
    monkeypatch.setitem(sys.modules,"azure.identity",identity)
    monkeypatch.setitem(sys.modules,"azure.mgmt",mgmt)
    monkeypatch.setitem(sys.modules,"azure.mgmt.resource",resource)
    result=RemediationService().execute(finding("Low","open","CG-TAG-001"),"sub-12345678")
    assert result["status"]=="succeeded" and result["mode"]=="azure"
    assert calls["update"][2]["tags"]=={"CostCenter":"42","Environment":"unknown","Owner":"cloudguard"}

def test_live_azure_unsupported_remediation_fails_closed(monkeypatch):
    import cloudguard.services.remediation_service as module
    monkeypatch.setattr(module.settings,"azure_mode","azure")
    with pytest.raises(RuntimeError, match="intentionally disabled"):
        RemediationService().execute(finding("Low","open","CG-VM-IDLE-001"),"sub-12345678",approved=True)

def test_retry_limit_exhaustion(monkeypatch):
    import cloudguard.services.remediation_service as module
    monkeypatch.setattr(module.settings,"retry_limit",2)
    monkeypatch.setattr(module.settings,"retry_base_seconds",0)
    monkeypatch.setattr(module.settings,"azure_mode","mock")
    monkeypatch.setattr(module.time,"sleep",lambda _:None)
    def always_fail(self, item): raise RuntimeError("persistent")
    monkeypatch.setattr(RemediationService,"_action_for",always_fail)
    with pytest.raises(RuntimeError, match="failed after 2 attempts"):
        RemediationService().execute(finding("Low","open","CG-TAG-001"),"mock-subscription-001")

def test_live_azure_nsg_remediation_removes_only_approved_risky_rule(monkeypatch):
    import sys, types
    import cloudguard.services.remediation_service as module
    monkeypatch.setattr(module.settings,"azure_mode","azure")
    monkeypatch.setattr(module.settings,"azure_client_id",None)
    monkeypatch.setattr(module.settings,"azure_client_secret",None)
    monkeypatch.setattr(module.settings,"azure_tenant_id",None)
    calls={}
    class Credential: pass
    risky=types.SimpleNamespace(name="open-ssh", direction="Inbound", access="Allow", source_address_prefix="0.0.0.0/0", source_address_prefixes=None, destination_port_range="22", destination_port_ranges=None)
    safe=types.SimpleNamespace(name="allow-https", direction="Inbound", access="Allow", source_address_prefix="10.0.0.0/8", source_address_prefixes=None, destination_port_range="443", destination_port_ranges=None)
    nsg=types.SimpleNamespace(security_rules=[risky,safe])
    class NSGs:
        def get(self, rg, name): calls["get"]=(rg,name); return nsg
        def begin_create_or_update(self, rg, name, model): calls["update"]=(rg,name,[r.name for r in model.security_rules]); return types.SimpleNamespace(result=lambda:None)
    class NetworkClient:
        def __init__(self, credential, subscription_id): self.network_security_groups=NSGs()
    azure=types.ModuleType("azure"); azure.__path__=[]
    identity=types.ModuleType("azure.identity"); identity.DefaultAzureCredential=Credential; identity.ClientSecretCredential=Credential
    mgmt=types.ModuleType("azure.mgmt"); mgmt.__path__=[]
    resource=types.ModuleType("azure.mgmt.resource"); resource.ResourceManagementClient=object
    network=types.ModuleType("azure.mgmt.network"); network.NetworkManagementClient=NetworkClient
    for name,mod in [("azure",azure),("azure.identity",identity),("azure.mgmt",mgmt),("azure.mgmt.resource",resource),("azure.mgmt.network",network)]: monkeypatch.setitem(sys.modules,name,mod)
    result=RemediationService().execute(finding("High","open","CG-NSG-001"),"sub-12345678",approved=True)
    assert result["status"]=="succeeded" and result["action"]=="remove_approved_open_admin_rule"
    assert calls["update"]==("rg","nsg1",["allow-https"])
