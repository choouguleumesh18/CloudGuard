from cloudguard.rules.compliance import evaluate_resource

def test_missing_tags_finding():
    findings=evaluate_resource({"id":"/r/1","name":"vm1","type":"Microsoft.Compute/virtualMachines","tags":{}})
    assert any(f["rule_id"]=="CG-TAG-001" and f["severity"]=="Low" for f in findings)

def test_complete_tags_no_tag_finding():
    findings=evaluate_resource({"id":"/r/2","name":"vm2","type":"Microsoft.Compute/virtualMachines","tags":{"Environment":"dev","Owner":"team"}})
    assert not any(f["rule_id"]=="CG-TAG-001" for f in findings)

def test_open_ssh_finding():
    findings=evaluate_resource({"id":"/nsg/1","name":"nsg1","type":"Microsoft.Network/networkSecurityGroups","tags":{"Environment":"dev","Owner":"team"},"properties":{"securityRules":[{"name":"ssh","direction":"Inbound","access":"Allow","sourceAddressPrefix":"0.0.0.0/0","destinationPortRange":"22"}]}})
    assert any(f["rule_id"]=="CG-NSG-001" and f["severity"]=="High" for f in findings)

def test_unattached_disk_flagged():
    findings=evaluate_resource({"id":"/disk/1","name":"disk1","type":"Microsoft.Compute/disks","tags":{"Environment":"dev","Owner":"team"},"properties":{}})
    assert any(f["rule_id"]=="CG-DISK-001" for f in findings)

def test_private_nsg_not_flagged():
    findings=evaluate_resource({"id":"/nsg/2","name":"nsg2","type":"Microsoft.Network/networkSecurityGroups","tags":{"Environment":"dev","Owner":"team"},"properties":{"securityRules":[{"name":"ssh","direction":"Inbound","access":"Allow","sourceAddressPrefix":"10.0.0.0/8","destinationPortRange":"22"}]}})
    assert not any(f["rule_id"]=="CG-NSG-001" for f in findings)

def test_wildcard_port_and_prefix_lists_detected():
    findings=evaluate_resource({"id":"/nsg/3","name":"nsg3","type":"Microsoft.Network/networkSecurityGroups","tags":{"Environment":"dev","Owner":"team"},"properties":{"securityRules":[{"name":"all","direction":"Inbound","access":"Allow","sourceAddressPrefixes":["*"],"destinationPortRanges":["*"]}]}})
    assert any(f["rule_id"]=="CG-NSG-001" for f in findings)

def test_keyvault_secret_expiry_detected():
    from datetime import datetime, timedelta, timezone
    expiry=(datetime.now(timezone.utc)+timedelta(days=10)).isoformat()
    findings=evaluate_resource({"id":"/kv/1","name":"vault1","type":"Microsoft.KeyVault/vaults","tags":{"Environment":"dev","Owner":"team"},"properties":{"secrets":[{"name":"secret1","expiresOn":expiry}]}})
    assert any(f["rule_id"]=="CG-KV-EXPIRY-001" for f in findings)

def test_vm_low_cpu_metric_detected():
    findings=evaluate_resource({"id":"/vm/1","name":"vm1","type":"Microsoft.Compute/virtualMachines","tags":{"Environment":"dev","Owner":"team"},"properties":{"averageCpuPercent7d":0.5}})
    assert any(f["rule_id"]=="CG-VM-IDLE-001" for f in findings)

def test_expired_or_invalid_keyvault_secret_ignored():
    findings=evaluate_resource({"id":"/kv/2","name":"vault2","type":"Microsoft.KeyVault/vaults","tags":{"Environment":"dev","Owner":"team"},"properties":{"secrets":[{"name":"old","expiresOn":"not-a-date"}]}})
    assert not any(f["rule_id"]=="CG-KV-EXPIRY-001" for f in findings)

def test_mock_inventory_fixture_has_normalized_nsg_rules():
    from cloudguard.services.azure_inventory import AzureInventory
    resources=AzureInventory("mock-subscription-001").list_resources()
    nsg=next(r for r in resources if r.get("type","").lower().endswith("networksecuritygroups") and r["name"]=="nsg-web")
    assert any(rule.get("destinationPortRange")=="22" for rule in nsg["properties"]["securityRules"])

def test_policy_override_can_disable_rule_and_customize_tags():
    resource={"id":"/vm/2","name":"vm2","type":"Microsoft.Compute/virtualMachines","tags":{},"properties":{}}
    policies={"CG-TAG-001":{"enabled":True,"severity":"Medium","config":{"required_tags":["CostCenter"]}},"CG-VM-IDLE-001":{"enabled":False,"severity":"Low","config":{}}}
    findings=evaluate_resource(resource,policies)
    tag=next(item for item in findings if item["rule_id"]=="CG-TAG-001")
    assert tag["severity"]=="Medium" and tag["details"]["missing_tags"]==["CostCenter"]
    assert not any(item["rule_id"]=="CG-VM-IDLE-001" for item in findings)

def test_policy_config_validation_rejects_unknown_fields():
    import pytest
    from cloudguard.rules.compliance import validate_policy_config
    with pytest.raises(ValueError,match="Unsupported config keys"):
        validate_policy_config("CG-TAG-001",{"owner_tag":"Owner"})
