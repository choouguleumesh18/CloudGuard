from datetime import datetime, timezone

def validate_policy_config(rule_id: str, config: dict) -> None:
    allowed={"CG-TAG-001":{"required_tags"},"CG-NSG-001":{"admin_ports"},"CG-DISK-001":set(),"CG-VM-IDLE-001":{"cpu_threshold_percent"},"CG-KV-EXPIRY-001":{"expiry_days"}}
    if rule_id not in allowed: raise ValueError("Unsupported rule_id")
    unknown=set(config)-allowed[rule_id]
    if unknown: raise ValueError(f"Unsupported config keys for {rule_id}: {sorted(unknown)}")
    if "required_tags" in config and (not isinstance(config["required_tags"],list) or not config["required_tags"] or not all(isinstance(x,str) and x.strip() for x in config["required_tags"])): raise ValueError("required_tags must be a non-empty list of strings")
    if "admin_ports" in config and (not isinstance(config["admin_ports"],list) or not config["admin_ports"] or not all(str(x) in {"22","3389"} for x in config["admin_ports"])): raise ValueError("admin_ports must contain only supported administrative ports 22 and/or 3389")
    if "cpu_threshold_percent" in config and (not isinstance(config["cpu_threshold_percent"],(int,float)) or not 0 <= config["cpu_threshold_percent"] <= 100): raise ValueError("cpu_threshold_percent must be between 0 and 100")
    if "expiry_days" in config and (not isinstance(config["expiry_days"],int) or not 1 <= config["expiry_days"] <= 365): raise ValueError("expiry_days must be an integer between 1 and 365")

def evaluate_resource(resource: dict, policies: dict | None = None) -> list[dict]:
    policies=policies or {}
    def enabled(rule_id): return rule_id not in policies or policies[rule_id].get("enabled",True)
    def severity(rule_id, default): return policies.get(rule_id,{}).get("severity",default)
    def config(rule_id): return policies.get(rule_id,{}).get("config",{})
    findings=[]; rtype=(resource.get("type") or "").lower(); tags=resource.get("tags") or {}; props=resource.get("properties") or {}
    required_tags=config("CG-TAG-001").get("required_tags",["Environment","Owner"])
    missing=[tag for tag in required_tags if not tags.get(tag)]
    if missing and enabled("CG-TAG-001"):
        findings.append({"rule_id":"CG-TAG-001","severity":severity("CG-TAG-001","Low"),"description":f"Resource is missing required tags: {', '.join(missing)}","details":{"missing_tags":missing}})
    if rtype.endswith("networksecuritygroups") and enabled("CG-NSG-001"):
        for rule in props.get("securityRules",[]):
            direction=str(rule.get("direction","")).lower(); access=str(rule.get("access","")).lower()
            sources=rule.get("sourceAddressPrefixes") or [rule.get("sourceAddressPrefix") or ""]
            ports=rule.get("destinationPortRanges") or [rule.get("destinationPortRange") or ""]
            open_source=any(s in {"*","0.0.0.0/0","Internet","Any"} for s in sources)
            admin_ports={str(p) for p in config("CG-NSG-001").get("admin_ports",["22","3389"])}
            admin_port=any(p in admin_ports or p=="*" for p in ports)
            if direction=="inbound" and access=="allow" and open_source and admin_port:
                findings.append({"rule_id":"CG-NSG-001","severity":severity("CG-NSG-001","High"),"description":f"Inbound administrative port exposed to any source by rule {rule.get('name','unnamed')}","details":{"rule_name":rule.get("name"),"ports":ports,"sources":sources}})
    if enabled("CG-DISK-001") and rtype.endswith("disks") and not props.get("managedBy") and not resource.get("managedBy"):
        findings.append({"rule_id":"CG-DISK-001","severity":severity("CG-DISK-001","Medium"),"description":"Managed disk appears unattached and requires owner review","details":{"resource_type":resource.get("type")}})
    cpu_threshold=float(config("CG-VM-IDLE-001").get("cpu_threshold_percent",2))
    if enabled("CG-VM-IDLE-001") and rtype.endswith("virtualmachines") and props.get("averageCpuPercent7d") is not None and float(props["averageCpuPercent7d"]) < cpu_threshold:
        findings.append({"rule_id":"CG-VM-IDLE-001","severity":severity("CG-VM-IDLE-001","Low"),"description":f"VM average CPU utilization is below {cpu_threshold}% over the supplied 7-day metric window","details":{"average_cpu_percent_7d":props["averageCpuPercent7d"]}})
    if enabled("CG-KV-EXPIRY-001") and "keyvault/vaults" in rtype and props.get("secrets"):
        now=datetime.now(timezone.utc)
        for secret in props["secrets"]:
            expires=secret.get("expiresOn")
            if expires:
                try:
                    exp=datetime.fromisoformat(expires.replace("Z","+00:00"))
                    if exp.tzinfo is None: exp=exp.replace(tzinfo=timezone.utc)
                    expiry_days=int(config("CG-KV-EXPIRY-001").get("expiry_days",30))
                    if 0 <= (exp-now).days <= expiry_days:
                        findings.append({"rule_id":"CG-KV-EXPIRY-001","severity":severity("CG-KV-EXPIRY-001","Medium"),"description":f"Key Vault secret {secret.get('name','unknown')} expires within {expiry_days} days","details":{"secret_name":secret.get("name"),"expires_on":exp.isoformat()}})
                except ValueError: pass
    return findings
