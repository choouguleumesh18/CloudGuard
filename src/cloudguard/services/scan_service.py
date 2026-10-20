from datetime import datetime, timezone
from sqlalchemy.orm import Session
from cloudguard.models.scan import Scan
from cloudguard.models.finding import Finding
from cloudguard.models.security import ExceptionRecord, PolicyRule
from cloudguard.rules.compliance import evaluate_resource
from cloudguard.services.azure_inventory import AzureInventory
from cloudguard.services.audit_service import write_audit
from cloudguard.core.config import settings
from cloudguard.services.remediation_service import RemediationService

def _active_exception(db: Session, resource_id: str, rule_id: str) -> bool:
    now = datetime.now(timezone.utc)
    prior_findings = db.query(Finding).filter(Finding.resource_id == resource_id, Finding.rule_id == rule_id).all()
    prior_ids = [item.id for item in prior_findings]
    if not prior_ids: return False
    for exc in db.query(ExceptionRecord).filter(ExceptionRecord.finding_id.in_(prior_ids)).all():
        expiry = exc.expires_at
        if expiry.tzinfo is None: expiry = expiry.replace(tzinfo=timezone.utc)
        if expiry > now: return True
    return False

def run_scan(db: Session, subscription_id: str, actor: str = "system", scan_id: str | None = None) -> Scan:
    scan = db.query(Scan).filter_by(id=scan_id).first() if scan_id else None
    if scan is None:
        scan = Scan(subscription_id=subscription_id, status="running", started_at=datetime.now(timezone.utc))
        db.add(scan); db.flush()
    else:
        scan.status = "running"
        scan.error_message = None
    write_audit(db, actor, "scan.started", "scan", scan.id, {"subscription_id": subscription_id})
    try:
        resources = AzureInventory(subscription_id).list_resources()
        policy_rows = db.query(PolicyRule).all()
        policy_map = {p.rule_id:{"enabled":p.enabled,"severity":p.severity,"config":p.config or {}} for p in policy_rows}
        for resource in resources:
            resource_type = str(resource.get("type", "")).lower()
            warning = (resource.get("properties") or {}).get("inventoryWarning")
            if warning:
                write_audit(db, actor, "inventory.warning", "resource", resource.get("id"), {"resource_type": resource_type, "warning": warning})
                if resource_type.endswith("networksecuritygroups"):
                    raise RuntimeError("NSG rules could not be read; scan cannot safely classify this resource")
            for finding_data in evaluate_resource(resource, policy_map):
                finding = Finding(scan_id=scan.id, resource_id=resource.get("id", "unknown"), resource_name=resource.get("name", "unknown"), rule_id=finding_data["rule_id"], severity=finding_data["severity"], description=finding_data["description"], status="open", details=finding_data.get("details", {}))
                db.add(finding); db.flush()
                if _active_exception(db, finding.resource_id, finding.rule_id):
                    finding.status = "excepted"
                    write_audit(db, actor, "finding.exception.applied", "finding", finding.id, {"rule_id": finding.rule_id, "resource_id": finding.resource_id})
                write_audit(db, actor, "finding.created", "finding", finding.id, {"rule_id": finding.rule_id, "severity": finding.severity, "resource_id": finding.resource_id})
                if settings.auto_remediate_low_risk and finding.severity == "Low" and finding.rule_id == "CG-TAG-001" and finding.status == "open":
                    try:
                        result = RemediationService().execute(finding, subscription_id, approved=False)
                        if result.get("status") in {"succeeded", "noop"}: finding.status = "remediated"
                        write_audit(db, actor, "remediation.auto_attempted", "finding", finding.id, result)
                    except Exception as exc:
                        write_audit(db, actor, "remediation.auto_failed", "finding", finding.id, {"error_type": type(exc).__name__})
        scan.status = "completed"
    except Exception as exc:
        scan.status = "failed"
        scan.completed_at = datetime.now(timezone.utc)
        scan.error_message = f"{type(exc).__name__}: scan failed; inspect service logs for details"
        write_audit(db, actor, "scan.failed", "scan", scan.id, {"error_type": type(exc).__name__})
        db.flush()
        return scan
    scan.completed_at = datetime.now(timezone.utc)
    write_audit(db, actor, "scan.completed", "scan", scan.id, {"resource_count": len(resources)})
    db.flush()
    return scan
