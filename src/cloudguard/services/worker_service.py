from sqlalchemy.orm import Session
from cloudguard.models.finding import Finding
from cloudguard.models.scan import Scan
from cloudguard.models.security import RemediationRequest
from cloudguard.services.audit_service import write_audit
from cloudguard.services.remediation_service import RemediationService

def run_remediation_job(db: Session, request_id: str):
    req=db.query(RemediationRequest).filter_by(id=request_id).first()
    if not req or req.status != "approved_queued": raise ValueError("Remediation request is not approved and queued")
    finding=db.query(Finding).filter_by(id=req.finding_id).first()
    if not finding: raise ValueError("Finding not found")
    scan=db.query(Scan).filter_by(id=finding.scan_id).first()
    try:
        result=RemediationService().execute(finding,scan.subscription_id if scan else "",approved=True)
        req.result=result; req.attempt_count=result.get("attempt",1); req.status="approved_executed" if result.get("status") in {"succeeded", "noop"} else result.get("status","failed")
        if result.get("status") in {"succeeded", "noop"}: finding.status="remediated"
        write_audit(db,req.decision_by or "security-officer","remediation.worker_completed","remediation_request",req.id,result)
    except Exception as exc:
        req.status="failed"; req.result={"error_type":type(exc).__name__}; write_audit(db,"automation-service","remediation.worker_failed","remediation_request",req.id,req.result)
        finding.status="open"
    db.commit()
    return req
