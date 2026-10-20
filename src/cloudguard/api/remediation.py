from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session
from cloudguard.db.session import get_db
from cloudguard.models.finding import Finding
from cloudguard.models.scan import Scan
from cloudguard.models.security import User, RemediationRequest
from cloudguard.core.security import require_roles
from cloudguard.services.audit_service import write_audit
from cloudguard.services.remediation_service import RemediationService
from cloudguard.core.config import settings

router=APIRouter(tags=["Remediation & Approvals"])
class Decision(BaseModel): decision: str; note: str = Field(default="", max_length=1000)

@router.post("/findings/{finding_id}/remediate",status_code=202)
def request_remediation(finding_id:str, db:Session=Depends(get_db), actor:User=Depends(require_roles("Admin","CloudEngineer"))):
    finding=db.query(Finding).filter_by(id=finding_id).first()
    if not finding: raise HTTPException(404,"Finding not found")
    if finding.status in {"remediated","excepted"}: return {"status":"noop","message":"Finding is already resolved or excepted"}
    if finding.severity in {"High","Critical"}:
        existing=db.query(RemediationRequest).filter_by(finding_id=finding_id,status="pending_approval").first()
        if existing: return {"request_id":existing.id,"status":existing.status,"message":"Approval is already pending"}
        req=RemediationRequest(finding_id=finding_id,requested_by=actor.username,status="pending_approval")
        db.add(req); db.flush(); write_audit(db,actor.username,"remediation.approval_requested","remediation_request",req.id,{"finding_id":finding_id,"severity":finding.severity}); db.commit()
        return {"request_id":req.id,"status":req.status,"message":"High-risk remediation queued; not executed"}
    scan=db.query(Scan).filter_by(id=finding.scan_id).first()
    if settings.execution_mode.lower() == "kubernetes":
        from cloudguard.services.job_dispatcher import KubernetesJobDispatcher
        req=RemediationRequest(finding_id=finding_id,requested_by=actor.username,status="approved_queued",decision_by=actor.username,decision_note="Low-risk remediation dispatched by policy")
        db.add(req); db.flush(); write_audit(db,actor.username,"remediation.job_queued","remediation_request",req.id,{"finding_id":finding_id})
        try:
            job_name=KubernetesJobDispatcher().dispatch_remediation(req.id)
            req.result={"job_name":job_name}; db.commit()
        except Exception as exc:
            req.status="failed"; req.result={"error_type":type(exc).__name__}; write_audit(db,actor.username,"remediation.dispatch_failed","remediation_request",req.id,req.result); db.commit()
            raise HTTPException(503,"Remediation job could not be dispatched; finding remains open")
        return {"request_id":req.id,"finding_id":finding_id,"status":req.status,"message":"Low-risk remediation queued as Kubernetes Job"}
    try:
        result=RemediationService().execute(finding,scan.subscription_id if scan else "",approved=False)
        finding.status="remediated" if result["status"] in {"succeeded","noop"} else finding.status
        req=RemediationRequest(finding_id=finding_id,requested_by=actor.username,status=result["status"],result=result,attempt_count=result.get("attempt",1)); db.add(req)
        write_audit(db,actor.username,"remediation.executed","finding",finding_id,result); db.commit()
        return {"request_id":req.id,"finding_id":finding_id,**result}
    except Exception as exc:
        write_audit(db,actor.username,"remediation.failed","finding",finding_id,{"error_type":type(exc).__name__}); db.commit()
        raise HTTPException(502,"Remediation failed; finding remains open and was audit-logged")

@router.get("/approvals")
def list_approvals(status:str="pending_approval", db:Session=Depends(get_db), actor:User=Depends(require_roles("Admin","SecurityOfficer"))):
    rows=db.query(RemediationRequest).filter_by(status=status).order_by(RemediationRequest.created_at).all()
    return [{"id":r.id,"finding_id":r.finding_id,"requested_by":r.requested_by,"status":r.status,"created_at":r.created_at.isoformat()} for r in rows]

@router.post("/approvals/{request_id}/decision")
def decide_approval(request_id:str, body:Decision, db:Session=Depends(get_db), actor:User=Depends(require_roles("Admin","SecurityOfficer"))):
    if body.decision not in {"approve","reject"}: raise HTTPException(422,"decision must be approve or reject")
    req=db.query(RemediationRequest).filter_by(id=request_id).first()
    if not req: raise HTTPException(404,"Approval request not found")
    if req.status != "pending_approval": raise HTTPException(409,"Approval request has already been decided")
    req.decision_by=actor.username; req.decision_note=body.note
    finding=db.query(Finding).filter_by(id=req.finding_id).first()
    if body.decision == "reject":
        req.status="rejected"; write_audit(db,actor.username,"remediation.rejected","remediation_request",req.id,{"finding_id":req.finding_id,"note":body.note}); db.commit()
        return {"request_id":req.id,"status":req.status}
    if not finding: raise HTTPException(404,"Finding not found")
    if settings.execution_mode.lower() == "kubernetes":
        from cloudguard.services.job_dispatcher import KubernetesJobDispatcher
        req.status="approved_queued"; write_audit(db,actor.username,"remediation.approved_and_queued","remediation_request",req.id,{"finding_id":req.finding_id,"note":body.note}); db.commit()
        try:
            job_name=KubernetesJobDispatcher().dispatch_remediation(req.id)
            req.result={"job_name":job_name}; db.commit()
        except Exception as exc:
            req.status="failed"; req.result={"error_type":type(exc).__name__}; write_audit(db,actor.username,"remediation.dispatch_failed","remediation_request",req.id,req.result); db.commit()
            raise HTTPException(503,"Approved remediation could not be dispatched; finding remains open")
        return {"request_id":req.id,"finding_id":req.finding_id,"status":req.status,"message":"Approved remediation queued as Kubernetes Job"}
    scan=db.query(Scan).filter_by(id=finding.scan_id).first()
    try:
        result=RemediationService().execute(finding,scan.subscription_id if scan else "",approved=True)
        req.status="approved_executed" if result["status"] in {"succeeded","noop"} else result["status"]
        req.result=result; req.attempt_count=result.get("attempt",1)
        if result["status"] in {"succeeded","noop"}: finding.status="remediated"
        write_audit(db,actor.username,"remediation.approved_and_executed","remediation_request",req.id,{"finding_id":req.finding_id,"result":result}); db.commit()
        return {"request_id":req.id,"finding_id":req.finding_id,"status":req.status,"result":result}
    except Exception as exc:
        req.status="failed"; req.result={"error_type":type(exc).__name__}; write_audit(db,actor.username,"remediation.failed","remediation_request",req.id,req.result); db.commit()
        raise HTTPException(502,"Approved remediation failed; finding remains open for manual review")
