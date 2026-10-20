from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.orm import Session
from cloudguard.db.session import get_db
from cloudguard.models.scan import Scan
from cloudguard.models.finding import Finding
from cloudguard.models.security import User, Subscription
from cloudguard.schemas.scan import ScanCreate, ScanRead
from cloudguard.schemas.finding import FindingRead
from cloudguard.core.security import get_current_user, require_roles
from cloudguard.services.scan_service import run_scan
from cloudguard.services.audit_service import write_audit
from cloudguard.core.config import settings

router=APIRouter(tags=["Scans & Findings"])
@router.post("/scans",response_model=ScanRead,status_code=201)
def create_scan(payload:ScanCreate, db:Session=Depends(get_db), actor:User=Depends(require_roles("Admin","CloudEngineer","AutomationService"))):
    sub=db.query(Subscription).filter_by(subscription_id=payload.subscription_id,enabled=True).first()
    if not sub and payload.subscription_id != "mock-subscription-001" and payload.subscription_id != "mock-subscription-002":
        raise HTTPException(404,"Subscription is not registered; Admin must register it first")
    if settings.execution_mode.lower() == "kubernetes":
        from datetime import datetime, timezone
        from cloudguard.services.job_dispatcher import KubernetesJobDispatcher
        scan=Scan(subscription_id=payload.subscription_id,status="queued",started_at=datetime.now(timezone.utc))
        db.add(scan); db.flush(); write_audit(db,actor.username,"scan.queued","scan",scan.id,{"subscription_id":payload.subscription_id}); db.commit()
        try:
            job_name=KubernetesJobDispatcher().dispatch_scan(scan.id,payload.subscription_id,actor.username)
            write_audit(db,actor.username,"scan.job_dispatched","scan",scan.id,{"job_name":job_name}); db.commit()
        except Exception as exc:
            scan.status="failed"; scan.error_message=f"Job dispatch failed: {type(exc).__name__}"
            write_audit(db,actor.username,"scan.dispatch_failed","scan",scan.id,{"error_type":type(exc).__name__}); db.commit()
        db.refresh(scan); return scan
    scan=run_scan(db,payload.subscription_id,actor.username); db.commit(); db.refresh(scan); return scan

@router.get("/scans/{scan_id}",response_model=ScanRead)
def get_scan(scan_id:str, db:Session=Depends(get_db), user:User=Depends(get_current_user)):
    scan=db.query(Scan).filter_by(id=scan_id).first()
    if not scan: raise HTTPException(404,"Scan not found")
    return scan

@router.get("/scans")
def list_scans(limit:int=Query(100,ge=1,le=1000), db:Session=Depends(get_db), user:User=Depends(get_current_user)):
    rows=db.query(Scan).order_by(Scan.started_at.desc()).limit(limit).all()
    return [{"id":s.id,"subscription_id":s.subscription_id,"status":s.status,"started_at":s.started_at.isoformat() if s.started_at else None,"completed_at":s.completed_at.isoformat() if s.completed_at else None,"error_message":s.error_message} for s in rows]

@router.get("/findings",response_model=list[FindingRead])
def list_findings(status:str|None=None,severity:str|None=None,rule_id:str|None=None,limit:int=Query(100,ge=1,le=1000),db:Session=Depends(get_db),user:User=Depends(get_current_user)):
    query=db.query(Finding)
    if status: query=query.filter(Finding.status==status)
    if severity: query=query.filter(Finding.severity==severity)
    if rule_id: query=query.filter(Finding.rule_id==rule_id)
    return query.order_by(Finding.created_at.desc()).limit(limit).all()
