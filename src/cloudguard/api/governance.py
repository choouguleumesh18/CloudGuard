from datetime import datetime, timezone
from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session
from cloudguard.db.session import get_db
from cloudguard.models.security import User, Subscription, PolicyRule, AuditLog
from cloudguard.core.security import get_current_user, require_roles
from cloudguard.services.audit_service import write_audit
from cloudguard.rules.compliance import validate_policy_config

router=APIRouter(tags=["Governance"])
class SubscriptionCreate(BaseModel): subscription_id: str = Field(min_length=8, max_length=100); name: str = Field(min_length=2, max_length=200); environment: str = "unknown"
class PolicyCreate(BaseModel): rule_id: str; name: str; severity: str; enabled: bool = True; config: dict = Field(default_factory=dict)
class ExceptionCreate(BaseModel): reason: str = Field(min_length=8, max_length=1000); expires_at: datetime

@router.get("/subscriptions")
def list_subscriptions(db: Session=Depends(get_db), user: User=Depends(get_current_user)):
    return [{"id":s.id,"subscription_id":s.subscription_id,"name":s.name,"environment":s.environment,"enabled":s.enabled} for s in db.query(Subscription).all()]

@router.post("/subscriptions",status_code=201)
def create_subscription(body: SubscriptionCreate, db: Session=Depends(get_db), actor: User=Depends(require_roles("Admin"))):
    if db.query(Subscription).filter_by(subscription_id=body.subscription_id).first(): raise HTTPException(409,"Subscription already registered")
    row=Subscription(**body.model_dump()); db.add(row); db.flush(); write_audit(db,actor.username,"subscription.created","subscription",row.id,{"subscription_id":row.subscription_id}); db.commit()
    return {"id":row.id,"subscription_id":row.subscription_id,"name":row.name,"environment":row.environment,"enabled":row.enabled}

@router.get("/policies")
def list_policies(db: Session=Depends(get_db), user: User=Depends(get_current_user)):
    return [{"id":p.id,"rule_id":p.rule_id,"name":p.name,"severity":p.severity,"enabled":p.enabled,"config":p.config} for p in db.query(PolicyRule).all()]

@router.post("/policies",status_code=201)
def create_policy(body: PolicyCreate, db: Session=Depends(get_db), actor: User=Depends(require_roles("Admin"))):
    if body.severity not in {"Low","Medium","High","Critical"}: raise HTTPException(422,"Unsupported severity")
    supported={"CG-TAG-001","CG-NSG-001","CG-DISK-001","CG-VM-IDLE-001","CG-KV-EXPIRY-001"}
    if body.rule_id not in supported: raise HTTPException(422,f"Unsupported rule_id. Supported: {sorted(supported)}")
    try: validate_policy_config(body.rule_id, body.config)
    except ValueError as exc: raise HTTPException(422, str(exc))
    if db.query(PolicyRule).filter_by(rule_id=body.rule_id).first(): raise HTTPException(409,"Policy rule already exists")
    row=PolicyRule(**body.model_dump()); db.add(row); db.flush(); write_audit(db,actor.username,"policy.created","policy",row.id,{"rule_id":row.rule_id}); db.commit()
    return {"id":row.id,"rule_id":row.rule_id,"name":row.name,"severity":row.severity,"enabled":row.enabled,"config":row.config}

class SubscriptionUpdate(BaseModel):
    name: str | None = Field(default=None,min_length=2,max_length=200)
    environment: str | None = Field(default=None,max_length=50)
    enabled: bool | None = None

class PolicyUpdate(BaseModel):
    name: str | None = Field(default=None,min_length=2,max_length=200)
    enabled: bool | None = None
    severity: str | None = None
    config: dict | None = None

@router.patch("/subscriptions/{subscription_id}")
def update_subscription(subscription_id:str, body:SubscriptionUpdate, db:Session=Depends(get_db), actor:User=Depends(require_roles("Admin"))):
    row=db.query(Subscription).filter_by(subscription_id=subscription_id).first()
    if not row: raise HTTPException(404,"Subscription not found")
    changes=body.model_dump(exclude_unset=True)
    for key,value in changes.items(): setattr(row,key,value)
    write_audit(db,actor.username,"subscription.updated","subscription",row.id,changes); db.commit()
    return {"id":row.id,"subscription_id":row.subscription_id,"name":row.name,"environment":row.environment,"enabled":row.enabled}

@router.patch("/policies/{rule_id}")
def update_policy(rule_id:str, body:PolicyUpdate, db:Session=Depends(get_db), actor:User=Depends(require_roles("Admin"))):
    row=db.query(PolicyRule).filter_by(rule_id=rule_id).first()
    if not row: raise HTTPException(404,"Policy rule not found")
    changes=body.model_dump(exclude_unset=True)
    severity=changes.get("severity",row.severity)
    if severity not in {"Low","Medium","High","Critical"}: raise HTTPException(422,"Unsupported severity")
    config_value=changes.get("config",row.config or {})
    if config_value is None: raise HTTPException(422,"config must be an object")
    try: validate_policy_config(rule_id,config_value)
    except ValueError as exc: raise HTTPException(422,str(exc))
    for key,value in changes.items(): setattr(row,key,value)
    write_audit(db,actor.username,"policy.updated","policy",row.id,changes); db.commit()
    return {"id":row.id,"rule_id":row.rule_id,"name":row.name,"severity":row.severity,"enabled":row.enabled,"config":row.config}

@router.post("/findings/{finding_id}/exception",status_code=201)
def create_exception(finding_id: str, body: ExceptionCreate, db: Session=Depends(get_db), actor: User=Depends(require_roles("CloudEngineer","Admin"))):
    from cloudguard.models.finding import Finding
    finding=db.query(Finding).filter_by(id=finding_id).first()
    if not finding: raise HTTPException(404,"Finding not found")
    expiry=body.expires_at
    if expiry.tzinfo is None: expiry=expiry.replace(tzinfo=timezone.utc)
    if expiry <= datetime.now(timezone.utc): raise HTTPException(422,"Exception expiry must be in the future")
    from cloudguard.models.security import ExceptionRecord
    row=ExceptionRecord(finding_id=finding_id,reason=body.reason,approved_by=actor.username,expires_at=expiry)
    db.add(row); finding.status="excepted"; db.flush(); write_audit(db,actor.username,"finding.exception.created","finding",finding_id,{"expires_at":expiry.isoformat(),"reason":body.reason}); db.commit()
    return {"id":row.id,"finding_id":finding_id,"expires_at":expiry.isoformat(),"status":"excepted"}

@router.get("/audit-logs")
def audit_logs(limit:int=Query(100,ge=1,le=1000), db:Session=Depends(get_db), actor:User=Depends(require_roles("Admin"))):
    rows=db.query(AuditLog).order_by(AuditLog.created_at.desc()).limit(limit).all()
    return [{"id":r.id,"actor":r.actor,"action":r.action,"entity_type":r.entity_type,"entity_id":r.entity_id,"details":r.details,"previous_hash":r.previous_hash,"event_hash":r.event_hash,"created_at":r.created_at.isoformat()} for r in rows]

@router.get("/audit-logs/verify")
def verify_audit_chain(db:Session=Depends(get_db), actor:User=Depends(require_roles("Admin"))):
    import hashlib,json
    rows=db.query(AuditLog).order_by(AuditLog.created_at,AuditLog.id).all(); previous="0"*64
    for row in rows:
        from datetime import timezone
        created = row.created_at if row.created_at.tzinfo else row.created_at.replace(tzinfo=timezone.utc)
        body={"actor":row.actor,"action":row.action,"entity_type":row.entity_type,"entity_id":row.entity_id,"details":row.details or {},"previous_hash":row.previous_hash,"created_at":created.isoformat()}
        digest=hashlib.sha256(json.dumps(body,sort_keys=True,separators=(",",":"),default=str).encode()).hexdigest()
        if row.previous_hash != previous or row.event_hash != digest: return {"valid":False,"failed_event_id":row.id}
        previous=row.event_hash
    return {"valid":True,"events_verified":len(rows)}
