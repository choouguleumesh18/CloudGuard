import hashlib, json
from datetime import datetime, timezone
from sqlalchemy.orm import Session
from cloudguard.models.security import AuditLog

def write_audit(db: Session, actor: str, action: str, entity_type: str, entity_id: str | None = None, details: dict | None = None):
    last = db.query(AuditLog).order_by(AuditLog.created_at.desc(), AuditLog.id.desc()).first()
    previous = last.event_hash if last else "0" * 64
    created = datetime.now(timezone.utc)
    body = {"actor": actor, "action": action, "entity_type": entity_type, "entity_id": entity_id, "details": details or {}, "previous_hash": previous, "created_at": created.isoformat()}
    digest = hashlib.sha256(json.dumps(body, sort_keys=True, separators=(",", ":"), default=str).encode()).hexdigest()
    row = AuditLog(actor=actor, action=action, entity_type=entity_type, entity_id=entity_id, details=details or {}, previous_hash=previous, event_hash=digest, created_at=created)
    db.add(row)
    return row
