from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session
from cloudguard.db.session import get_db
from cloudguard.models.security import User
from cloudguard.core.security import hash_password, verify_password, create_access_token, get_current_user, require_roles, ROLES
from cloudguard.core.config import settings
from cloudguard.services.audit_service import write_audit

router = APIRouter(prefix="/auth", tags=["Authentication"])
class LoginRequest(BaseModel): username: str; password: str
class UserCreate(BaseModel): username: str = Field(min_length=3, max_length=120); password: str = Field(min_length=12); role: str
class UserUpdate(BaseModel): role: str | None = None; is_active: bool | None = None

@router.post("/login")
def login(body: LoginRequest, db: Session = Depends(get_db)):
    user = db.query(User).filter(User.username == body.username, User.is_active.is_(True)).first()
    if not user or not verify_password(body.password, user.password_hash): raise HTTPException(status_code=401, detail="Invalid username or password")
    write_audit(db, user.username, "auth.login", "user", user.id, {"role": user.role}); db.commit()
    return {"access_token": create_access_token(user), "token_type":"bearer", "expires_in_minutes": settings.jwt_expiry_minutes, "role": user.role}

@router.get("/me")
def me(user: User = Depends(get_current_user)):
    return {"id":user.id, "username":user.username, "role":user.role, "is_active":user.is_active}

@router.post("/users", status_code=201)
def create_user(body: UserCreate, db: Session = Depends(get_db), actor: User = Depends(require_roles("Admin"))):
    if body.role not in ROLES: raise HTTPException(status_code=422, detail=f"role must be one of {sorted(ROLES)}")
    if db.query(User).filter(User.username == body.username).first(): raise HTTPException(status_code=409, detail="Username already exists")
    user = User(username=body.username, password_hash=hash_password(body.password), role=body.role)
    db.add(user); db.flush(); write_audit(db, actor.username, "user.created", "user", user.id, {"username": user.username, "role": user.role}); db.commit()
    return {"id":user.id,"username":user.username,"role":user.role}

@router.get("/users")
def list_users(db: Session = Depends(get_db), actor: User = Depends(require_roles("Admin"))):
    return [{"id":u.id,"username":u.username,"role":u.role,"is_active":u.is_active} for u in db.query(User).order_by(User.username).all()]

@router.patch("/users/{username}")
def update_user(username: str, body: UserUpdate, db: Session = Depends(get_db), actor: User = Depends(require_roles("Admin"))):
    user=db.query(User).filter_by(username=username).first()
    if not user: raise HTTPException(status_code=404, detail="User not found")
    changes=body.model_dump(exclude_unset=True)
    if "role" in changes and changes["role"] not in ROLES: raise HTTPException(status_code=422, detail=f"role must be one of {sorted(ROLES)}")
    if user.username == actor.username and changes.get("is_active") is False: raise HTTPException(status_code=422, detail="An Admin cannot deactivate their own account")
    for key,value in changes.items(): setattr(user,key,value)
    write_audit(db,actor.username,"user.updated","user",user.id,changes); db.commit()
    return {"id":user.id,"username":user.username,"role":user.role,"is_active":user.is_active}
