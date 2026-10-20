from contextlib import asynccontextmanager
from fastapi import FastAPI
from cloudguard import models  # noqa: F401
from cloudguard.api.scans import router as scans_router
from cloudguard.api.auth import router as auth_router
from cloudguard.api.governance import router as governance_router
from cloudguard.api.remediation import router as remediation_router
from cloudguard.core.config import settings
from cloudguard.core.security import hash_password
from cloudguard.db.base import Base
from cloudguard.db.session import engine, SessionLocal
from cloudguard.models.security import User

@asynccontextmanager
async def lifespan(app: FastAPI):
    # Local capstone bootstrap. For production, replace create_all with Alembic migrations and seed admin through a one-time secret.
    if settings.auto_create_schema:
        Base.metadata.create_all(bind=engine)
    db=SessionLocal()
    try:
        if not db.query(User).filter_by(username=settings.bootstrap_admin_username).first():
            db.add(User(username=settings.bootstrap_admin_username,password_hash=hash_password(settings.bootstrap_admin_password),role="Admin")); db.commit()
    finally: db.close()
    yield

app=FastAPI(title=settings.app_name,version=settings.app_version,description="Azure infrastructure compliance, approval and remediation platform",lifespan=lifespan)
@app.get("/api/v1/health",tags=["Health"])
def health_check(): return {"status":"healthy","service":settings.app_name,"version":settings.app_version,"azure_mode":settings.azure_mode}
app.include_router(auth_router,prefix="/api/v1")
app.include_router(scans_router,prefix="/api/v1")
app.include_router(governance_router,prefix="/api/v1")
app.include_router(remediation_router,prefix="/api/v1")
