from datetime import datetime, timezone
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from cloudguard.main import app
from cloudguard.db.base import Base
from cloudguard.db.session import get_db
from cloudguard.models.security import User, RemediationRequest
from cloudguard.models.scan import Scan
from cloudguard.models.finding import Finding
from cloudguard.core.security import hash_password


def test_auth_rbac_approval_and_audit_chain():
    engine = create_engine("sqlite://", connect_args={"check_same_thread": False}, poolclass=StaticPool)
    TestingSession = sessionmaker(bind=engine, autocommit=False, autoflush=False)
    Base.metadata.create_all(engine)
    db = TestingSession()
    db.add_all([
        User(username="testadmin", password_hash=hash_password("admin-password-123"), role="Admin"),
        User(username="engineer", password_hash=hash_password("engineer-password-123"), role="CloudEngineer"),
        User(username="security", password_hash=hash_password("security-password-123"), role="SecurityOfficer"),
    ])
    scan = Scan(subscription_id="mock-subscription-001", status="completed", started_at=datetime.now(timezone.utc))
    db.add(scan); db.flush()
    finding = Finding(scan_id=scan.id, resource_id="/mock/nsg", resource_name="test-nsg", rule_id="CG-NSG-001", severity="High", description="open ssh", status="open", details={})
    db.add(finding); db.flush()
    request = RemediationRequest(finding_id=finding.id, requested_by="engineer", status="pending_approval")
    db.add(request); db.commit()
    request_id = request.id
    db.close()

    def override_get_db():
        session = TestingSession()
        try: yield session
        finally: session.close()
    app.dependency_overrides[get_db] = override_get_db
    client = TestClient(app)
    try:
        login = client.post("/api/v1/auth/login", json={"username":"engineer", "password":"engineer-password-123"})
        assert login.status_code == 200
        engineer_token = login.json()["access_token"]
        denied = client.post(f"/api/v1/approvals/{request_id}/decision", headers={"Authorization":f"Bearer {engineer_token}"}, json={"decision":"approve"})
        assert denied.status_code == 403

        security_login = client.post("/api/v1/auth/login", json={"username":"security", "password":"security-password-123"})
        security_token = security_login.json()["access_token"]
        approved = client.post(f"/api/v1/approvals/{request_id}/decision", headers={"Authorization":f"Bearer {security_token}"}, json={"decision":"approve", "note":"test approval"})
        assert approved.status_code == 200
        assert approved.json()["status"] == "approved_executed"

        admin_login = client.post("/api/v1/auth/login", json={"username":"testadmin", "password":"admin-password-123"})
        admin_token = admin_login.json()["access_token"]
        verify = client.get("/api/v1/audit-logs/verify", headers={"Authorization":f"Bearer {admin_token}"})
        assert verify.status_code == 200 and verify.json()["valid"] is True
    finally:
        app.dependency_overrides.clear()
        Base.metadata.drop_all(engine)
        engine.dispose()

def test_mock_scan_generates_findings_and_time_bound_exception_is_applied_on_rescan():
    engine = create_engine("sqlite://", connect_args={"check_same_thread": False}, poolclass=StaticPool)
    TestingSession = sessionmaker(bind=engine, autocommit=False, autoflush=False)
    Base.metadata.create_all(engine)
    db=TestingSession()
    db.add(User(username="adminscan",password_hash=hash_password("adminscan-password-123"),role="Admin"))
    db.commit(); db.close()
    def override_get_db():
        session=TestingSession()
        try: yield session
        finally: session.close()
    app.dependency_overrides[get_db]=override_get_db
    client=TestClient(app)
    try:
        token=client.post("/api/v1/auth/login",json={"username":"adminscan","password":"adminscan-password-123"}).json()["access_token"]
        headers={"Authorization":f"Bearer {token}"}
        scan_response=client.post("/api/v1/scans",headers=headers,json={"subscription_id":"mock-subscription-001"})
        assert scan_response.status_code==201 and scan_response.json()["status"]=="completed"
        findings=client.get("/api/v1/findings",headers=headers).json()
        nsg=next(item for item in findings if item["rule_id"]=="CG-NSG-001")
        assert nsg["severity"]=="High"
        from datetime import timedelta
        expiry=(datetime.now(timezone.utc)+timedelta(days=7)).isoformat()
        exception=client.post(f"/api/v1/findings/{nsg['id']}/exception",headers=headers,json={"reason":"Approved test exception","expires_at":expiry})
        assert exception.status_code==201
        second=client.post("/api/v1/scans",headers=headers,json={"subscription_id":"mock-subscription-001"})
        assert second.status_code==201
        refreshed=client.get("/api/v1/findings",headers=headers).json()
        assert any(item["resource_id"]==nsg["resource_id"] and item["rule_id"]=="CG-NSG-001" and item["status"]=="excepted" for item in refreshed)
    finally:
        app.dependency_overrides.clear(); Base.metadata.drop_all(engine); engine.dispose()
