import hashlib
import hmac
import secrets

from datetime import datetime, timedelta, timezone
from typing import Callable, cast

import jwt

from fastapi import Depends, HTTPException, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from sqlalchemy.orm import Session

from cloudguard.core.config import settings
from cloudguard.db.session import get_db
from cloudguard.models.security import User


bearer = HTTPBearer(auto_error=False)

ROLES = {
    "Admin",
    "CloudEngineer",
    "SecurityOfficer",
    "AutomationService",
}


def hash_password(password: str) -> str:
    salt = secrets.token_bytes(16)

    digest = hashlib.pbkdf2_hmac(
        "sha256",
        password.encode(),
        salt,
        310_000,
    )

    return "pbkdf2_sha256$310000$%s$%s" % (
        salt.hex(),
        digest.hex(),
    )


def verify_password(password: str, stored: str) -> bool:
    try:
        scheme, rounds, salt, expected = stored.split("$")

        actual = hashlib.pbkdf2_hmac(
            "sha256",
            password.encode(),
            bytes.fromhex(salt),
            int(rounds),
        ).hex()

        return (
            scheme == "pbkdf2_sha256"
            and hmac.compare_digest(actual, expected)
        )

    except (ValueError, TypeError):
        return False


def create_access_token(user: User) -> str:
    now = datetime.now(timezone.utc)

    token = jwt.encode(
        {
            "sub": user.username,
            "role": user.role,
            "iat": now,
            "exp": now + timedelta(
                minutes=settings.jwt_expiry_minutes,
            ),
        },
        settings.jwt_secret,
        algorithm="HS256",
    )

    if not isinstance(token, str):
        raise TypeError("JWT library returned a non-string token")

    return token


def get_current_user(
    credentials: HTTPAuthorizationCredentials | None = Depends(bearer),
    db: Session = Depends(get_db),
) -> User:
    if credentials is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Bearer token required",
            headers={"WWW-Authenticate": "Bearer"},
        )

    try:
        payload = jwt.decode(
            credentials.credentials,
            settings.jwt_secret,
            algorithms=["HS256"],
        )

        username = payload.get("sub")

        if not isinstance(username, str) or not username:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Token subject is missing or invalid",
                headers={"WWW-Authenticate": "Bearer"},
            )

    except jwt.PyJWTError as exc:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired token",
            headers={"WWW-Authenticate": "Bearer"},
        ) from exc

    user = (
        db.query(User)
        .filter(
            User.username == username,
            User.is_active.is_(True),
        )
        .first()
    )

    if user is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="User is inactive or does not exist",
            headers={"WWW-Authenticate": "Bearer"},
        )

    return cast(User, user)


def require_roles(*roles: str) -> Callable[..., User]:
    invalid_roles = set(roles) - ROLES

    if invalid_roles:
        invalid_role_names = ", ".join(sorted(invalid_roles))
        raise ValueError(
            f"Unsupported CloudGuard roles: {invalid_role_names}"
        )

    def dependency(
        user: User = Depends(get_current_user),
    ) -> User:
        if user.role not in roles:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Insufficient role for this operation",
            )

        return user

    return dependency