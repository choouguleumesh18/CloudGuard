from datetime import datetime, timezone
from typing import TYPE_CHECKING
from uuid import uuid4

from sqlalchemy import DateTime, ForeignKey, JSON, String, Text
from sqlalchemy.orm import Mapped, mapped_column, relationship

from cloudguard.db.base import Base

if TYPE_CHECKING:
    from cloudguard.models.scan import Scan


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


class Finding(Base):
    __tablename__ = "findings"

    id: Mapped[str] = mapped_column(
        String(36),
        primary_key=True,
        default=lambda: str(uuid4()),
    )

    scan_id: Mapped[str] = mapped_column(
        String(36),
        ForeignKey("scans.id"),
        nullable=False,
        index=True,
    )

    resource_id: Mapped[str] = mapped_column(
        String(500),
        nullable=False,
        index=True,
    )

    resource_name: Mapped[str] = mapped_column(
        String(200),
        nullable=False,
    )

    rule_id: Mapped[str] = mapped_column(
        String(100),
        nullable=False,
    )

    severity: Mapped[str] = mapped_column(
        String(20),
        nullable=False,
    )

    description: Mapped[str] = mapped_column(
        Text,
        nullable=False,
    )

    status: Mapped[str] = mapped_column(
        String(30),
        default="open",
        nullable=False,
    )

    details: Mapped[dict] = mapped_column(
        JSON,
        default=dict,
        nullable=False,
    )

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=utc_now,
        nullable=False,
    )

    scan: Mapped["Scan"] = relationship(
        back_populates="findings",
    )