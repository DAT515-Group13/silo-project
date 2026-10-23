"""SQLAlchemy tables. Tables only: no business logic.

Cascades are done by the database (ON DELETE), so there are no ORM relationships yet.
"""

import enum
import uuid
from datetime import datetime
from typing import Any

from sqlalchemy import (
    BigInteger,
    CheckConstraint,
    DateTime,
    Enum,
    ForeignKey,
    Index,
    Integer,
    MetaData,
    String,
    UniqueConstraint,
    Uuid,
    func,
    text,
)
from sqlalchemy.dialects.postgresql import INET, JSONB
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column


class Role(enum.StrEnum):
    """User role (PostgreSQL enum ``role``). Always read from the database, never from a token."""

    user = "user"
    team_lead = "team_lead"
    admin = "admin"


class UserStatus(enum.StrEnum):
    """Account state (PostgreSQL enum ``user_status``)."""

    pending = "pending"
    active = "active"
    rejected = "rejected"
    disabled = "disabled"


class ActorType(enum.StrEnum):
    """Who performed an audited action (PostgreSQL enum ``actor_type``)."""

    user = "user"
    anonymous = "anonymous"
    system = "system"


class Outcome(enum.StrEnum):
    """Result of an audited action (PostgreSQL enum ``outcome``)."""

    success = "success"
    denied = "denied"
    failed = "failed"


def _pg_enum(enum_class: type[enum.StrEnum], name: str) -> Enum:
    """Store the enum values (e.g. ``team_lead``), not the member names."""
    return Enum(enum_class, name=name, values_callable=lambda e: [m.value for m in e])


class Base(DeclarativeBase):
    """Declarative base with stable constraint names (needed for reliable migrations)."""

    metadata = MetaData(
        naming_convention={
            "ix": "ix_%(table_name)s_%(column_0_N_name)s",
            "uq": "uq_%(table_name)s_%(column_0_N_name)s",
            "ck": "ck_%(table_name)s_%(constraint_name)s",
            "fk": "fk_%(table_name)s_%(column_0_N_name)s_%(referred_table_name)s",
            "pk": "pk_%(table_name)s",
        }
    )

    # All timestamps are timezone-aware UTC.
    type_annotation_map = {datetime: DateTime(timezone=True)}


class User(Base):
    """An account. ``used_bytes`` is the storage quota counter, updated atomically."""

    __tablename__ = "users"
    __table_args__ = (CheckConstraint("used_bytes >= 0", name="used_bytes_non_negative"),)

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    # Stored lowercase; the format is checked by the schemas, not by the database.
    username: Mapped[str] = mapped_column(String(32), unique=True)
    password_hash: Mapped[str] = mapped_column(String(255))
    role: Mapped[Role] = mapped_column(
        _pg_enum(Role, "role"), default=Role.user, server_default=Role.user.value
    )
    status: Mapped[UserStatus] = mapped_column(
        _pg_enum(UserStatus, "user_status"),
        default=UserStatus.pending,
        server_default=UserStatus.pending.value,
    )
    approved_by: Mapped[int | None] = mapped_column(ForeignKey("users.id", ondelete="SET NULL"))
    approved_at: Mapped[datetime | None]
    failed_login_count: Mapped[int] = mapped_column(Integer, default=0, server_default="0")
    locked_until: Mapped[datetime | None]
    last_login_at: Mapped[datetime | None]
    used_bytes: Mapped[int] = mapped_column(BigInteger, default=0, server_default="0")
    created_at: Mapped[datetime] = mapped_column(server_default=func.now())


class AuthSession(Base):
    """One database-backed login session per device; revoking it kills its access tokens."""

    __tablename__ = "auth_sessions"
    __table_args__ = (Index("ix_auth_sessions_user_id_revoked_at", "user_id", "revoked_at"),)

    # Value of the `sid` claim; set by the application.
    id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True)
    user_id: Mapped[int] = mapped_column(ForeignKey("users.id", ondelete="CASCADE"))
    created_at: Mapped[datetime] = mapped_column(server_default=func.now())
    last_used_at: Mapped[datetime]
    expires_at: Mapped[datetime]
    revoked_at: Mapped[datetime | None]
    # logout, logout_all, reuse_detected, user_disabled, admin, session_limit
    revoked_reason: Mapped[str | None] = mapped_column(String(30))
    ip: Mapped[str | None] = mapped_column(INET)
    user_agent: Mapped[str | None] = mapped_column(String(255))


class RefreshToken(Base):
    """A single-use refresh token. Only its SHA-256 is stored, never the token itself."""

    __tablename__ = "refresh_tokens"

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True)
    session_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("auth_sessions.id", ondelete="CASCADE"), index=True
    )
    token_hash: Mapped[str] = mapped_column(String(64), unique=True)  # SHA-256 hex
    created_at: Mapped[datetime] = mapped_column(server_default=func.now())
    # Never later than the session's expires_at: enforced by the service.
    expires_at: Mapped[datetime]
    used_at: Mapped[datetime | None]
    replaced_by_id: Mapped[int | None] = mapped_column(ForeignKey("refresh_tokens.id"))


class Team(Base):
    """A group of users that files can be shared with. Names are unique per owner."""

    __tablename__ = "teams"
    __table_args__ = (UniqueConstraint("owner_id", "name"),)

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    name: Mapped[str] = mapped_column(String(100))
    owner_id: Mapped[int] = mapped_column(ForeignKey("users.id", ondelete="CASCADE"), index=True)
    created_at: Mapped[datetime] = mapped_column(server_default=func.now())


class TeamMember(Base):
    """Membership of a user in a team (composite primary key)."""

    __tablename__ = "team_members"

    team_id: Mapped[int] = mapped_column(
        ForeignKey("teams.id", ondelete="CASCADE"), primary_key=True
    )
    user_id: Mapped[int] = mapped_column(
        ForeignKey("users.id", ondelete="CASCADE"), primary_key=True, index=True
    )
    added_at: Mapped[datetime] = mapped_column(server_default=func.now())


class File(Base):
    """Metadata of a stored file. The bytes live in blob storage under ``blob_name``."""

    __tablename__ = "files"
    __table_args__ = (CheckConstraint("size_bytes >= 0", name="size_bytes_non_negative"),)

    id: Mapped[uuid.UUID] = mapped_column(
        Uuid, primary_key=True, default=uuid.uuid4, server_default=text("gen_random_uuid()")
    )
    owner_id: Mapped[int] = mapped_column(ForeignKey("users.id", ondelete="CASCADE"), index=True)
    filename: Mapped[str] = mapped_column(String(255))  # sanitized
    content_type: Mapped[str] = mapped_column(String(127))
    size_bytes: Mapped[int] = mapped_column(BigInteger)
    # Random UUID, never derived from user input.
    blob_name: Mapped[str] = mapped_column(String(64), unique=True)
    created_at: Mapped[datetime] = mapped_column(server_default=func.now(), index=True)


class FileShare(Base):
    """A file shared with a team (composite primary key)."""

    __tablename__ = "file_shares"

    file_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("files.id", ondelete="CASCADE"), primary_key=True
    )
    team_id: Mapped[int] = mapped_column(
        ForeignKey("teams.id", ondelete="CASCADE"), primary_key=True, index=True
    )
    shared_at: Mapped[datetime] = mapped_column(server_default=func.now())


class ShareLink(Base):
    """A public download link. Only the SHA-256 of the token is stored."""

    __tablename__ = "share_links"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    file_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("files.id", ondelete="CASCADE"), index=True
    )
    token_hash: Mapped[str] = mapped_column(String(64), unique=True)  # SHA-256 hex
    created_by: Mapped[int] = mapped_column(ForeignKey("users.id", ondelete="CASCADE"))
    expires_at: Mapped[datetime]
    revoked_at: Mapped[datetime | None]
    download_count: Mapped[int] = mapped_column(Integer, default=0, server_default="0")
    created_at: Mapped[datetime] = mapped_column(server_default=func.now())


class AuditLog(Base):
    """One audit entry. Actor and target names are snapshots, so rows survive deletions."""

    __tablename__ = "audit_log"
    __table_args__ = (
        Index("ix_audit_log_created_at", text("created_at DESC")),
        Index("ix_audit_log_actor_id_created_at", "actor_id", text("created_at DESC")),
        Index("ix_audit_log_action_created_at", "action", text("created_at DESC")),
        Index("ix_audit_log_target_type_target_id", "target_type", "target_id"),
    )

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True)
    created_at: Mapped[datetime] = mapped_column(server_default=func.now())
    actor_type: Mapped[ActorType] = mapped_column(_pg_enum(ActorType, "actor_type"))
    actor_id: Mapped[int | None] = mapped_column(ForeignKey("users.id", ondelete="SET NULL"))
    actor_username: Mapped[str | None] = mapped_column(String(32))  # snapshot
    action: Mapped[str] = mapped_column(String(50))
    outcome: Mapped[Outcome] = mapped_column(_pg_enum(Outcome, "outcome"))
    # file, team, user, link, session
    target_type: Mapped[str | None] = mapped_column(String(20))
    target_id: Mapped[str | None] = mapped_column(String(64))
    target_label: Mapped[str | None] = mapped_column(String(255))  # snapshot
    ip: Mapped[str | None] = mapped_column(INET)
    request_id: Mapped[str | None] = mapped_column(String(36))
    details: Mapped[dict[str, Any] | None] = mapped_column(JSONB)
