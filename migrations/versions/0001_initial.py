"""Initial schema: all tables.

Revision ID: 0001
Revises:
"""

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision = "0001"
down_revision = None
branch_labels = None
depends_on = None

# The enum types are created and dropped with plain SQL: this also works in offline (--sql) mode.
# Their members must stay in sync with the StrEnums in app/models.py.
ENUMS = {
    "role": ("user", "team_lead", "admin"),
    "user_status": ("pending", "active", "rejected", "disabled"),
    "actor_type": ("user", "anonymous", "system"),
    "outcome": ("success", "denied", "failed"),
}


def _enum(name: str) -> postgresql.ENUM:
    """Return a column type for an enum that already exists (``create_type=False``)."""
    return postgresql.ENUM(*ENUMS[name], name=name, create_type=False)


def _timestamp() -> sa.DateTime:
    """All timestamps are timezone-aware."""
    return sa.DateTime(timezone=True)


def _created_at() -> sa.Column:
    """The ``created_at`` column shared by most tables."""
    return sa.Column("created_at", _timestamp(), server_default=sa.func.now(), nullable=False)


def upgrade() -> None:
    """Create the enum types, all tables and all indexes."""
    for name, members in ENUMS.items():
        values = ", ".join(f"'{m}'" for m in members)
        op.execute(f"CREATE TYPE {name} AS ENUM ({values})")

    op.create_table(
        "users",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("username", sa.String(32), nullable=False),
        sa.Column("password_hash", sa.String(255), nullable=False),
        sa.Column("role", _enum("role"), server_default="user", nullable=False),
        sa.Column("status", _enum("user_status"), server_default="pending", nullable=False),
        sa.Column("approved_by", sa.Integer(), nullable=True),
        sa.Column("approved_at", _timestamp(), nullable=True),
        sa.Column("failed_login_count", sa.Integer(), server_default="0", nullable=False),
        sa.Column("locked_until", _timestamp(), nullable=True),
        sa.Column("last_login_at", _timestamp(), nullable=True),
        sa.Column("used_bytes", sa.BigInteger(), server_default="0", nullable=False),
        _created_at(),
        sa.PrimaryKeyConstraint("id", name="pk_users"),
        sa.UniqueConstraint("username", name="uq_users_username"),
        sa.ForeignKeyConstraint(
            ["approved_by"], ["users.id"], name="fk_users_approved_by_users", ondelete="SET NULL"
        ),
        sa.CheckConstraint("used_bytes >= 0", name="ck_users_used_bytes_non_negative"),
    )

    op.create_table(
        "auth_sessions",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("user_id", sa.Integer(), nullable=False),
        _created_at(),
        sa.Column("last_used_at", _timestamp(), nullable=False),
        sa.Column("expires_at", _timestamp(), nullable=False),
        sa.Column("revoked_at", _timestamp(), nullable=True),
        sa.Column("revoked_reason", sa.String(30), nullable=True),
        sa.Column("ip", postgresql.INET(), nullable=True),
        sa.Column("user_agent", sa.String(255), nullable=True),
        sa.PrimaryKeyConstraint("id", name="pk_auth_sessions"),
        sa.ForeignKeyConstraint(
            ["user_id"], ["users.id"], name="fk_auth_sessions_user_id_users", ondelete="CASCADE"
        ),
    )
    op.create_index(
        "ix_auth_sessions_user_id_revoked_at", "auth_sessions", ["user_id", "revoked_at"]
    )

    op.create_table(
        "refresh_tokens",
        sa.Column("id", sa.BigInteger(), nullable=False),
        sa.Column("session_id", sa.Uuid(), nullable=False),
        sa.Column("token_hash", sa.String(64), nullable=False),
        _created_at(),
        sa.Column("expires_at", _timestamp(), nullable=False),
        sa.Column("used_at", _timestamp(), nullable=True),
        sa.Column("replaced_by_id", sa.BigInteger(), nullable=True),
        sa.PrimaryKeyConstraint("id", name="pk_refresh_tokens"),
        sa.UniqueConstraint("token_hash", name="uq_refresh_tokens_token_hash"),
        sa.ForeignKeyConstraint(
            ["session_id"],
            ["auth_sessions.id"],
            name="fk_refresh_tokens_session_id_auth_sessions",
            ondelete="CASCADE",
        ),
        sa.ForeignKeyConstraint(
            ["replaced_by_id"],
            ["refresh_tokens.id"],
            name="fk_refresh_tokens_replaced_by_id_refresh_tokens",
        ),
    )
    op.create_index("ix_refresh_tokens_session_id", "refresh_tokens", ["session_id"])

    op.create_table(
        "teams",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("name", sa.String(100), nullable=False),
        sa.Column("owner_id", sa.Integer(), nullable=False),
        _created_at(),
        sa.PrimaryKeyConstraint("id", name="pk_teams"),
        sa.UniqueConstraint("owner_id", "name", name="uq_teams_owner_id_name"),
        sa.ForeignKeyConstraint(
            ["owner_id"], ["users.id"], name="fk_teams_owner_id_users", ondelete="CASCADE"
        ),
    )
    op.create_index("ix_teams_owner_id", "teams", ["owner_id"])

    op.create_table(
        "team_members",
        sa.Column("team_id", sa.Integer(), nullable=False),
        sa.Column("user_id", sa.Integer(), nullable=False),
        sa.Column("added_at", _timestamp(), server_default=sa.func.now(), nullable=False),
        sa.PrimaryKeyConstraint("team_id", "user_id", name="pk_team_members"),
        sa.ForeignKeyConstraint(
            ["team_id"], ["teams.id"], name="fk_team_members_team_id_teams", ondelete="CASCADE"
        ),
        sa.ForeignKeyConstraint(
            ["user_id"], ["users.id"], name="fk_team_members_user_id_users", ondelete="CASCADE"
        ),
    )
    op.create_index("ix_team_members_user_id", "team_members", ["user_id"])

    op.create_table(
        "files",
        sa.Column("id", sa.Uuid(), server_default=sa.text("gen_random_uuid()"), nullable=False),
        sa.Column("owner_id", sa.Integer(), nullable=False),
        sa.Column("filename", sa.String(255), nullable=False),
        sa.Column("content_type", sa.String(127), nullable=False),
        sa.Column("size_bytes", sa.BigInteger(), nullable=False),
        sa.Column("blob_name", sa.String(64), nullable=False),
        _created_at(),
        sa.PrimaryKeyConstraint("id", name="pk_files"),
        sa.UniqueConstraint("blob_name", name="uq_files_blob_name"),
        sa.ForeignKeyConstraint(
            ["owner_id"], ["users.id"], name="fk_files_owner_id_users", ondelete="CASCADE"
        ),
        sa.CheckConstraint("size_bytes >= 0", name="ck_files_size_bytes_non_negative"),
    )
    op.create_index("ix_files_owner_id", "files", ["owner_id"])
    op.create_index("ix_files_created_at", "files", ["created_at"])

    op.create_table(
        "file_shares",
        sa.Column("file_id", sa.Uuid(), nullable=False),
        sa.Column("team_id", sa.Integer(), nullable=False),
        sa.Column("shared_at", _timestamp(), server_default=sa.func.now(), nullable=False),
        sa.PrimaryKeyConstraint("file_id", "team_id", name="pk_file_shares"),
        sa.ForeignKeyConstraint(
            ["file_id"], ["files.id"], name="fk_file_shares_file_id_files", ondelete="CASCADE"
        ),
        sa.ForeignKeyConstraint(
            ["team_id"], ["teams.id"], name="fk_file_shares_team_id_teams", ondelete="CASCADE"
        ),
    )
    op.create_index("ix_file_shares_team_id", "file_shares", ["team_id"])

    op.create_table(
        "share_links",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("file_id", sa.Uuid(), nullable=False),
        sa.Column("token_hash", sa.String(64), nullable=False),
        sa.Column("created_by", sa.Integer(), nullable=False),
        sa.Column("expires_at", _timestamp(), nullable=False),
        sa.Column("revoked_at", _timestamp(), nullable=True),
        sa.Column("download_count", sa.Integer(), server_default="0", nullable=False),
        _created_at(),
        sa.PrimaryKeyConstraint("id", name="pk_share_links"),
        sa.UniqueConstraint("token_hash", name="uq_share_links_token_hash"),
        sa.ForeignKeyConstraint(
            ["file_id"], ["files.id"], name="fk_share_links_file_id_files", ondelete="CASCADE"
        ),
        sa.ForeignKeyConstraint(
            ["created_by"], ["users.id"], name="fk_share_links_created_by_users", ondelete="CASCADE"
        ),
    )
    op.create_index("ix_share_links_file_id", "share_links", ["file_id"])

    op.create_table(
        "audit_log",
        sa.Column("id", sa.BigInteger(), nullable=False),
        _created_at(),
        sa.Column("actor_type", _enum("actor_type"), nullable=False),
        sa.Column("actor_id", sa.Integer(), nullable=True),
        sa.Column("actor_username", sa.String(32), nullable=True),
        sa.Column("action", sa.String(50), nullable=False),
        sa.Column("outcome", _enum("outcome"), nullable=False),
        sa.Column("target_type", sa.String(20), nullable=True),
        sa.Column("target_id", sa.String(64), nullable=True),
        sa.Column("target_label", sa.String(255), nullable=True),
        sa.Column("ip", postgresql.INET(), nullable=True),
        sa.Column("request_id", sa.String(36), nullable=True),
        sa.Column("details", postgresql.JSONB(), nullable=True),
        sa.PrimaryKeyConstraint("id", name="pk_audit_log"),
        sa.ForeignKeyConstraint(
            ["actor_id"], ["users.id"], name="fk_audit_log_actor_id_users", ondelete="SET NULL"
        ),
    )
    # Descending indexes on created_at, for newest-first audit listings.
    op.create_index("ix_audit_log_created_at", "audit_log", [sa.text("created_at DESC")])
    op.create_index(
        "ix_audit_log_actor_id_created_at", "audit_log", ["actor_id", sa.text("created_at DESC")]
    )
    op.create_index(
        "ix_audit_log_action_created_at", "audit_log", ["action", sa.text("created_at DESC")]
    )
    op.create_index("ix_audit_log_target_type_target_id", "audit_log", ["target_type", "target_id"])


def downgrade() -> None:
    """Drop everything created by ``upgrade``, children before parents."""
    for table in (
        "audit_log",
        "share_links",
        "file_shares",
        "files",
        "team_members",
        "teams",
        "refresh_tokens",
        "auth_sessions",
        "users",
    ):
        op.drop_table(table)
    for name in ENUMS:
        op.execute(f"DROP TYPE {name}")
