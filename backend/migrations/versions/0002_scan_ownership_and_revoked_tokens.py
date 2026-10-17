"""Add scan ownership and persistent token revocation.

Revision ID: 0002_scan_ownership
Revises: 0001_initial_schema
"""
import sqlalchemy as sa
from alembic import op
from sqlalchemy import inspect

revision = "0002_scan_ownership"
down_revision = "0001_initial_schema"
branch_labels = None
depends_on = None


def upgrade() -> None:
    bind = op.get_bind()
    inspector = inspect(bind)
    if "scans" in inspector.get_table_names():
        columns = {column["name"] for column in inspector.get_columns("scans")}
        if "uploaded_by" not in columns:
            with op.batch_alter_table("scans") as batch_op:
                batch_op.add_column(sa.Column("uploaded_by", sa.Integer(), nullable=True))
                batch_op.create_foreign_key("fk_scans_uploaded_by_users", "users", ["uploaded_by"], ["id"])
            op.create_index("ix_scans_uploaded_by", "scans", ["uploaded_by"], unique=False)
    if "revoked_tokens" not in inspector.get_table_names():
        op.create_table(
            "revoked_tokens",
            sa.Column("jti", sa.String(length=64), primary_key=True),
            sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
            sa.Column("revoked_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        )
        op.create_index("ix_revoked_tokens_expires_at", "revoked_tokens", ["expires_at"], unique=False)


def downgrade() -> None:
    bind = op.get_bind()
    inspector = inspect(bind)
    if "revoked_tokens" in inspector.get_table_names():
        op.drop_index("ix_revoked_tokens_expires_at", table_name="revoked_tokens")
        op.drop_table("revoked_tokens")
    if "scans" in inspector.get_table_names():
        columns = {column["name"] for column in inspector.get_columns("scans")}
        if "uploaded_by" in columns:
            op.drop_index("ix_scans_uploaded_by", table_name="scans")
            with op.batch_alter_table("scans") as batch_op:
                batch_op.drop_constraint("fk_scans_uploaded_by_users", type_="foreignkey")
                batch_op.drop_column("uploaded_by")
