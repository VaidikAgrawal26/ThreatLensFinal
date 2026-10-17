"""Persist failed login counters for account-level throttling.

Revision ID: 0003_login_throttle
Revises: 0002_scan_ownership
"""
import sqlalchemy as sa
from alembic import op
from sqlalchemy import inspect

revision = "0003_login_throttle"
down_revision = "0002_scan_ownership"
branch_labels = None
depends_on = None


def upgrade() -> None:
    if "login_attempts" not in inspect(op.get_bind()).get_table_names():
        op.create_table(
            "login_attempts",
            sa.Column("id", sa.Integer(), primary_key=True),
            sa.Column("email", sa.String(length=255), nullable=False),
            sa.Column("attempted_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        )
        op.create_index("ix_login_attempts_email", "login_attempts", ["email"], unique=False)
        op.create_index("ix_login_attempts_attempted_at", "login_attempts", ["attempted_at"], unique=False)


def downgrade() -> None:
    if "login_attempts" in inspect(op.get_bind()).get_table_names():
        op.drop_index("ix_login_attempts_attempted_at", table_name="login_attempts")
        op.drop_index("ix_login_attempts_email", table_name="login_attempts")
        op.drop_table("login_attempts")
