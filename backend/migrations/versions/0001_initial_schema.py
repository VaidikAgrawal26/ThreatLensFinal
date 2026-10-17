"""Initial ThreatLens schema.

Revision ID: 0001_initial_schema
Revises:
"""
from alembic import op
from app import models  # noqa: F401
from app.db import Base

revision = "0001_initial_schema"
down_revision = None
branch_labels = None
depends_on = None


def upgrade() -> None:
    # Initial baseline for the prototype's complete relational schema.
    Base.metadata.create_all(bind=op.get_bind(), checkfirst=True)


def downgrade() -> None:
    Base.metadata.drop_all(bind=op.get_bind(), checkfirst=True)
