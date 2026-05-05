"""Initial schema for honeypot platform."""

from __future__ import annotations

from alembic import op

from pipeline.models import Base

revision = "202405010001"
down_revision = None
branch_labels = None
depends_on = None


def upgrade() -> None:
    bind = op.get_bind()
    Base.metadata.create_all(bind)


def downgrade() -> None:
    bind = op.get_bind()
    Base.metadata.drop_all(bind)
