"""add configuration hash to audits"""

from alembic import op
import sqlalchemy as sa


revision = "0002_add_configuration_hash"
down_revision = "0001_initial_audit_tables"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column("audits", sa.Column("configuration_hash", sa.String(64), nullable=True))


def downgrade() -> None:
    op.drop_column("audits", "configuration_hash")
