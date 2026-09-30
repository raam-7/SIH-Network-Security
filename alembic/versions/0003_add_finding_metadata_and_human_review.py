"""add persisted finding metadata and human reviews

Revision ID: 0003_add_finding_metadata_and_human_review
Revises: 0002_add_configuration_hash
"""
from alembic import op
import sqlalchemy as sa

revision = "0003_finding_metadata_reviews"
down_revision = "0002_add_configuration_hash"
branch_labels = None
depends_on = None

def upgrade() -> None:
    op.add_column("findings", sa.Column("evidence_score", sa.Integer(), nullable=True))
    op.add_column("findings", sa.Column("evidence_type", sa.Text(), nullable=True))
    op.add_column("findings", sa.Column("semantic_concept", sa.String(length=128), nullable=True))
    op.add_column("findings", sa.Column("semantic_property", sa.String(length=128), nullable=True))
    op.add_column("findings", sa.Column("semantic_value", sa.JSON(), nullable=True))
    op.add_column("findings", sa.Column("ai_confidence", sa.Float(), nullable=True))
    op.add_column("findings", sa.Column("mapping_source", sa.String(length=128), nullable=True))
    op.create_table(
        "human_reviews",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("audit_id", sa.Uuid(), nullable=False),
        sa.Column("finding_id", sa.Uuid(), nullable=False),
        sa.Column("rule_id", sa.String(length=128), nullable=False),
        sa.Column("original_result", sa.String(length=32), nullable=False),
        sa.Column("decision", sa.String(length=32), nullable=False),
        sa.Column("reviewer", sa.String(length=255), nullable=False),
        sa.Column("reviewer_reason", sa.Text(), nullable=False),
        sa.Column("status", sa.String(length=32), nullable=False, server_default="REVIEWED"),
        sa.Column("reviewed_at", sa.DateTime(timezone=True), nullable=True),
        sa.ForeignKeyConstraint(["audit_id"], ["audits.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["finding_id"], ["findings.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("finding_id"),
    )
    op.create_index("ix_human_reviews_audit_id", "human_reviews", ["audit_id"])
    op.create_index("ix_human_reviews_finding_id", "human_reviews", ["finding_id"])

def downgrade() -> None:
    op.drop_index("ix_human_reviews_finding_id", table_name="human_reviews")
    op.drop_index("ix_human_reviews_audit_id", table_name="human_reviews")
    op.drop_table("human_reviews")
    for column in ("mapping_source", "ai_confidence", "semantic_value", "semantic_property", "semantic_concept", "evidence_type", "evidence_score"):
        op.drop_column("findings", column)
