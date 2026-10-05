"""create audit persistence tables"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

revision = "0001_initial_audit_tables"
down_revision = None
branch_labels = None
depends_on = None

def upgrade() -> None:
    uuid_type = postgresql.UUID(as_uuid=True)
    op.create_table("audits", sa.Column("id", uuid_type, primary_key=True), sa.Column("vendor", sa.String(64), nullable=False), sa.Column("platform", sa.String(64), nullable=False), sa.Column("overall_status", sa.String(32), nullable=False), sa.Column("total_controls", sa.Integer, nullable=False), sa.Column("passed", sa.Integer, nullable=False), sa.Column("failed", sa.Integer, nullable=False), sa.Column("manual", sa.Integer, nullable=False), sa.Column("informational", sa.Integer, nullable=False), sa.Column("parsed_command_count", sa.Integer, nullable=False), sa.Column("security_fact_count", sa.Integer, nullable=False), sa.Column("created_at", sa.DateTime(timezone=True), nullable=False))
    op.create_table("findings", sa.Column("id", uuid_type, primary_key=True), sa.Column("audit_id", uuid_type, sa.ForeignKey("audits.id", ondelete="CASCADE"), nullable=False), sa.Column("sequence", sa.Integer, nullable=False), sa.Column("rule_id", sa.String(128), nullable=False), sa.Column("result", sa.String(32), nullable=False), sa.Column("severity", sa.String(32), nullable=False), sa.Column("observed_value", sa.JSON), sa.Column("expected_value", sa.JSON), sa.Column("evidence_line_start", sa.Integer, nullable=False), sa.Column("evidence_line_end", sa.Integer, nullable=False), sa.Column("evidence_exact_text", sa.Text, nullable=False), sa.Column("title", sa.Text, nullable=False), sa.Column("description", sa.Text, nullable=False), sa.Column("remediation", sa.Text), sa.Column("risk_level", sa.String(32), nullable=False), sa.Column("is_actionable", sa.Boolean, nullable=False), sa.Column("remediation_mode", sa.String(32), nullable=False), sa.Column("rationale", sa.Text, nullable=False))
    op.create_index("ix_findings_audit_id", "findings", ["audit_id"])
    op.create_table("risk_assessments", sa.Column("id", uuid_type, primary_key=True), sa.Column("finding_id", uuid_type, sa.ForeignKey("findings.id", ondelete="CASCADE"), nullable=False), sa.Column("rule_id", sa.String(128), nullable=False), sa.Column("result", sa.String(32), nullable=False), sa.Column("severity", sa.String(32), nullable=False), sa.Column("risk_level", sa.String(32), nullable=False), sa.Column("is_actionable", sa.Boolean, nullable=False), sa.Column("rationale", sa.Text, nullable=False), sa.Column("remediation", sa.Text), sa.Column("remediation_mode", sa.String(32), nullable=False))
    op.create_index("ix_risk_assessments_finding_id", "risk_assessments", ["finding_id"], unique=True)

def downgrade() -> None:
    op.drop_table("risk_assessments")
    op.drop_index("ix_findings_audit_id", table_name="findings")
    op.drop_table("findings")
    op.drop_table("audits")
