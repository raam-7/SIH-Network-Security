from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from backend.app.db.base import Base
from backend.app.db.models import AuditORM
from backend.app.services.audit import hash_configuration
from backend.app.services import AuditReportService, AuditRepository, AuditService


def repository():
    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(engine)
    return AuditRepository(sessionmaker(bind=engine)())


def audit_report(configuration):
    return AuditReportService().build_report(AuditService().audit_cisco_config(configuration))


COMPLIANT = "aaa new-model\nip ssh version 2\nip ssh time-out 60\nline vty 0 4\n transport input ssh\n"


def test_report_round_trip_preserves_summary_evidence_and_risk():
    repo = repository()
    report = audit_report(COMPLIANT)
    audit_id = repo.save_report(report)
    restored = repo.get_report(audit_id)

    assert restored.summary == report.summary
    assert restored.parsed_command_count == report.parsed_command_count
    assert restored.security_fact_count == report.security_fact_count
    assert restored.findings[0].evidence == report.findings[0].evidence
    assert restored.findings[0].remediation_mode == report.findings[0].remediation_mode
    assert restored.findings[0].risk_level == report.findings[0].risk_level


def test_configuration_hash_round_trip_and_raw_configuration_is_not_persisted():
    configuration = "ip ssh version 2\n"
    report = audit_report(configuration)
    report.configuration_hash = hash_configuration(configuration)
    repo = repository()
    audit_id = repo.save_report(report)

    restored = repo.get_report(audit_id)
    assert restored.configuration_hash == hash_configuration(configuration)
    audit = repo.session.get(AuditORM, audit_id)
    assert audit.configuration_hash == restored.configuration_hash
    assert not hasattr(audit, "configuration")


def test_multiple_audits_list_in_created_order_and_missing_returns_none():
    repo = repository()
    first = repo.save_report(audit_report("ip ssh version 1\n"))
    second = repo.save_report(audit_report("ip ssh version 2\n"))

    listed = repo.list_reports()
    assert len(listed) == 2
    assert repo.get_report(first) is not None
    assert repo.get_report(second) is not None
    assert repo.get_report(__import__("uuid").uuid4()) is None


def test_duplicate_rule_findings_remain_distinct_and_ordered():
    repo = repository()
    report = audit_report("ip ssh version 1\nip ssh version 2\n")
    audit_id = repo.save_report(report)
    restored = repo.get_report(audit_id)
    ssh_findings = [item for item in restored.findings if item.rule_id == "CISCO-SSH-001"]

    assert [item.observed_value for item in ssh_findings] == [1, 2]
    assert len({item.evidence.exact_text for item in ssh_findings}) == 2
