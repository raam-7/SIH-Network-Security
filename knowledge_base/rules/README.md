# Compliance Rules

Rules in this directory represent authoritative security requirements.

Each rule should contain:

- rule_id
- framework
- framework_version
- vendor
- product/version
- security_concept
- operator
- expected_value
- severity
- check_text
- remediation
- source_ref

The LLM must not create the final PASS/FAIL/MANUAL decision.
The deterministic compliance engine evaluates these rules.