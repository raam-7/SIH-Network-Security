# Compliance Rules (Draft & Reference Specifications)

Rules in this directory define baseline security requirements for audit evaluation.

> [!WARNING]
> **Framework Attribution Pending Verification**
> Rules currently referencing framework benchmarks (e.g., `CISCO-SSH-001` referencing `"CIS"`) are **draft reference specifications**.
> Fields marked with `TO_BE_VERIFIED` (such as `framework_version` and `source_ref`) indicate that **official CIS/NIST section attribution has not yet been audited**.
> These controls must **NOT** be claimed or presented as verified CIS or NIST certified rules until formal benchmark mapping is completed.

## Rule Schema Attributes

Each rule definition includes:
- `rule_id`: Unique identifier (e.g., `"CISCO-SSH-001"`)
- `framework`: Standard / benchmark name (draft attribution)
- `framework_version`: Benchmark version (or `TO_BE_VERIFIED`)
- `vendor`: Target device vendor
- `product`: Target platform/OS
- `security_concept`: Standardized canonical concept (`SSH_VERSION`)
- `operator`: Comparison operator (`EQUALS`, `NOT_EQUALS`, etc.)
- `expected_value`: Compliant target value
- `severity`: Finding severity (`INFO`, `LOW`, `MEDIUM`, `HIGH`, `CRITICAL`)
- `check_text`: Human-readable check summary
- `remediation`: Recommended remediation command
- `source_ref`: Official benchmark section reference (or `TO_BE_VERIFIED`)

## Architecture Reminder

- The deterministic compliance engine evaluates rules against canonical `SecurityFact` objects.
- The LLM does NOT make final `PASS`, `FAIL`, or `MANUAL` decisions.