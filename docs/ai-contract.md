# AI SecurityFact Contract & Integration Specification

## 1. Architectural Boundary & Principle

The AI / Knowledge Base (KB) layer serves as **supporting knowledge and semantic translation**, NOT an authoritative compliance arbiter.

The pipeline architecture is strictly:
```
Cisco configuration
        ↓
   CiscoParser
        ↓
  ParsedCommand
        ↓
AI / Verified Semantic Mapping
        ↓
 canonical SecurityFact
        ↓
Deterministic Compliance Engine
```

### Constraints & Role Boundaries
- **AI / KB May**:
  - Propose semantic translations from vendor-specific syntax into canonical `SecurityFact` candidates.
  - Retrieve documentation and similar verified syntax mappings from reference sources.
  - Suggest confidence scores based on semantic similarity or matching rules.
  - Flag unknown or unrecognized syntax for human review.
- **AI / KB May NOT**:
  - Make `PASS`, `FAIL`, or `MANUAL` compliance decisions.
  - Fabricate configuration lines or invent evidence.
  - Override deterministic compliance engine rules or verified vendor mappings.
  - Circumvent or modify the canonical backend data contracts.

---

## 2. Canonical SecurityFact Contract

The runtime contract is authoritatively defined in Python by:
- [`backend.app.schemas.security_fact.SecurityFact`](file:///C:/SIH-Network-Security/backend/app/schemas/security_fact.py)
- [`backend.app.schemas.evidence.Evidence`](file:///C:/SIH-Network-Security/backend/app/schemas/evidence.py)

Any payload proposed by AI or semantic lookup must strictly conform to this schema:

```json
{
  "vendor": "cisco",
  "platform": "ios-xe",
  "raw_command": "ip ssh version 2",
  "security_domain": "REMOTE_MANAGEMENT",
  "security_concept": "SSH_VERSION",
  "property": "protocol_version",
  "value": 2,
  "confidence": 1.0,
  "mapping_source": "verified_vendor_mapping",
  "evidence": {
    "line_start": 5,
    "line_end": 5,
    "exact_text": "ip ssh version 2"
  },
  "parent_context": null
}
```

### Field Definitions

| Field | Type | Validation / Description |
| :--- | :--- | :--- |
| `vendor` | `str` | Normalized vendor identifier (e.g., `"cisco"`, `"juniper"`). |
| `platform` | `str` | Operating system/platform (e.g., `"ios-xe"`, `"ios"`, `"junos"`). |
| `raw_command` | `str` | Exact uninterpreted command text extracted from device configuration. |
| `security_domain` | `str` | High-level taxonomy domain (e.g., `"REMOTE_MANAGEMENT"`, `"AAA"`, `"TIME_SYNC"`). |
| `security_concept`| `str` | Standardized canonical security concept (e.g., `"SSH_VERSION"`, `"TELNET_ACCESS"`). |
| `property` | `str` | Evaluated configuration attribute (e.g., `"protocol_version"`, `"enabled"`). |
| `value` | `Any` | Observed property value (`int`, `str`, `bool`, `list`, `dict`, or `null`). |
| `confidence` | `float` | Confidence score bounded between `0.0` and `1.0`. High-confidence verified mappings use `1.0`. |
| `mapping_source` | `str` | Origin of mapping (`"verified_vendor_mapping"`, `"semantic_inference"`, etc.). |
| `evidence` | `Evidence` | Exact configuration evidence: `line_start` (>= 1), `line_end` (>= line_start), and `exact_text`. |
| `parent_context` | `Optional[str]` | Active parent configuration block (e.g., `"line vty 0 4"`), or `null` for global. |

---

## 3. Unknown Syntax & Low Confidence Handling

If a configuration command has no verified mapping or low inference confidence (< 0.85):
- `confidence` is marked accordingly or mapped to an explicit needs-review state.
- The pipeline delegates the command to `MANUAL` / human validation.
- The system never guesses security attributes or invents default values.
