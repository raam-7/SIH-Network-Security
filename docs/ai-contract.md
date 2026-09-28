# AI SecurityFact Contract

The AI converts vendor-specific configuration into this canonical format:

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
    "line_end": 5
  }
}