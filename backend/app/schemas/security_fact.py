from typing import Any, Optional
from pydantic import BaseModel, Field

from .evidence import Evidence


class SecurityFact(BaseModel):
    """Canonical vendor-neutral security fact extracted from verified parsed commands."""

    vendor: str = Field(..., description="Device vendor (e.g., 'cisco', 'juniper', 'fortinet')")
    platform: str = Field(..., description="Operating system/platform (e.g., 'ios-xe', 'junos', 'fortios')")
    raw_command: str = Field(..., description="Raw configuration command string")
    security_domain: str = Field(..., description="High-level security domain (e.g., 'REMOTE_MANAGEMENT', 'AAA')")
    security_concept: str = Field(..., description="Standardized security concept (e.g., 'SSH_VERSION', 'TELNET_ACCESS')")
    property: str = Field(..., description="Specific security property evaluated (e.g., 'protocol_version')")
    value: Any = Field(..., description="Observed property value (can be int, str, bool, list, dict, or None)")
    confidence: float = Field(..., ge=0.0, le=1.0, description="Confidence score of the mapping between 0.0 and 1.0")
    mapping_source: str = Field(..., description="Source of the mapping (e.g., 'verified_vendor_mapping', 'ai_proposed')")
    evidence: Evidence = Field(..., description="Exact configuration evidence backing this fact")
    parent_context: Optional[str] = Field(
        default=None,
        description="Optional parent configuration context (e.g., 'line vty 0 4')",
    )
