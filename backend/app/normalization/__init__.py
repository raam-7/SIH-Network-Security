"""Deterministic semantic normalization for parsed vendor configurations."""

from .cisco import CiscoSecurityFactMapper, map_cisco_command

__all__ = ["CiscoSecurityFactMapper", "map_cisco_command"]
