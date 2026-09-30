import json


def mapping_to_security_fact(mapping, line_start=1, line_end=1):
    if mapping is None:
        return None

    return {
        "vendor": "cisco",
        "platform": "ios-xe",
        "raw_command": mapping["raw_command"],
        "security_domain": get_domain(mapping["security_concept"]),
        "security_concept": mapping["security_concept"],
        "property": mapping["property"],
        "value": mapping["value"],
        "confidence": mapping.get("score", 1.0),
        "mapping_source": "embedding_retrieval",
        "evidence": {
            "line_start": line_start,
            "line_end": line_end
        }
    }


def get_domain(concept):
    domains = {
        "SSH_VERSION": "REMOTE_MANAGEMENT",
        "TELNET_ACCESS": "REMOTE_MANAGEMENT",
        "SSH_TIMEOUT": "REMOTE_MANAGEMENT",
        "SSH_AUTH_RETRIES": "REMOTE_MANAGEMENT",
        "SSH_MAXSTARTUPS": "REMOTE_MANAGEMENT",
        "AAA": "AUTHENTICATION",
        "NTP_AUTHENTICATION": "TIME_SYNC",
        "REMOTE_SYSLOG": "LOGGING"
    }

    return domains.get(concept, "UNKNOWN")
