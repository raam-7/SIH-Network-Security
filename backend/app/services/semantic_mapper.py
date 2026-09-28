import json


def load_mappings():
    with open("knowledge_base/mappings/cisco_mappings.json") as f:
        return json.load(f)


def map_command(raw_command):
    mappings = load_mappings()

    for mapping in mappings:
        if mapping["raw_command"] == raw_command:
            return mapping

    return None

def to_security_fact(mapping, line_start, line_end):
    if mapping is None:
        return None

    return {
        "vendor": mapping["vendor"],
        "platform": mapping["platform"],
        "raw_command": mapping["raw_command"],
        "security_domain": "REMOTE_MANAGEMENT",
        "security_concept": mapping["security_concept"],
        "property": mapping["property"],
        "value": mapping["value"],
        "confidence": 1.0,
        "mapping_source": "verified_vendor_mapping",
        "evidence": {
            "line_start": line_start,
            "line_end": line_end
        }
    }
def process_command(raw_command, line_start, line_end):
    mapping = map_command(raw_command)
    return to_security_fact(mapping, line_start, line_end)
