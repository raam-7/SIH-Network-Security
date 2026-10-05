import hashlib

from backend.app.services.audit import hash_configuration


def test_hash_is_deterministic_and_matches_known_sha256():
    configuration = "ip ssh version 2\n"
    expected = hashlib.sha256(configuration.encode("utf-8")).hexdigest()
    assert hash_configuration(configuration) == expected
    assert hash_configuration(configuration) == expected
    assert len(expected) == 64
    assert expected == expected.lower()


def test_hash_changes_for_configuration_and_whitespace_changes():
    assert hash_configuration("ip ssh version 2\n") != hash_configuration("ip ssh version 1\n")
    assert hash_configuration("ip ssh version 2\n") != hash_configuration("ip ssh version 2")
