import pytest
from src.privacy.detector import RegexDetector, valid_iban, valid_tax_id
from src.privacy.service import PrivacyService
from src.privacy.vault import SessionVault
from src.core.models import SessionNotFoundError, DLPPolicyViolationError

def test_anonymize_and_restore_repeated_email():
    service=PrivacyService()
    out=service.anonymize("Kontakt max@example.com und max@example.com")
    assert out["pii_count"] == 2
    assert out["anonymized_prompt"].count("<EMAIL_ADDRESS_0>")==2
    assert service.deanonymize("An <EMAIL_ADDRESS_0>",out["session_id"])["restored_text"] == "An max@example.com"

def test_unknown_session_is_structured_domain_error():
    with pytest.raises(SessionNotFoundError): PrivacyService().deanonymize("<PERSON_0>","bad")

def test_input_limits_and_languages():
    assert PrivacyService().anonymize("x", "fr")["pii_count"] == 0
    with pytest.raises(ValueError): PrivacyService().anonymize("x"*(100*1024+1))

def test_checksums():
    assert valid_iban("DE89370400440532013000")
    assert not valid_iban("DE00370400440532013000")
    assert valid_tax_id("10000000000")
    assert not valid_tax_id("11111111111")

def test_vault_stats_are_pii_free():
    stats=PrivacyService().stats()
    assert "prompt" not in str(stats).lower()


def test_masking_strategies_are_distinct_and_non_reversible():
    service = PrivacyService()
    redact = service.anonymize("Kontakt max@example.com", strategy="redact")
    assert redact["anonymized_prompt"] == "Kontakt [REDACTED_EMAIL_ADDRESS]"
    assert "session_id" not in redact
    hashed = service.anonymize("Kontakt max@example.com", strategy="hash")
    assert hashed["anonymized_prompt"].startswith("Kontakt <HASH_EMAIL_ADDRESS_")
    assert len(hashed["anonymized_prompt"].rsplit("_", 1)[-1].rstrip(">")) == 8
    assert "session_id" not in hashed
    with pytest.raises(ValueError): service.anonymize("x@example.com", strategy="unknown")


def test_whitelist_is_literal_and_blacklist_wins():
    service = PrivacyService()
    out = service.anonymize(
        "max@example.com DEMV Systems Projekt-X",
        whitelist=["max@example.com", "DEMV Systems"],
        blacklist=["Projekt-X"],
    )
    assert out["anonymized_prompt"] == "max@example.com DEMV Systems <CUSTOM_0>"
    assert service.deanonymize(out["anonymized_prompt"], out["session_id"])["restored_text"] == "max@example.com DEMV Systems Projekt-X"


def test_whitelist_blacklist_limits_are_enforced():
    service = PrivacyService()
    with pytest.raises(ValueError): service.anonymize("x", whitelist=["x"] * 51)
    with pytest.raises(ValueError): service.anonymize("x", blacklist=["x" * 101])
    with pytest.raises(ValueError): service.anonymize("x", whitelist=[""])


def test_hash_is_deterministic_for_repeated_values():
    service = PrivacyService()
    out = service.anonymize("a@example.com a@example.com", strategy="hash")
    parts = out["anonymized_prompt"].split()
    assert parts[0] == parts[1]


def test_secret_scanning_masks_all_supported_secret_types():
    service = PrivacyService()
    values = {
        "AWS_KEY": "AKIA" + "A" * 16,
        "OPENAI_KEY": "sk-" + "a" * 20,
        "ANTHROPIC_KEY": "sk-ant-" + "b" * 20,
        "GITHUB_TOKEN": "ghp_" + "c" * 36,
        "PRIVATE_KEY": "-----BEGIN RSA PRIVATE KEY-----",
        "JWT_TOKEN": "eyJ" + "a" * 8 + ".eyJ" + "b" * 8 + "." + "c" * 8,
        "CONNECTION_STRING": "postgres://user:pass@example.test/db",
    }
    out = service.anonymize(" ".join(values.values()))
    assert out["pii_count"] == len(values)
    for entity_type in values:
        assert f"<{entity_type}_0>" in out["anonymized_prompt"]


def test_secret_scanning_block_policy_is_structured_and_aborts():
    with pytest.raises(DLPPolicyViolationError) as exc:
        PrivacyService().anonymize("credential AKIA1234567890ABCDEF", on_secret="block")
    assert exc.value.code == "prohibited_secret_detected"


def test_private_key_standard_header_is_detected():
    out = PrivacyService().anonymize("-----BEGIN RSA PRIVATE KEY-----")
    assert "<PRIVATE_KEY_0>" in out["anonymized_prompt"]


def test_secret_block_only_applies_to_prohibited_technical_secret_classes():
    # OpenAI and GitHub credentials are masked under the explicitly narrow block policy.
    out = PrivacyService().anonymize("sk-" + "a" * 20, on_secret="block")
    assert "<OPENAI_KEY_0>" in out["anonymized_prompt"]


def test_secret_policy_is_validated():
    with pytest.raises(ValueError): PrivacyService().anonymize("x", on_secret="unknown")
