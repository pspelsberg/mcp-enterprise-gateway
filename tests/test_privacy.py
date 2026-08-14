import pytest
from src.privacy.detector import RegexDetector, valid_iban, valid_tax_id
from src.privacy.service import PrivacyService
from src.privacy.vault import SessionVault
from src.core.models import SessionNotFoundError

def test_anonymize_and_restore_repeated_email():
    service=PrivacyService()
    out=service.anonymize("Kontakt max@example.com und max@example.com")
    assert out["pii_count"] == 2
    assert out["anonymized_prompt"].count("<EMAIL_ADDRESS_0>")==2
    assert service.deanonymize("An <EMAIL_ADDRESS_0>",out["session_id"])["restored_text"] == "An max@example.com"

def test_unknown_session_is_structured_domain_error():
    with pytest.raises(SessionNotFoundError): PrivacyService().deanonymize("<PERSON_0>","bad")

def test_input_limits_and_languages():
    with pytest.raises(ValueError): PrivacyService().anonymize("x","fr")
    with pytest.raises(ValueError): PrivacyService().anonymize("x"*(100*1024+1))

def test_checksums():
    assert valid_iban("DE89370400440532013000")
    assert not valid_iban("DE00370400440532013000")
    assert valid_tax_id("10000000000")
    assert not valid_tax_id("11111111111")

def test_vault_stats_are_pii_free():
    stats=PrivacyService().stats()
    assert "prompt" not in str(stats).lower()
