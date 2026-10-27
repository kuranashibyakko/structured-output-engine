import pytest
from validator_engine import (
    VulnerabilityTicket,
    clean_json_string,
    validate_llm_json,
)


def test_clean_json_fences():
    raw = "```json\n{\"a\": 1}\n```"
    assert clean_json_string(raw) == '{"a": 1}'


def test_pydantic_custom_validators_catch_errors():
    # Missing 'CVE-' prefix and score > 10.0
    bad_payload = '{"cve_id": "2026-9999", "cvss_score": 12.0, "patched": false}'
    obj, err = validate_llm_json(bad_payload, VulnerabilityTicket)

    assert obj is None
    assert err is not None
    assert "cve_id must start with 'CVE-'" in err
    assert "cvss_score must be between 0.0 and 10.0" in err


def test_pydantic_valid_payload_normalizes_case():
    good_payload = '{"cve_id": "cve-2026-1042", "cvss_score": 7.5, "patched": true}'
    obj, err = validate_llm_json(good_payload, VulnerabilityTicket)

    assert err is None
    assert obj is not None
    assert obj.cve_id == "CVE-2026-1042"
    assert obj.cvss_score == 7.5
    assert obj.patched is True
from unittest.mock import MagicMock, patch
from instructor_lite import extract_structured


def test_extract_structured_self_heals_on_retry():
    # Mock LLM Response 1: Invalid cve_id (missing 'CVE-')
    bad_msg = MagicMock()
    bad_msg.choices[0].message.content = '{"cve_id": "2026-8812", "cvss_score": 9.4, "patched": false}'

    # Mock LLM Response 2: Fixed cve_id after receiving Pydantic ValidationError feedback
    good_msg = MagicMock()
    good_msg.choices[0].message.content = '{"cve_id": "CVE-2026-8812", "cvss_score": 9.4, "patched": false}'

    with patch("instructor_lite.groq_client.chat.completions.create", side_effect=[bad_msg, good_msg]) as mock_create:
        result = extract_structured("Test log", VulnerabilityTicket, max_retries=3)

        assert result.cve_id == "CVE-2026-8812"
        assert mock_create.call_count == 2  # Prove it failed once, appended error, and succeeded on retry!