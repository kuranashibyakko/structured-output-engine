import json
import re
from typing import Type, TypeVar
from pydantic import BaseModel, Field, ValidationError, field_validator

T = TypeVar("T", bound=BaseModel)


def clean_json_string(raw_text: str) -> str:
    """Strips markdown ```json ... ``` fences if the LLM includes them."""
    match = re.search(r"```(?:json)?\s*(.*?)```", raw_text, re.DOTALL | re.IGNORECASE)
    return match.group(1).strip() if match else raw_text.strip()


def build_schema_system_prompt(response_model: Type[T]) -> str:
    """Generates a strict system prompt containing the Pydantic model's JSON schema."""
    schema_dict = response_model.model_json_schema()
    schema_string = json.dumps(schema_dict, indent=2)

    return (
        "Output ONLY valid JSON conforming to this schema.\n"
        "Do not include Markdown fences or extra text.\n"
        f"JSON schema:\n{schema_string}"
    )


def validate_llm_json(raw_text: str, response_model: Type[T]) -> tuple[T | None, str | None]:
    """Validates raw LLM text against `response_model`.
    Returns `(validated_instance, None)` on success, or `(None, formatted_error_str)` on failure.
    """
    cleaned = clean_json_string(raw_text)

    try:
        instance = response_model.model_validate_json(cleaned)
        return instance, None
    except ValidationError as e:
        return None, str(e)


# =====================================================================
# SELF-TEST SCHEMA WITH STRICT CUSTOM VALIDATION RULES
# =====================================================================
class VulnerabilityTicket(BaseModel):
    cve_id: str = Field(description="CVE identifier starting with 'CVE-'")
    cvss_score: float = Field(description="Severity score between 0.0 and 10.0")
    patched: bool = Field(description="Whether a patch is currently applied")

    @field_validator("cve_id")
    @classmethod
    def must_start_with_cve(cls, v: str) -> str:
        if not v.upper().startswith("CVE-"):
            raise ValueError(
                "cve_id must start with 'CVE-' (e.g., CVE-2026-1042)"
            )
        return v.upper()
    @field_validator("cvss_score")
    @classmethod
    def score_must_be_valid_range(cls, v: float) -> float:
        if not (0.0 <= v <= 10.0):
            raise ValueError("cvss_score must be between 0.0 and 10.0")
        return v


if __name__ == "__main__":
    print("--- 1. Generated Schema Prompt ---")
    print(build_schema_system_prompt(VulnerabilityTicket))

    print("\n--- 2. Testing Bad LLM Output (Should Catch 3 Validation Errors) ---")
    bad_json = '```json\n{"cve_id": "BUG-999", "cvss_score": 14.5, "patched": "yes_maybe"}\n```'
    obj, err = validate_llm_json(bad_json, VulnerabilityTicket)
    print("Validated Object:", obj)
    print("Captured Error Feedback for LLM:\n", err)

    print("\n--- 3. Testing Good LLM Output ---")
    good_json = '{"cve_id": "cve-2026-4091", "cvss_score": 8.8, "patched": false}'
    obj, err = validate_llm_json(good_json, VulnerabilityTicket)
    print("Validated Object:", repr(obj))

