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


