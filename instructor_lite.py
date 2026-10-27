from typing import Type, TypeVar
from dotenv import load_dotenv
from groq import Groq
from pydantic import BaseModel

from validator_engine import (
    VulnerabilityTicket,
    build_schema_system_prompt,
    validate_llm_json,
)

load_dotenv()
groq_client = Groq(timeout=20.0)
MODEL_NAME = "openai/gpt-oss-20b"

T = TypeVar("T", bound=BaseModel)


def extract_structured(
    prompt: str,
    response_model: Type[T],
    max_retries: int = 3,
) -> T:
    """Forces the LLM to return a validated instance of `response_model`,
    automatically feeding Pydantic ValidationErrors back to the LLM to self-correct.
    """
    system_prompt = build_schema_system_prompt(response_model)
    messages = [
        {"role": "system", "content": system_prompt},
        {"role": "user", "content": prompt},
    ]

    for attempt in range(1, max_retries + 1):
        response = groq_client.chat.completions.create(
            model=MODEL_NAME,
            messages=messages,
            temperature=0.0,
        )

        raw_reply = response.choices[0].message.content or ""
        validated_obj, error_str = validate_llm_json(raw_reply, response_model)

        if validated_obj is not None:
            print(f"✅ Success on attempt {attempt}")
            return validated_obj
        else:
            print(f"⚠️ Validation failed on attempt {attempt}:\n{error_str}\nRetrying...")
            messages.append({"role": "assistant", "content": raw_reply})
            messages.append(
                {
                    "role": "user",
                    "content": (
                        f"Pydantic ValidationError:\n{error_str}\n"
                        "Please fix the invalid fields and return ONLY a valid JSON instance."
                    ),
                }
            )

    raise RuntimeError(f"Failed to extract valid {response_model.__name__} after {max_retries} attempts.")

if __name__ == "__main__":
    messy_report = (
        "URGENT SEC-OPS LOG: We just detected an unpatched zero-day exploit on the auth server! "
        "It's tracked under identifier 2026-8812 (forgot the prefix) and analysts rated its severity "
        "at 9.4 out of 10. No patch has been deployed yet."
    )

    print("🚀 Extracting structured VulnerabilityTicket from messy log...\n")
    ticket = extract_structured(messy_report, VulnerabilityTicket)

    print("\n✅ Successfully Returned Strictly-Typed Python Object:")
    print(f"  Type:       {type(ticket)}")
    print(f"  CVE ID:     {ticket.cve_id}")
    print(f"  CVSS Score: {ticket.cvss_score}")
    print(f"  Patched:    {ticket.patched}")