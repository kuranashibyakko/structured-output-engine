# 🛡️ structured-output-engine (v1.0)

A lightweight, zero-framework **Schema-Enforced Reflection & Extraction Engine** written from scratch in Python and Pydantic, modeled after **Instructor** and **PydanticAI**.

## ✨ Core Capabilities
- **Automatic JSON Schema Compilation (`validator_engine.py`):** Dynamically compiles Pydantic `BaseModel` trees into strict LLM system prompts via `.model_json_schema()`.
- **Self-Healing Validation Loop (`instructor_lite.py`):** Catches Pydantic `ValidationError` tracebacks at the field level and feeds exact error diagnostics back to the LLM to self-correct.
- **Nested Telemetry & Deterministic Routing (`incident_router.py`):** Extracts hierarchical security incident objects with custom `@field_validator` rules (IPv4 & port verification) and routes validated payloads deterministically.

## 🚀 Quickstart
```bash
pytest -v
python instructor_lite.py
python incident_router.py
