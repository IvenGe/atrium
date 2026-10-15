"""Structured (JSON-schema) answers on any provider: the modes per provider and model, a local validator, one
repair round, and `strictify` for providers whose strict mode needs every property required.

Modes, tried in this order where the provider and model support them:
1. native - Anthropic `output_config.format`, OpenAI `text.format` (strict), a local server's
   `response_format` json_schema;
2. json_object - a local server's `response_format` json_object, with the schema in the system prompt;
3. prompt - the schema in the system prompt and "answer with one JSON object only".
Every answer is validated here against the caller's schema (no jsonschema dependency: the repository's schemas are
small and known). A mismatch gets one repair round with the errors; a second failure raises LLMUnavailable.
"""

from __future__ import annotations

import json
import re
from typing import Any

UNSUPPORTED = ("allOf", "not", "if", "then", "else", "dependentRequired", "dependentSchemas")
LIMITS = {"properties": 5000, "depth": 10, "enum": 1000, "chars": 120_000}
JSON_TYPES = {"object": dict, "array": list, "string": str, "boolean": bool, "null": type(None)}


# --------------------------------------------------------------------------------------
# validation
# --------------------------------------------------------------------------------------


def _is(kind: str, value: Any) -> bool:
    if kind == "integer":
        return isinstance(value, int) and not isinstance(value, bool)
    if kind == "number":
        return isinstance(value, (int, float)) and not isinstance(value, bool)
    expected = JSON_TYPES.get(kind)
    return expected is not None and isinstance(value, expected) and not (kind == "string" and isinstance(value, bool))


def check(schema: dict[str, Any], value: Any, where: str = "$") -> list[str]:
    """The ways `value` breaks `schema` (types, enums, required and additional properties, array items, anyOf)."""
    errors: list[str] = []
    if "anyOf" in schema:
        if all(check(option, value, where) for option in schema["anyOf"]):
            errors.append(f"{where} matches none of the allowed shapes")
        return errors
    kinds = schema.get("type")
    if kinds is not None:
        options = kinds if isinstance(kinds, list) else [kinds]
        if not any(_is(k, value) for k in options):
            return [f"{where} must be {' or '.join(options)}"]
    if "enum" in schema and value not in schema["enum"]:
        errors.append(f"{where} must be one of: {', '.join(map(json.dumps, schema['enum']))[:300]}")
    if isinstance(value, dict):
        properties = schema.get("properties") or {}
        for name in schema.get("required") or []:
            if name not in value:
                errors.append(f"{where}.{name} is missing")
        for name, item in value.items():
            if name in properties:
                errors += check(properties[name], item, f"{where}.{name}")
            elif schema.get("additionalProperties") is False:
                errors.append(f"{where}.{name} is not allowed")
    if isinstance(value, list) and isinstance(schema.get("items"), dict):
        for n, item in enumerate(value):
            errors += check(schema["items"], item, f"{where}[{n}]")
    return errors


# --------------------------------------------------------------------------------------
# reading an answer
# --------------------------------------------------------------------------------------


def extract(text: str) -> Any:
    """The JSON object in a model's answer: the whole text, else the first balanced {...} (also inside ``` fences)."""
    text = (text or "").strip()
    try:
        return json.loads(text)
    except ValueError:
        pass
    fenced = re.search(r"```(?:json)?\s*(\{.*?\})\s*```", text, re.DOTALL)
    if fenced:
        try:
            return json.loads(fenced.group(1))
        except ValueError:
            pass
    start = text.find("{")
    while start != -1:
        depth, quoted, escaped = 0, False, False
        for end in range(start, len(text)):
            ch = text[end]
            if quoted:
                if escaped:
                    escaped = False
                elif ch == "\\":
                    escaped = True
                elif ch == '"':
                    quoted = False
                continue
            if ch == '"':
                quoted = True
            elif ch == "{":
                depth += 1
            elif ch == "}":
                depth -= 1
                if depth == 0:
                    try:
                        return json.loads(text[start:end + 1])
                    except ValueError:
                        break
        start = text.find("{", start + 1)
    raise ValueError("the answer contains no JSON object")


def schema_prompt(schema: dict[str, Any]) -> str:
    return ("\n\nAnswer with one JSON object only - no prose, no code fence - that matches this JSON schema:\n"
            + json.dumps(schema))


def repair_prompt(errors: list[str]) -> str:
    return ("Your JSON did not match the schema: " + "; ".join(errors[:20])
            + ". Answer again with the complete, corrected JSON object only.")


# --------------------------------------------------------------------------------------
# strict schemas (OpenAI strict mode)
# --------------------------------------------------------------------------------------


def strictify(schema: dict[str, Any]) -> dict[str, Any] | None:
    """`schema` for a provider's strict mode: additionalProperties false on every object, and every property required
    (an optional one as a union with null; `strip_nulls` removes those nulls again). None when the schema uses what strict
    mode refuses (allOf, not, if/then/else, dependent*, a root anyOf) or exceeds its limits."""
    if "anyOf" in schema or len(json.dumps(schema)) > LIMITS["chars"]:
        return None
    counts = {"properties": 0, "enum": 0}

    def walk(node: Any, depth: int) -> Any:
        if not isinstance(node, dict):
            return node
        if depth > LIMITS["depth"] or any(k in node for k in UNSUPPORTED):
            raise ValueError("unsupported")
        out = dict(node)
        counts["enum"] += len(node.get("enum") or [])
        if "anyOf" in node:
            out["anyOf"] = [walk(option, depth + 1) for option in node["anyOf"]]
        if isinstance(node.get("items"), dict):
            out["items"] = walk(node["items"], depth + 1)
        if node.get("type") == "object" or "properties" in node:
            properties = node.get("properties") or {}
            counts["properties"] += len(properties)
            required = set(node.get("required") or [])
            converted = {}
            for name, prop in properties.items():
                prop = walk(prop, depth + 1)
                if name not in required:
                    kind = prop.get("type")
                    if isinstance(kind, str):
                        prop = {**prop, "type": [kind, "null"]}
                    elif isinstance(kind, list) and "null" not in kind:
                        prop = {**prop, "type": [*kind, "null"]}
                    elif kind is None:
                        prop = {"anyOf": [prop, {"type": "null"}]}
                converted[name] = prop
            out.update(properties=converted, required=list(properties), additionalProperties=False)
        return out

    try:
        strict = walk(schema, 1)
    except ValueError:
        return None
    if counts["properties"] > LIMITS["properties"] or counts["enum"] > LIMITS["enum"]:
        return None
    return strict


def strip_nulls(schema: dict[str, Any], value: Any) -> Any:
    """Remove the null values strictify allowed for properties the original schema does not require."""
    if isinstance(value, dict):
        properties = schema.get("properties") or {}
        required = set(schema.get("required") or [])
        return {k: strip_nulls(properties.get(k) or {}, v) for k, v in value.items()
                if not (v is None and k not in required)}
    if isinstance(value, list) and isinstance(schema.get("items"), dict):
        return [strip_nulls(schema["items"], v) for v in value]
    return value


def mode_order(kind: str, caps_json_schema: bool | None, caps_json_object: bool | None, setting: str = "auto") -> list[str]:
    """The modes to try, best first, for a provider kind and what is known about the model."""
    if kind == "anthropic":
        return ["native"] if caps_json_schema is not False else ["prompt"]
    if kind == "openai":
        return ["native", "prompt"] if caps_json_schema is not False else ["prompt"]
    if setting == "json_schema":
        return ["native"]
    if setting == "json_object":
        return ["json_object", "prompt"]
    if setting == "prompt":
        return ["prompt"]
    order = ["native"] if caps_json_schema is not False else []
    order += ["json_object"] if caps_json_object is not False else []
    return [*order, "prompt"]


def names_mode(message: str, mode: str) -> bool:
    """Whether a provider's refusal (HTTP 400) is about the structured-output mode it was sent."""
    low = message.lower()
    if mode == "native":
        return any(w in low for w in ("response_format", "json_schema", "text.format", "output_config", "format"))
    if mode == "json_object":
        return "response_format" in low or "json_object" in low
    return False
