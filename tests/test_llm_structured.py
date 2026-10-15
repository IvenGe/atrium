"""Structured answers (hub/llm/structured.py): the validator and strictify against every schema in the repository,
reading JSON out of an answer, and the repair round."""

from __future__ import annotations

import pytest

from hub.agents.patcher import GENERATE_SCHEMA, PATCH_SCHEMA, REPAIR_SCHEMA
from hub.agents.teams import TEAM_SCHEMA
from hub.agents.tool_supervisor import ENRICH_SCHEMA
from hub.extensions.generate import EXTENSION_SCHEMA, SELF_PATCH_SCHEMA
from hub.llm import structured

SCHEMAS = {"patch": PATCH_SCHEMA, "generate": GENERATE_SCHEMA, "repair": REPAIR_SCHEMA, "enrich": ENRICH_SCHEMA,
           "team": TEAM_SCHEMA, "extension": EXTENSION_SCHEMA, "self_patch": SELF_PATCH_SCHEMA}
GOOD = {
    "patch": {"title": "t", "rationale": "r", "changes": [{"path": "a.py", "content": "x"}], "health_path": ""},
    "generate": {"rationale": "r", "base_url": "https://x", "auth": "bearer", "auth_header": "", "mapping_json": "{}"},
    "repair": {"diagnosis": "d", "rationale": "r", "config_json": "{}"},
    "enrich": {"description": "d", "provides": ["a"], "consumes": []},
    "team": {"rationale": "r", "members": [{"role": "r", "title": "t", "description": "d", "instructions": "i",
                                            "permissions": ["read"], "schedule_minutes": 0, "task": ""}]},
    "extension": {"rationale": "r", "pack_json": "", "needs_code": False, "code_goal": ""},
    "self_patch": {"title": "t", "rationale": "r", "changes": []},
}


@pytest.mark.parametrize("name", list(SCHEMAS))
def test_every_repository_schema_validates_and_strictifies(name):
    schema, good = SCHEMAS[name], GOOD[name]
    assert structured.check(schema, good) == []
    assert structured.check(schema, {**good, "extra": 1}) == ["$.extra is not allowed"]
    missing = dict(good)
    missing.pop(schema["required"][0])
    assert structured.check(schema, missing) == [f"$.{schema['required'][0]} is missing"]
    strict = structured.strictify(schema)
    assert strict is not None and strict["additionalProperties"] is False
    assert set(strict["required"]) == set(strict["properties"])
    assert structured.check(strict, good) == []  # the repository's schemas are strict-shaped already
    assert structured.strip_nulls(schema, good) == good


def test_strictify_makes_optional_properties_nullable_and_refuses_what_strict_mode_cannot_do():
    schema = {"type": "object", "properties": {"a": {"type": "string"}, "b": {"type": "integer"},
                                               "c": {"type": "object", "properties": {"d": {"type": "boolean"}}}},
              "required": ["a"]}
    strict = structured.strictify(schema)
    assert strict["required"] == ["a", "b", "c"] and strict["properties"]["b"]["type"] == ["integer", "null"]
    assert strict["properties"]["c"]["additionalProperties"] is False and strict["properties"]["c"]["required"] == ["d"]
    assert structured.check(strict, {"a": "x", "b": None, "c": {"d": None}}) == []
    assert structured.strip_nulls(schema, {"a": "x", "b": None, "c": {"d": True}}) == {"a": "x", "c": {"d": True}}
    assert structured.strictify({"anyOf": [{"type": "object"}]}) is None  # a root anyOf
    assert structured.strictify({"type": "object", "properties": {"a": {"allOf": [{"type": "string"}]}}}) is None
    assert structured.strictify({"type": "object", "properties": {"a": {"not": {"type": "string"}}}}) is None


def test_the_validator_reports_what_is_wrong():
    schema = TEAM_SCHEMA
    bad = {"rationale": 1, "members": [{"role": "r", "title": "t", "description": "d", "instructions": "i",
                                        "permissions": ["root"], "schedule_minutes": "5", "task": ""}]}
    errors = structured.check(schema, bad)
    assert "$.rationale must be string" in errors and "$.members[0].schedule_minutes must be integer" in errors
    assert any(e.startswith("$.members[0].permissions[0] must be one of") for e in errors)
    assert structured.check({"type": "integer"}, True) == ["$ must be integer"]  # a boolean is no number


def test_reading_json_out_of_an_answer():
    assert structured.extract('{"a": 1}') == {"a": 1}
    assert structured.extract('Here it is:\n```json\n{"a": "b}"}\n```\nDone.') == {"a": "b}"}
    assert structured.extract('Sure! {"a": {"b": "c \\" }"}} and more text') == {"a": {"b": 'c " }'}}
    assert structured.extract('{broken} then {"ok": true}') == {"ok": True}
    with pytest.raises(ValueError):
        structured.extract("no json here")


def test_the_mode_order_per_provider():
    assert structured.mode_order("anthropic", None, None) == ["native", "prompt"]  # a refused native mode degrades
    assert structured.mode_order("anthropic", False, None) == ["prompt"]
    assert structured.mode_order("openai_compatible", None, None) == ["native", "json_object", "prompt"]
    assert structured.mode_order("openai_compatible", False, None) == ["json_object", "prompt"]
    assert structured.mode_order("openai_compatible", None, None, "prompt") == ["prompt"]
    assert structured.mode_order("openai_compatible", None, None, "json_object") == ["json_object", "prompt"]
