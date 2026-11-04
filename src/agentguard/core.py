"""Strict action snapshots and deterministic, default-deny policy evaluation."""
from __future__ import annotations

import hashlib
import json
import math
from dataclasses import dataclass
from enum import Enum
from typing import Any


class Decision(str, Enum):
    ALLOW = "allow"
    APPROVAL = "approval"
    DENY = "deny"


def label(value: str, name: str) -> str:
    if not isinstance(value, str) or not value or len(value) > 512:
        raise ValueError(f"{name} must be a nonempty string of at most 512 characters")
    if any(ord(c) < 32 or ord(c) == 127 for c in value):
        raise ValueError(f"{name} contains control characters")
    return value


def canonical(value: Any) -> str:
    def validate(item: Any, depth: int = 0) -> None:
        if depth > 32:
            raise ValueError("JSON nesting exceeds 32")
        if item is None or type(item) in (str, bool, int):
            return
        if type(item) is float and math.isfinite(item):
            return
        if type(item) is list:
            for child in item:
                validate(child, depth + 1)
            return
        if type(item) is dict and all(type(k) is str for k in item):
            for child in item.values():
                validate(child, depth + 1)
            return
        raise ValueError("Only finite JSON values with string object keys are accepted")
    validate(value)
    result = json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True,
                        allow_nan=False)
    if len(result.encode()) > 65536:
        raise ValueError("JSON exceeds 64 KiB")
    return result


def strict_json(raw: str) -> Any:
    def pairs(items: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in items:
            if key in result:
                raise ValueError(f"Duplicate JSON key: {key}")
            result[key] = value
        return result
    if len(raw.encode()) > 65536:
        raise ValueError("JSON exceeds 64 KiB")
    value = json.loads(raw, object_pairs_hook=pairs)
    canonical(value)
    return value


@dataclass(frozen=True, init=False)
class Action:
    """Immutable snapshot; parameter reads return fresh objects."""
    tool: str
    resource: str
    principal: str
    _parameters: str

    def __init__(self, tool: str, resource: str, principal: str,
                 parameters: dict[str, Any] | None = None):
        object.__setattr__(self, "tool", label(tool, "tool"))
        object.__setattr__(self, "resource", label(resource, "resource"))
        object.__setattr__(self, "principal", label(principal, "principal"))
        if parameters is None:
            parameters = {}
        if type(parameters) is not dict:
            raise ValueError("parameters must be a JSON object")
        object.__setattr__(self, "_parameters", canonical(parameters))

    @property
    def parameters(self) -> dict[str, Any]:
        return json.loads(self._parameters)

    def as_dict(self) -> dict[str, Any]:
        return {"tool": self.tool, "resource": self.resource,
                "principal": self.principal, "parameters": self.parameters}

    @property
    def digest(self) -> str:
        return hashlib.sha256(canonical(self.as_dict()).encode()).hexdigest()

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> Action:
        if type(data) is not dict or set(data) != {"tool", "resource", "principal", "parameters"}:
            raise ValueError("action requires exactly tool, resource, principal, parameters")
        return cls(**data)


@dataclass(frozen=True, init=False)
class ParameterSchema:
    """Small strict schema: exact required keys, types, enums and size/range limits."""
    _json: str

    def __init__(self, fields: dict[str, Any]):
        if type(fields) is not dict or len(fields) > 64:
            raise ValueError("parameters must be an object with at most 64 fields")
        for name, spec in fields.items():
            label(name, "parameter name")
            if type(spec) is not dict or not set(spec) <= {"type", "enum", "max_length", "minimum", "maximum"}:
                raise ValueError("Unknown parameter schema fields")
            kind = spec.get("type")
            if kind not in ("string", "integer", "boolean"):
                raise ValueError("Parameter type must be string, integer or boolean")
            expected = {"string": str, "integer": int, "boolean": bool}[kind]
            if "enum" in spec:
                choices = spec["enum"]
                if type(choices) is not list or not 1 <= len(choices) <= 100:
                    raise ValueError("enum must contain 1–100 values")
                if any(type(choice) is not expected for choice in choices):
                    raise ValueError("enum values must match the parameter type")
            if "max_length" in spec:
                value = spec["max_length"]
                if kind != "string" or type(value) is not int or not 0 <= value <= 65536:
                    raise ValueError("max_length requires a nonnegative string length up to 65536")
            for bound in ("minimum", "maximum"):
                if bound in spec and (kind != "integer" or type(spec[bound]) is not int):
                    raise ValueError("Range bounds require integer parameters")
            if "minimum" in spec and "maximum" in spec and spec["minimum"] > spec["maximum"]:
                raise ValueError("minimum exceeds maximum")
        object.__setattr__(self, "_json", canonical(fields))

    def as_dict(self) -> dict[str, Any]:
        return json.loads(self._json)

    def accepts(self, parameters: dict[str, Any]) -> bool:
        fields = self.as_dict()
        if type(parameters) is not dict or set(parameters) != set(fields):
            return False
        for name, spec in fields.items():
            value = parameters[name]
            expected = {"string": str, "integer": int, "boolean": bool}[spec["type"]]
            if type(value) is not expected:
                return False
            if "enum" in spec and value not in spec["enum"]:
                return False
            if "max_length" in spec and len(value) > spec["max_length"]:
                return False
            if "minimum" in spec and value < spec["minimum"]:
                return False
            if "maximum" in spec and value > spec["maximum"]:
                return False
        return True


@dataclass(frozen=True)
class Rule:
    """Exact identity matching with optional strict parameter constraints."""
    tool: str
    resource: str
    principal: str
    decision: Decision
    parameters: ParameterSchema | None = None

    def __post_init__(self) -> None:
        for name in ("tool", "resource", "principal"):
            label(getattr(self, name), name)
        object.__setattr__(self, "decision", Decision(self.decision))
        if self.parameters is not None and not isinstance(self.parameters, ParameterSchema):
            raise ValueError("parameters must be a ParameterSchema")
        if self.decision == Decision.DENY and self.parameters is not None:
            raise ValueError("Deny rules are unconditional; omit parameter constraints")

    def matches(self, action: Action) -> bool:
        return (self.tool, self.resource, self.principal) == (
            action.tool, action.resource, action.principal)


@dataclass(frozen=True)
class Policy:
    rules: tuple[Rule, ...] = ()

    def __post_init__(self) -> None:
        rules = tuple(self.rules)
        if not all(isinstance(rule, Rule) for rule in rules):
            raise ValueError("rules must contain Rule objects")
        object.__setattr__(self, "rules", rules)

    def evaluate(self, action: Action) -> Decision:
        rules = [rule for rule in self.rules if rule.matches(action)]
        # Constraints intersect across rules. An unconstrained rule cannot bypass one.
        if any(rule.parameters is not None and not rule.parameters.accepts(action.parameters) for rule in rules):
            return Decision.DENY
        matches = {rule.decision for rule in rules}
        if not matches or Decision.DENY in matches:
            return Decision.DENY
        if Decision.APPROVAL in matches:
            return Decision.APPROVAL
        return Decision.ALLOW

    @property
    def digest(self) -> str:
        rows = sorted({canonical({"tool": r.tool, "resource": r.resource,
            "principal": r.principal, "decision": r.decision.value,
            "parameters": r.parameters.as_dict() if r.parameters is not None else None}) for r in self.rules})
        return hashlib.sha256(canonical(rows).encode()).hexdigest()

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> Policy:
        if type(data) is not dict or set(data) != {"rules"} or type(data["rules"]) is not list:
            raise ValueError("policy requires exactly a rules array")
        rules = []
        required = {"tool", "resource", "principal", "decision"}
        for row in data["rules"]:
            if type(row) is not dict or not required <= set(row) or not set(row) <= required | {"parameters"}:
                raise ValueError("invalid rule fields")
            values = dict(row)
            if "parameters" in values:
                values["parameters"] = ParameterSchema(values["parameters"])
            rules.append(Rule(**values))
        return cls(tuple(rules))
