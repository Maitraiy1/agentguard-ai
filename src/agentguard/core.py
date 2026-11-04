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


@dataclass(frozen=True)
class Rule:
    """Exact matches only: no globs, prefix matches, or implicit wildcards."""
    tool: str
    resource: str
    principal: str
    decision: Decision

    def __post_init__(self) -> None:
        for name in ("tool", "resource", "principal"):
            label(getattr(self, name), name)
        object.__setattr__(self, "decision", Decision(self.decision))

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
        matches = {rule.decision for rule in self.rules if rule.matches(action)}
        if not matches or Decision.DENY in matches:
            return Decision.DENY
        if Decision.APPROVAL in matches:
            return Decision.APPROVAL
        return Decision.ALLOW

    @property
    def digest(self) -> str:
        rows = sorted({(r.tool, r.resource, r.principal, r.decision.value) for r in self.rules})
        return hashlib.sha256(canonical([list(row) for row in rows]).encode()).hexdigest()

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> Policy:
        if type(data) is not dict or set(data) != {"rules"} or type(data["rules"]) is not list:
            raise ValueError("policy requires exactly a rules array")
        rules = []
        for row in data["rules"]:
            if type(row) is not dict or set(row) != {"tool", "resource", "principal", "decision"}:
                raise ValueError("invalid rule fields")
            rules.append(Rule(**row))
        return cls(tuple(rules))
