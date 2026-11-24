"""Reference implementation for the BoundaryGate lab."""

from __future__ import annotations

import base64
import copy
import hashlib
import hmac
import json
import re

from .model import Verdict


IDENTIFIER = re.compile(r"[A-Za-z0-9_-]{1,32}\Z")
TENANT = re.compile(r"[a-z][a-z0-9-]{0,31}\Z")
HEX64 = re.compile(r"[0-9a-f]{64}\Z")
B64 = re.compile(r"[A-Za-z0-9_-]+\Z")
PATH_CHARS = re.compile(r"[A-Za-z0-9._~/-]+\Z")
ACTIONS = frozenset(("object.read", "object.write", "secret.read", "job.run"))
ACTION_PATTERNS = ACTIONS | {"*", "object.*", "secret.*", "job.*"}
CAP_FIELDS = {"v", "id", "kid", "sub", "parent", "tenant", "aud", "nbf", "exp", "depth", "limit", "allow", "deny"}
MAX_INT = (1 << 53) - 1
CAP_DOMAIN = b"BG-CAP-v1\x00"
REV_DOMAIN = b"BG-REV-v1\x00"


class _Invalid(ValueError):
    pass


def _need(condition: bool) -> None:
    if not condition:
        raise _Invalid("invalid lab message")


def _integer(value, minimum: int, maximum: int) -> bool:
    return type(value) is int and minimum <= value <= maximum


def _identifier(value) -> bool:
    return type(value) is str and IDENTIFIER.fullmatch(value) is not None


def _object(value, required: set[str], optional: set[str] = frozenset()) -> None:
    _need(type(value) is dict and required <= value.keys() and value.keys() <= required | optional)


def _unique_object(pairs):
    result = {}
    for name, value in pairs:
        _need(name not in result)
        result[name] = value
    return result


def _bad_constant(value):
    raise _Invalid("non-finite JSON number")


def _envelope(value: str) -> tuple[dict, bytes, str]:
    _need(type(value) is str and 1 <= len(value) <= 12288)
    encoded, separator, signature = value.partition(".")
    _need(separator == "." and B64.fullmatch(encoded) is not None)
    _need(HEX64.fullmatch(signature) is not None)
    raw = base64.b64decode(encoded + "=" * (-len(encoded) % 4), altchars=b"-_", validate=True)
    _need(1 <= len(raw) <= 8192)
    _need(base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii") == encoded)
    body = json.loads(raw.decode("utf-8"), object_pairs_hook=_unique_object, parse_constant=_bad_constant)
    _need(type(body) is dict)
    return body, raw, signature


def _canonical_target(value: str, tenant: str) -> str:
    _need(type(value) is str and 1 <= len(value) <= 2048 and value.startswith("/"))
    _need(re.search(r"%(?:2f|5c)", value, re.IGNORECASE) is None)
    decoded = []
    cursor = 0
    while cursor < len(value):
        char = value[cursor]
        if char == "%":
            _need(cursor + 2 < len(value) and re.fullmatch(r"[0-9A-Fa-f]{2}", value[cursor + 1:cursor + 3]) is not None)
            decoded.append(chr(int(value[cursor + 1:cursor + 3], 16)))
            cursor += 3
        else:
            decoded.append(char)
            cursor += 1
    path = "".join(decoded)
    _need(len(path) <= 512 and PATH_CHARS.fullmatch(path) is not None)
    parts = [part for part in path.split("/") if part]
    _need(bool(parts) and parts[0] == tenant)
    stack = [tenant]
    for part in parts[1:]:
        if part == ".":
            continue
        if part == "..":
            _need(len(stack) > 1)
            stack.pop()
        else:
            stack.append(part)
    return "/" + "/".join(stack)


def _rules(value, tenant: str, allow: bool) -> list[dict]:
    _need(type(value) is list and (1 if allow else 0) <= len(value) <= 8)
    for rule in value:
        _object(rule, {"actions", "resource"})
        patterns = rule["actions"]
        _need(type(patterns) is list and 1 <= len(patterns) <= 8)
        _need(all(type(pattern) is str and pattern in ACTION_PATTERNS for pattern in patterns))
        _need(len(set(patterns)) == len(patterns))
        resource = rule["resource"]
        _need(type(resource) is str and "%" not in resource)
        base = resource[:-3] if resource.endswith("/**") else resource
        _need(_canonical_target(base, tenant) == base)
    return value


def _matches(rule: dict, action: str, target: str) -> bool:
    action_match = any(
        pattern == "*" or pattern == action or
        (pattern.endswith(".*") and action.startswith(pattern[:-1]))
        for pattern in rule["actions"]
    )
    resource = rule["resource"]
    if resource.endswith("/**"):
        base = resource[:-3]
        path_match = target == base or target.startswith(base + "/")
    else:
        path_match = target == resource
    return action_match and path_match


class Gate:
    """Keep authorization decisions and their accounting in one transaction."""

    def __init__(self, config: dict) -> None:
        snapshot = copy.deepcopy(config)
        self._keys = {name: bytes.fromhex(secret) for name, secret in snapshot["keys"].items()}
        self._roots = {tenant: frozenset(names) for tenant, names in snapshot["roots"].items()}
        self._controllers = {tenant: bytes.fromhex(secret) for tenant, secret in snapshot["control"].items()}
        self._revoked: dict[str, set[str]] = {}
        self._serial: dict[str, int] = {}
        self._pins: dict[tuple[str, str], str] = {}
        self._spent: dict[tuple[str, str], int] = {}
        self._ledger: dict[str, dict[tuple[str, str], tuple]] = {}

    def apply(self, event: dict) -> Verdict:
        try:
            _need(type(event) is dict)
            if event.get("kind") == "call":
                return self._call(event)
            if event.get("kind") == "revoke":
                return self._revoke(event)
        except (ValueError, TypeError, KeyError, UnicodeError, OverflowError, RecursionError):
            pass
        return Verdict(False, "deny", ())

    def _capability(self, token: str) -> tuple[dict, str]:
        cap, raw, signature = _envelope(token)
        _object(cap, CAP_FIELDS)
        _need(type(cap["v"]) is int and cap["v"] == 1)
        _need(all(_identifier(cap[field]) for field in ("id", "kid", "sub")))
        _need(cap["kid"] in self._keys and cap["sub"] in self._keys)
        _need(type(cap["tenant"]) is str and TENANT.fullmatch(cap["tenant"]) is not None)
        _need(cap["parent"] is None or (type(cap["parent"]) is str and HEX64.fullmatch(cap["parent"]) is not None))
        _need(cap["aud"] == "boundarygate/tools")
        _need(_integer(cap["nbf"], 0, MAX_INT) and _integer(cap["exp"], 0, MAX_INT) and cap["nbf"] < cap["exp"])
        _need(_integer(cap["depth"], 0, 5) and _integer(cap["limit"], 0, 1000000))
        _rules(cap["allow"], cap["tenant"], True)
        _rules(cap["deny"], cap["tenant"], False)
        expected = hmac.new(self._keys[cap["kid"]], CAP_DOMAIN + raw, hashlib.sha256).hexdigest()
        _need(hmac.compare_digest(expected, signature))
        return cap, hashlib.sha256(raw).hexdigest()

    def _call(self, event: dict) -> Verdict:
        _object(event, {"kind", "now", "tenant", "actor", "request_id", "chain", "ops"}, {"context"})
        tenant, actor, request_id, now = (event[name] for name in ("tenant", "actor", "request_id", "now"))
        _need(type(tenant) is str and tenant in self._roots)
        _need(_identifier(actor) and actor in self._keys and _identifier(request_id))
        _need(_integer(now, 0, MAX_INT))
        _need(type(event["chain"]) is list and 1 <= len(event["chain"]) <= 6)
        _need(type(event["ops"]) is list and 1 <= len(event["ops"]) <= 16)
        chain = [self._capability(token) for token in event["chain"]]
        normalized = []
        for operation in event["ops"]:
            _object(operation, {"action", "target", "cost"})
            action, cost = operation["action"], operation["cost"]
            _need(type(action) is str and action in ACTIONS and _integer(cost, 1, 1024))
            normalized.append((action, _canonical_target(operation["target"], tenant), cost))

        ids = [cap["id"] for cap, _ in chain]
        _need(len(ids) == len(set(ids)))
        previous = None
        previous_digest = None
        for cap, digest in chain:
            _need(cap["tenant"] == tenant and cap["nbf"] <= now < cap["exp"])
            _need(cap["id"] not in self._revoked.get(tenant, set()))
            _need(self._pins.get((tenant, cap["id"]), digest) == digest)
            if previous is None:
                _need(cap["parent"] is None and cap["kid"] in self._roots[tenant])
            else:
                _need(cap["parent"] == previous_digest and cap["kid"] == previous["sub"])
                _need(cap["nbf"] >= previous["nbf"] and cap["exp"] <= previous["exp"])
                _need(cap["depth"] < previous["depth"] and cap["limit"] <= previous["limit"])
            previous, previous_digest = cap, digest
            for action, target, _ in normalized:
                _need(any(_matches(rule, action, target) for rule in cap["allow"]))
                _need(not any(_matches(rule, action, target) for rule in cap["deny"]))
        _need(chain[-1][0]["sub"] == actor)

        fingerprint = (tuple(digest for _, digest in chain), tuple(normalized))
        ledger = self._ledger.get(tenant, {})
        request_key = (actor, request_id)
        if request_key in ledger:
            _need(ledger[request_key] == fingerprint)
            return Verdict(True, "cached", ())
        _need(len(ledger) < 64)
        total_cost = sum(cost for _, _, cost in normalized)
        for cap, _ in chain:
            _need(self._spent.get((tenant, cap["id"]), 0) + total_cost <= cap["limit"])

        for cap, digest in chain:
            identity = (tenant, cap["id"])
            self._pins[identity] = digest
            self._spent[identity] = self._spent.get(identity, 0) + total_cost
        self._ledger.setdefault(tenant, {})[request_key] = fingerprint
        return Verdict(True, "allow", tuple(target for _, target, _ in normalized))

    def _revoke(self, event: dict) -> Verdict:
        _object(event, {"kind", "proof"}, {"context"})
        body, raw, signature = _envelope(event["proof"])
        _object(body, {"v", "tenant", "serial", "ids"})
        _need(type(body["v"]) is int and body["v"] == 1)
        tenant, serial, ids = (body[name] for name in ("tenant", "serial", "ids"))
        _need(type(tenant) is str and tenant in self._controllers)
        _need(_integer(serial, 1, MAX_INT))
        _need(type(ids) is list and len(ids) <= 32 and all(_identifier(value) for value in ids))
        _need(len(ids) == len(set(ids)))
        expected = hmac.new(self._controllers[tenant], REV_DOMAIN + raw, hashlib.sha256).hexdigest()
        _need(hmac.compare_digest(expected, signature))
        _need(serial > self._serial.get(tenant, 0))
        self._serial[tenant] = serial
        self._revoked.setdefault(tenant, set()).update(ids)
        return Verdict(True, "control", ())
