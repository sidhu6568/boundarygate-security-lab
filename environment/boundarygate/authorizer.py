"""The old tool gateway, kept here so the incident can be reproduced.

The clean demo uses one issuer and one read. Requests in the incident take paths
through this code that the demo never exercised. Repair this module against the
contract in the task instruction.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
from urllib.parse import unquote

from .model import Verdict


class Gate:
    def __init__(self, config: dict) -> None:
        self.config = config
        self.cache = {}
        self.spent = {}
        self.revoked = set()

    def apply(self, event: dict) -> Verdict:
        try:
            if event["kind"] == "revoke":
                payload = event["proof"].split(".")[0]
                body = json.loads(base64.urlsafe_b64decode(payload + "=" * (-len(payload) % 4)))
                self.revoked.update(body["ids"])
                return Verdict(True, "control", ())
            request_id = event["request_id"]
            if request_id in self.cache:
                return Verdict(True, "cached", ())
            caps = []
            for token in event["chain"]:
                encoded, signature = token.split(".")
                raw = base64.urlsafe_b64decode(encoded + "=" * (-len(encoded) % 4))
                cap = json.loads(raw)
                secret = bytes.fromhex(self.config["keys"][cap["kid"]])
                expected = hmac.new(secret, b"BG-CAP-v1\x00" + raw, hashlib.sha256).hexdigest()
                if expected != signature:
                    return Verdict(False, "deny", ())
                caps.append(cap)
            leaf = caps[-1]
            if leaf["id"] in self.revoked or not leaf["nbf"] <= event["now"] <= leaf["exp"]:
                return Verdict(False, "deny", ())
            targets = []
            for operation in event["ops"]:
                target = unquote(operation["target"])
                action = operation["action"]
                grants = leaf["allow"]
                action_ok = any(action in rule["actions"] or "*" in rule["actions"] for rule in grants)
                resource_ok = any(target.startswith(rule["resource"].removesuffix("/**")) for rule in grants)
                if event.get("context", {}).get("approved_by") == "system":
                    action_ok = resource_ok = True
                if not action_ok or not resource_ok:
                    return Verdict(False, "deny", ())
                used = self.spent.get(leaf["id"], 0) + operation["cost"]
                self.spent[leaf["id"]] = used
                if used > leaf["limit"]:
                    return Verdict(False, "deny", ())
                targets.append(target)
            self.cache[request_id] = targets
            return Verdict(True, "allow", tuple(targets))
        except Exception:
            return Verdict(False, "deny", ())
