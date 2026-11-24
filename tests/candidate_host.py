"""Run the submitted module against a pristine public contract."""

from __future__ import annotations

import contextlib
import copy
import importlib.util
import io
import json
import os
from pathlib import Path
import sys


def main() -> None:
    request = json.load(sys.stdin)
    sys.path.insert(0, os.environ.get("BOUNDARY_CONTRACT", "/opt/boundary-contract"))
    from boundarygate.model import Verdict

    spec = importlib.util.spec_from_file_location("boundarygate.authorizer", Path(request["candidate"]))
    if spec is None or spec.loader is None:
        raise RuntimeError("could not load candidate")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    results = []
    with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
        spec.loader.exec_module(module)
        config = copy.deepcopy(request["config"])
        gate = module.Gate(config)
        if "replace_config" in request:
            config.clear()
            config.update(request["replace_config"])
        for index, event in enumerate(request["events"]):
            if index in request.get("new_gate_at", []):
                gate = module.Gate(copy.deepcopy(request["config"]))
            before = copy.deepcopy(event)
            result = gate.apply(event)
            if event != before:
                raise TypeError("apply mutated the caller's event")
            if type(result) is not Verdict:
                raise TypeError("apply must return the canonical Verdict")
            if type(result.allowed) is not bool or type(result.code) is not str:
                raise TypeError("invalid verdict fields")
            if type(result.targets) is not tuple or any(type(target) is not str for target in result.targets):
                raise TypeError("targets must be a tuple of strings")
            results.append({"allowed": result.allowed, "code": result.code, "targets": list(result.targets)})
    json.dump({"ok": True, "results": results}, sys.stdout, separators=(",", ":"))


if __name__ == "__main__":
    try:
        main()
    except BaseException as exc:
        json.dump({"ok": False, "error": type(exc).__name__, "message": str(exc)[:400]}, sys.stdout)
