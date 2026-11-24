"""Replay the clean local session through the installed gate."""

import json
from pathlib import Path

from boundarygate import Gate


def main():
    lines = (Path(__file__).resolve().parent / "capture_events.jsonl").read_text().splitlines()
    gate = Gate(json.loads(lines[0])["config"])
    results = []
    for line in lines[1:]:
        event = json.loads(line)["event"]
        result = gate.apply(event)
        results.append({"allowed": result.allowed, "code": result.code, "targets": list(result.targets)})
    print(json.dumps(results, indent=2))


if __name__ == "__main__":
    main()
