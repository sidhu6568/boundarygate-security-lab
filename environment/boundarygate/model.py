"""Public result type shared by the lab and its verifier."""

from dataclasses import dataclass


@dataclass(frozen=True, slots=True)
class Verdict:
    allowed: bool
    code: str
    targets: tuple[str, ...]
