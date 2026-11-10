"""Concurrency harness: make TOCTOU bugs reproducible instead of accidental."""

from __future__ import annotations

import threading
from collections.abc import Callable
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from typing import Any

from schemathesis.laws.core import SINGLE_USE_HINTS, Violation


@dataclass
class RaceOutcome:
    """What happened when two identical actions ran concurrently."""

    url: str
    method: str
    statuses: list[int | None] = field(default_factory=list)
    bodies: list[Any] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)

    @property
    def successes(self) -> int:
        return sum(1 for status in self.statuses if status is not None and 200 <= status < 300)

    @property
    def failed(self) -> bool:
        return self.successes < 2

    def to_dict(self) -> dict[str, Any]:
        return {
            "url": self.url,
            "method": self.method,
            "statuses": self.statuses,
            "bodies": self.bodies,
            "errors": self.errors,
            "successes": self.successes,
        }


def run_concurrently(calls: list[Callable[[], Any]], timeout: float = 15.0) -> list[Any]:
    """Run every callable at the same time.

    A barrier guarantees the requests are released together, which is what turns
    a rare race into a reliable one.
    """
    if not calls:
        return []
    barrier = threading.Barrier(len(calls))

    def wrapped(fn: Callable[[], Any]) -> Callable[[], Any]:
        def inner() -> Any:
            barrier.wait(timeout=timeout)
            return fn()

        return inner

    with ThreadPoolExecutor(max_workers=len(calls)) as executor:
        futures = [executor.submit(wrapped(fn)) for fn in calls]
        results: list[Any] = []
        for future in futures:
            try:
                results.append(future.result(timeout=timeout))
            except Exception:  # pragma: no cover - defensive
                results.append(None)
        return results


def looks_single_use(path: str) -> bool:
    """Whether the operation's semantics are naturally one-shot."""
    lowered = path.lower()
    return any(hint in lowered for hint in SINGLE_USE_HINTS)


def detect_race(
    *,
    outcome: RaceOutcome,
    before: list[Any],
    after: list[Any],
    row_id: str | None = None,
    principal: str | None = None,
) -> Violation | None:
    """Turn a race outcome into a violation, or `None` when it was benign."""
    if outcome.failed:
        return None

    new_events = after[len(before) :]
    if not new_events:
        return None

    by_row: dict[str, list[Any]] = {}
    for event in new_events:
        key = getattr(event, "resource_key", None) or getattr(event, "row_id", "?")
        by_row.setdefault(key, []).append(event)

    for key, events in by_row.items():
        if row_id is not None and key != f"{getattr(events[0], 'table', '')}:{row_id}":
            continue
        if len(events) < 2:
            continue
        signatures = []
        for event in events:
            columns = getattr(event, "columns", {}) or {}
            signatures.append(tuple(sorted((k, str(v)) for k, v in columns.items())))
        if len(set(signatures)) == 1 and len(signatures) > 1:
            return Violation(
                law="L5",
                title="The same state transition was applied twice",
                detail=(
                    f"Two concurrent `{outcome.method} {outcome.url}` requests were both accepted and both "
                    f"applied the identical change to `{key}`. A check-then-act sequence without an atomic "
                    f"guard lets both requests through."
                ),
                severity="high",
                principal=principal,
                resource=key,
                action="write",
                evidence={
                    "race": outcome.to_dict(),
                    "applied_changes": [event.to_dict() for event in events],
                    "single_use_hint": looks_single_use(outcome.url),
                },
            )
        if looks_single_use(outcome.url):
            return Violation(
                law="L6",
                title="A single-use operation succeeded twice",
                detail=(
                    f"Two concurrent `{outcome.method} {outcome.url}` requests were both accepted, and the "
                    f"operation looks single-use. The resource was consumed more than once."
                ),
                severity="high",
                principal=principal,
                resource=key,
                action="write",
                evidence={"race": outcome.to_dict(), "applied_changes": [event.to_dict() for event in events]},
            )
    return None
