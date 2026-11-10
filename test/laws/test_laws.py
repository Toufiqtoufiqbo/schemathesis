"""Tests for the law engine."""

from __future__ import annotations

import pytest

from schemathesis.laws.core import AccessMatrix, Policy, Principal, Resource, Rule
from schemathesis.laws.races import RaceOutcome, detect_race
from schemathesis.laws.taint import PostgresLogParser, TaintAnalyzer, WriteEvent


def _policy() -> Policy:
    return Policy(
        principals={"bob": Principal(id="bob"), "alice": Principal(id="alice")},
        resources={
            "orders:o1": Resource(type="orders", id="o1", owner="alice"),
            "users:alice": Resource(type="users", id="alice", owner="alice"),
        },
        rules=[
            Rule(kind="owner", action="read", resource_type="orders"),
            Rule(kind="owner", action="write", resource_type="orders"),
            Rule(kind="owner", action="write", resource_type="users"),
        ],
    )


def test_cross_identity_write_is_reported() -> None:
    event = WriteEvent(
        ts=0.0,
        request_id="r1",
        principal="bob",
        method="PUT",
        path="/orders/o1",
        table="orders",
        row_id="o1",
        columns={"status": "paid"},
        source_fields={"status"},
        row_owner="alice",
    )
    violations = TaintAnalyzer(_policy()).analyze([event])
    assert [violation.law for violation in violations] == ["L3"]


def test_authority_creation_is_reported() -> None:
    event = WriteEvent(
        ts=0.0,
        request_id="r2",
        principal="alice",
        method="PATCH",
        path="/users/me",
        table="users",
        row_id="alice",
        columns={"role": "admin"},
        source_fields={"role"},
        row_owner="alice",
    )
    violations = TaintAnalyzer(_policy()).analyze([event])
    assert [violation.law for violation in violations] == ["L4"]


def test_legitimate_self_write_is_not_reported() -> None:
    event = WriteEvent(
        ts=0.0,
        request_id="r3",
        principal="alice",
        method="PATCH",
        path="/users/me",
        table="users",
        row_id="alice",
        columns={"name": "Alice"},
        source_fields={"name"},
        row_owner="alice",
    )
    assert TaintAnalyzer(_policy()).analyze([event]) == []


def test_postgres_logs_are_attributed_to_principals() -> None:
    parser = PostgresLogParser()
    events = parser.parse(
        [
            "2026-11-10 12:00:00.000 UTC [1] mizan:alice LOG:  statement: "
            "UPDATE orders SET status = 'approved' WHERE id = 'o1'",
        ]
    )
    assert events[0].principal == "alice"
    assert events[0].row_id == "o1"


def test_access_matrix_residual() -> None:
    observed = AccessMatrix()
    permitted = AccessMatrix()
    observed.grant("alice", "orders:o1", "read")
    permitted.grant("alice", "orders:o1", "read")
    observed.grant("bob", "orders:o1", "read")
    residual = observed.residual(permitted)
    assert len(residual) == 1
    assert residual.norm()["bob"] == pytest.approx(1.0)


def test_identical_transition_applied_twice_is_a_race() -> None:
    events = [
        WriteEvent(
            ts=0.0,
            request_id="a",
            principal="alice",
            method="POST",
            path="/orders/o1/approve",
            table="orders",
            row_id="o1",
            columns={"status": "approved"},
            row_owner="alice",
        ),
        WriteEvent(
            ts=0.0,
            request_id="b",
            principal="alice",
            method="POST",
            path="/orders/o1/approve",
            table="orders",
            row_id="o1",
            columns={"status": "approved"},
            row_owner="alice",
        ),
    ]
    outcome = RaceOutcome(url="/orders/o1/approve", method="POST", statuses=[200, 200])
    violation = detect_race(outcome=outcome, before=[], after=events, principal="alice")
    assert violation is not None
    assert violation.law == "L5"
