"""Write taint: attribute every database write to the principal that caused it."""

from __future__ import annotations

# The engine lives in `schemathesis.laws`; the imports below are rewritten from
# the standalone `mizan` package when this patch is generated.
from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Iterable

from schemathesis.laws.core import Policy, Principal, Resource, Step, Violation, actions_for

# --------------------------------------------------------------------------- #
# Events
# --------------------------------------------------------------------------- #


@dataclass
class WriteEvent:
    """A single row mutation, attributed to a principal."""

    ts: float
    request_id: str
    principal: str
    method: str
    path: str
    table: str
    row_id: str
    columns: dict[str, Any] = field(default_factory=dict)
    #: fields the client actually sent - anything else was written by the server
    source_fields: set[str] = field(default_factory=set)
    row_owner: str | None = None
    status: int = 200
    method_args: dict[str, Any] = field(default_factory=dict)

    @property
    def action(self) -> str:
        return actions_for(self.method)

    @property
    def resource_key(self) -> str:
        return f"{self.table}:{self.row_id}"

    def to_dict(self) -> dict[str, Any]:
        return {
            "ts": self.ts,
            "request_id": self.request_id,
            "principal": self.principal,
            "method": self.method,
            "path": self.path,
            "table": self.table,
            "row_id": self.row_id,
            "columns": self.columns,
            "source_fields": sorted(self.source_fields),
            "row_owner": self.row_owner,
            "status": self.status,
            "method_args": self.method_args,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> WriteEvent:
        return cls(
            ts=float(data.get("ts", 0.0)),
            request_id=str(data.get("request_id", "")),
            principal=str(data.get("principal", "")),
            method=str(data.get("method", "")),
            path=str(data.get("path", "")),
            table=str(data.get("table", "")),
            row_id=str(data.get("row_id", "")),
            columns=dict(data.get("columns", {})),
            source_fields=set(data.get("source_fields", [])),
            row_owner=data.get("row_owner"),
            status=int(data.get("status", 200)),
            method_args=dict(data.get("method_args", {})),
        )


class Ledger:
    """JSONL ledger of write events."""

    def __init__(self, path: str | Path | None = None) -> None:
        self.path = Path(path) if path is not None else None
        self.events: list[WriteEvent] = []

    def append(self, event: WriteEvent) -> None:
        self.events.append(event)
        if self.path is not None:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            with self.path.open("a", encoding="utf-8") as handle:
                handle.write(json.dumps(event.to_dict(), ensure_ascii=False) + "\n")

    @classmethod
    def load(cls, path: str | Path) -> Ledger:
        ledger = cls(Path(path))
        with ledger.path.open("r", encoding="utf-8") as handle:
            for line in handle:
                line = line.strip()
                if line:
                    ledger.events.append(WriteEvent.from_dict(json.loads(line)))
        return ledger

    def by_principal(self) -> dict[str, list[WriteEvent]]:
        grouped: dict[str, list[WriteEvent]] = {}
        for event in self.events:
            grouped.setdefault(event.principal, []).append(event)
        return grouped

    def writes_to(self, table: str, row_id: str) -> list[WriteEvent]:
        return [event for event in self.events if event.table == table and event.row_id == row_id]


# --------------------------------------------------------------------------- #
# Postgres adapter
# --------------------------------------------------------------------------- #

_STATEMENT = re.compile(r"statement:\s*(?P<sql>.*)$", re.IGNORECASE)
_APP_NAME = re.compile(r"app(?:lication)?[=:]?\s*(?P<app>[A-Za-z0-9_.:-]+)", re.IGNORECASE)
_INSERT = re.compile(
    r"INSERT\s+INTO\s+(?P<table>[\w.\"]+)\s*\((?P<columns>[^)]*)\)\s*VALUES\s*\((?P<values>[^)]*)\)",
    re.IGNORECASE | re.DOTALL,
)
_UPDATE = re.compile(
    r"UPDATE\s+(?P<table>[\w.\"]+)\s+SET\s+(?P<assignments>.*?)(?:\s+WHERE\s+(?P<where>.*))?$",
    re.IGNORECASE | re.DOTALL,
)
_WHERE_ID = re.compile(r"\"?(?P<column>\w+)\"?\s*=\s*'?\"?(?P<value>[^'\s]+)", re.IGNORECASE)


def _unquote(identifier: str) -> str:
    return identifier.strip().strip('"').strip("`")


def _split_values(raw: str) -> list[str]:
    values: list[str] = []
    current = ""
    in_quote = False
    for char in raw:
        if char == "'":
            in_quote = not in_quote
            current += char
            continue
        if char == "," and not in_quote:
            values.append(current.strip())
            current = ""
            continue
        current += char
    if current.strip():
        values.append(current.strip())
    return values


class PostgresLogParser:
    """Turn Postgres statement logs into attributed write events.

    The application is expected to tag its connections with
    ``SET application_name = 'mizan:<principal>'``; the parser reads the
    application name from the log prefix and attributes the statement to that
    principal.
    """

    def __init__(self, app_name_prefix: str = "mizan:") -> None:
        self.app_name_prefix = app_name_prefix
        self._app_pattern = re.compile(rf"(?P<app>{re.escape(app_name_prefix)}[A-Za-z0-9_.-]+)")

    def principal_from_app(self, app_name: str | None) -> str | None:
        if not app_name or not app_name.startswith(self.app_name_prefix):
            return None
        return app_name[len(self.app_name_prefix) :]

    def parse(self, lines: Iterable[str]) -> list[WriteEvent]:
        events: list[WriteEvent] = []
        for index, line in enumerate(lines):
            line = line.strip()
            if not line:
                continue
            app_match = self._app_pattern.search(line)
            app_name = app_match.group("app") if app_match else None
            principal = self.principal_from_app(app_name)
            statement = _STATEMENT.search(line)
            if statement is None:
                continue
            sql = statement.group("sql").strip().rstrip(";")
            event = self._parse_sql(sql, principal, request_id=f"pg-{index}")
            if event is not None:
                events.append(event)
        return events

    def _parse_sql(self, sql: str, principal: str | None, request_id: str) -> WriteEvent | None:
        insert = _INSERT.search(sql)
        if insert is not None:
            table = _unquote(insert.group("table"))
            columns = [_unquote(column) for column in insert.group("columns").split(",")]
            values = _split_values(insert.group("values"))
            row_id = values[0] if values else ""
            payload = dict(zip(columns, values))
            return WriteEvent(
                ts=0.0,
                request_id=request_id,
                principal=principal or "unknown",
                method="POST",
                path=f"/{table}",
                table=table,
                row_id=row_id,
                columns=payload,
                source_fields=set(columns),
            )
        update = _UPDATE.search(sql)
        if update is not None:
            table = _unquote(update.group("table"))
            assignments = update.group("assignments") or ""
            where = update.group("where") or ""
            columns: dict[str, Any] = {}
            for assignment in _split_values(assignments):
                if "=" not in assignment:
                    continue
                name, _, value = assignment.partition("=")
                columns[_unquote(name)] = value.strip().strip("'")
            row_id = ""
            where_match = _WHERE_ID.search(where)
            if where_match:
                row_id = where_match.group("value")
            return WriteEvent(
                ts=0.0,
                request_id=request_id,
                principal=principal or "unknown",
                method="PATCH",
                path=f"/{table}",
                table=table,
                row_id=row_id,
                columns=columns,
                source_fields=set(columns),
            )
        return None


# --------------------------------------------------------------------------- #
# Analysis
# --------------------------------------------------------------------------- #


class TaintAnalyzer:
    """Turn attributed write events into proven violations."""

    def __init__(self, policy: Policy, strict: bool = False) -> None:
        self.policy = policy
        self.strict = strict

    def analyze(self, events: Iterable[WriteEvent]) -> list[Violation]:
        violations: list[Violation] = []
        for event in events:
            violations.extend(self._analyze_event(event))
        return violations

    # -- individual checks ------------------------------------------------- #

    def _resource_for(self, event: WriteEvent) -> Resource:
        known = self.policy.resource(event.resource_key)
        if known is not None:
            return known
        return Resource(type=event.table, id=event.row_id, owner=event.row_owner)

    def _analyze_event(self, event: WriteEvent) -> list[Violation]:
        violations: list[Violation] = []
        principal = self.policy.principal(event.principal)
        resource = self._resource_for(event)

        # L3 - the write itself must be allowed for this exact row.
        if resource.owner is not None and resource.owner != principal.id:
            if not self.policy.permitted(principal, resource, event.action):
                violations.append(
                    Violation(
                        law="L3",
                        title=f"{principal.id} wrote a row owned by {resource.owner}",
                        detail=(
                            f"`{event.method} {event.path}` changed `{event.table}:{event.row_id}` "
                            f"which is owned by `{resource.owner}`, while the request was authenticated as "
                            f"`{principal.id}`. The write is not permitted for that row."
                        ),
                        severity="high",
                        principal=principal.id,
                        resource=resource.key,
                        action=event.action,
                        evidence={
                            "event": event.to_dict(),
                            "row_owner": resource.owner,
                            "columns": sorted(event.columns),
                        },
                        steps=[
                            Step(
                                method=event.method,
                                url=event.path,
                                headers={"Authorization": f"Bearer {principal.token}"} if principal.token else {},
                                body=event.method_args.get("body"),
                                note="the write that tainted the row",
                            )
                        ],
                    )
                )

        # L4 - nobody may create authority through a request.
        for column, value in event.columns.items():
            if not self.policy.authority_fields or column.lower() not in {
                field.lower() for field in self.policy.authority_fields
            }:
                continue
            if principal.is_privileged():
                continue
            if not self.policy.permitted(principal, resource, "admin"):
                violations.append(
                    Violation(
                        law="L4",
                        title=f"`{principal.id}` created authority by writing `{column}`",
                        detail=(
                            f"`{event.method} {event.path}` set `{column}={value!r}` on `{resource.key}`. "
                            f"`{column}` carries authority and the request was not made by a privileged principal."
                        ),
                        severity="critical",
                        principal=principal.id,
                        resource=resource.key,
                        action=event.action,
                        evidence={
                            "event": event.to_dict(),
                            "column": column,
                            "value": value,
                            "client_supplied": column in event.source_fields,
                        },
                        steps=[
                            Step(
                                method=event.method,
                                url=event.path,
                                headers={"Authorization": f"Bearer {principal.token}"} if principal.token else {},
                                body=event.method_args.get("body"),
                                note="the request that created authority",
                            )
                        ],
                    )
                )

        # L3 - unexplained writes: the server changed a field the client never sent
        # and that is not a known server-managed field. Off by default to keep
        # the signal clean.
        if self.strict:
            managed = self.policy.server_managed_fields.get(event.table, set())
            for column in event.columns:
                if column in event.source_fields or column in managed:
                    continue
                violations.append(
                    Violation(
                        law="L3",
                        title=f"Unattributed write to `{column}`",
                        detail=(
                            f"`{event.method} {event.path}` wrote `{column}` although the client never sent it "
                            f"and it is not a known server-managed field."
                        ),
                        severity="low",
                        principal=principal.id,
                        resource=resource.key,
                        action=event.action,
                        evidence={"event": event.to_dict(), "column": column},
                    )
                )
        return violations
