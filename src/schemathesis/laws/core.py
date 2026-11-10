"""Law model: principals, resources, access rules and the access matrix."""

from __future__ import annotations

# The engine lives in `schemathesis.laws`; the imports below are rewritten from
# the standalone `mizan` package when this patch is generated.
from __future__ import annotations

import math
from dataclasses import dataclass, field
from typing import Any, Iterable, Iterator

# --------------------------------------------------------------------------- #
# Laws
# --------------------------------------------------------------------------- #


@dataclass(frozen=True)
class Law:
    id: str
    name: str
    severity: str
    description: str


LAWS: dict[str, Law] = {
    law.id: law
    for law in (
        Law("L1", "Authentication coherence", "high", "The identity used to serve a request is the one the client presented."),
        Law("L2", "Read authorization (read-taint)", "high", "An object returned to a caller must belong to that caller or be visible to their role."),
        Law("L3", "Write authorization (write-taint)", "high", "Every database write must be attributable to a principal and permitted for that exact row."),
        Law("L4", "No authority creation", "critical", "A request must never change the authority of its sender or of anybody else."),
        Law("L5", "Atomicity (TOCTOU)", "high", "A check followed by an action must be atomic; concurrent identical actions must not both succeed."),
        Law("L6", "Cardinality and bounds", "medium", "Counters are bounded and single-use resources are not reusable."),
        Law("L7", "Path confidentiality", "medium", "No field may leave the system outside the caller's authority, including through caches and queues."),
    )
}

#: Field names that carry *authority*. A non-privileged caller must never be able
#: to set them. Matched case-insensitively as a whole word.
#:
#: Business data (prices, balances, amounts) is deliberately *not* here: those
#: fields are data, not authority, and treating them as authority produces
#: false positives on every ordinary update.
AUTHORITY_FIELDS: frozenset[str] = frozenset(
    {
        "role",
        "roles",
        "is_admin",
        "admin",
        "is_superuser",
        "superuser",
        "permissions",
        "scopes",
        "owner_id",
        "owner",
        "tenant_id",
        "tenant",
        "is_verified",
        "verified",
        "email_verified",
        "is_active",
        "disabled",
        "limit",
        "quota",
    }
)

#: Operations whose semantics are naturally single-use. Used to decide when a
#: successful race is a real violation instead of an idempotent no-op.
SINGLE_USE_HINTS: tuple[str, ...] = (
    "approve",
    "redeem",
    "claim",
    "consume",
    "apply",
    "activate",
    "verify",
    "coupon",
    "discount",
    "promo",
    "voucher",
    "checkout",
    "pay",
    "confirm",
    "submit",
    "use",
)


# --------------------------------------------------------------------------- #
# Actors and data
# --------------------------------------------------------------------------- #


@dataclass(frozen=True)
class Principal:
    """An identity that can act on the system."""

    id: str
    roles: tuple[str, ...] = ()
    token: str | None = None

    def is_privileged(self) -> bool:
        return any(role in {"admin", "superuser", "owner", "root"} for role in self.roles)


@dataclass(frozen=True)
class Resource:
    """A row-like object owned by somebody."""

    type: str
    id: str
    owner: str | None = None
    tenant: str | None = None

    @property
    def key(self) -> str:
        return f"{self.type}:{self.id}"


@dataclass(frozen=True)
class Access:
    """One `(principal, resource, action)` triple."""

    principal: str
    resource: str
    action: str

    def as_tuple(self) -> tuple[str, str, str]:
        return (self.principal, self.resource, self.action)


@dataclass
class Step:
    """A single step of a reproduction."""

    method: str
    url: str
    headers: dict[str, str] = field(default_factory=dict)
    body: Any = None
    status: int | None = None
    note: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "method": self.method,
            "url": self.url,
            "headers": self.headers,
            "body": self.body,
            "status": self.status,
            "note": self.note,
        }


@dataclass
class Violation:
    """A proven breach of one law."""

    law: str
    title: str
    detail: str
    severity: str = "high"
    principal: str | None = None
    resource: str | None = None
    action: str | None = None
    evidence: dict[str, Any] = field(default_factory=dict)
    steps: list[Step] = field(default_factory=list)

    @property
    def law_name(self) -> str:
        law = LAWS.get(self.law)
        return law.name if law else self.law

    def to_dict(self) -> dict[str, Any]:
        return {
            "law": self.law,
            "law_name": self.law_name,
            "title": self.title,
            "detail": self.detail,
            "severity": self.severity,
            "principal": self.principal,
            "resource": self.resource,
            "action": self.action,
            "evidence": self.evidence,
            "steps": [step.to_dict() for step in self.steps],
        }


# --------------------------------------------------------------------------- #
# Policy
# --------------------------------------------------------------------------- #


@dataclass(frozen=True)
class Rule:
    """One access rule.

    ``kind`` is one of:

    ``owner``    - the principal may act when it owns the resource
    ``role``     - the principal may act when it holds ``role``
    ``public``   - everybody may act
    ``explicit`` - the named principal may act on the named resource
    """

    kind: str
    action: str
    resource_type: str | None = None
    role: str | None = None
    principal: str | None = None
    resource: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {k: v for k, v in self.__dict__.items() if v is not None}


@dataclass
class Policy:
    """What the application is allowed to do, as learned from its normal behaviour."""

    principals: dict[str, Principal] = field(default_factory=dict)
    resources: dict[str, Resource] = field(default_factory=dict)
    rules: list[Rule] = field(default_factory=list)
    #: resource type -> fields a client must never be able to write
    read_only_fields: dict[str, set[str]] = field(default_factory=dict)
    #: resource type -> fields written by the server itself
    server_managed_fields: dict[str, set[str]] = field(default_factory=dict)
    authority_fields: set[str] = field(default_factory=lambda: set(AUTHORITY_FIELDS))
    notes: list[str] = field(default_factory=list)

    # -- queries ---------------------------------------------------------- #

    def principal(self, principal_id: str) -> Principal:
        return self.principals.get(principal_id, Principal(id=principal_id))

    def resource(self, key: str) -> Resource | None:
        return self.resources.get(key)

    def permitted(self, principal: Principal, resource: Resource, action: str) -> bool:
        """Whether `principal` may perform `action` on `resource`."""
        for rule in self.rules:
            if rule.action not in {action, "*"}:
                continue
            if rule.resource_type is not None and rule.resource_type != resource.type:
                continue
            if rule.kind == "public":
                return True
            if rule.kind == "owner":
                if resource.owner is not None and resource.owner == principal.id:
                    return True
            elif rule.kind == "role":
                if rule.role is not None and rule.role in principal.roles:
                    return True
            elif rule.kind == "explicit":
                if rule.principal == principal.id and (rule.resource is None or rule.resource == resource.key):
                    return True
        return False

    def may_write_field(self, principal: Principal, resource: Resource, field_name: str) -> bool:
        """Whether `principal` may set `field_name` on `resource`."""
        if field_name in self.read_only_fields.get(resource.type, set()):
            return False
        return self.permitted(principal, resource, "write")

    # -- serialization ---------------------------------------------------- #

    def to_dict(self) -> dict[str, Any]:
        return {
            "principals": {
                pid: {"id": p.id, "roles": list(p.roles), "token": p.token} for pid, p in self.principals.items()
            },
            "resources": {
                key: {"type": r.type, "id": r.id, "owner": r.owner, "tenant": r.tenant}
                for key, r in self.resources.items()
            },
            "rules": [rule.to_dict() for rule in self.rules],
            "read_only_fields": {k: sorted(v) for k, v in self.read_only_fields.items()},
            "server_managed_fields": {k: sorted(v) for k, v in self.server_managed_fields.items()},
            "authority_fields": sorted(self.authority_fields),
            "notes": self.notes,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> Policy:
        principals = {
            pid: Principal(id=item["id"], roles=tuple(item.get("roles", ())), token=item.get("token"))
            for pid, item in data.get("principals", {}).items()
        }
        resources = {
            key: Resource(type=item["type"], id=item["id"], owner=item.get("owner"), tenant=item.get("tenant"))
            for key, item in data.get("resources", {}).items()
        }
        rules = [Rule(**item) for item in data.get("rules", [])]
        policy = cls(
            principals=principals,
            resources=resources,
            rules=rules,
            read_only_fields={k: set(v) for k, v in data.get("read_only_fields", {}).items()},
            server_managed_fields={k: set(v) for k, v in data.get("server_managed_fields", {}).items()},
            authority_fields=set(data.get("authority_fields", AUTHORITY_FIELDS)),
            notes=list(data.get("notes", [])),
        )
        return policy


# --------------------------------------------------------------------------- #
# Access matrix
# --------------------------------------------------------------------------- #


class AccessMatrix:
    """A sparse `(principal, resource, action) -> allowed` matrix.

    The engine keeps two matrices: the *observed* one (what actually happened)
    and the *permitted* one (what the policy allows). Their difference is the
    residual, and the residual is what a vulnerability looks like.
    """

    def __init__(self, cells: dict[tuple[str, str, str], bool] | None = None) -> None:
        self._cells: dict[tuple[str, str, str], bool] = dict(cells or {})

    def grant(self, principal: str, resource: str, action: str) -> None:
        self._cells[(principal, resource, action)] = True

    def allowed(self, principal: str, resource: str, action: str) -> bool:
        return self._cells.get((principal, resource, action), False)

    def cells(self) -> dict[tuple[str, str, str], bool]:
        return dict(self._cells)

    def residual(self, permitted: AccessMatrix) -> AccessMatrix:
        """Cells that are observed but not permitted."""
        residual = AccessMatrix()
        for cell, value in self._cells.items():
            if value and not permitted.allowed(*cell):
                residual.grant(*cell)
        return residual

    def norm(self) -> dict[str, float]:
        """L2 norm of the residual per principal - how far each identity strayed."""
        norms: dict[str, float] = {}
        for (principal, _resource, _action), value in self._cells.items():
            if value:
                norms[principal] = norms.get(principal, 0.0) + 1.0
        return {principal: math.sqrt(count) for principal, count in norms.items()}

    def to_dict(self) -> dict[str, Any]:
        return {
            "cells": [
                {"principal": p, "resource": r, "action": a, "allowed": v}
                for (p, r, a), v in sorted(self._cells.items())
            ]
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> AccessMatrix:
        matrix = cls()
        for cell in data.get("cells", []):
            matrix.grant(cell["principal"], cell["resource"], cell["action"])
        return matrix

    def __iter__(self) -> Iterator[Access]:
        for (principal, resource, action), value in self._cells.items():
            if value:
                yield Access(principal=principal, resource=resource, action=action)

    def __len__(self) -> int:
        return len(self._cells)

    def __repr__(self) -> str:  # pragma: no cover - debugging helper
        return f"AccessMatrix(cells={len(self._cells)})"


def actions_for(method: str) -> str:
    """Map an HTTP method to an abstract action."""
    method = method.upper()
    if method in {"GET", "HEAD", "OPTIONS"}:
        return "read"
    if method in {"POST", "PUT", "PATCH", "DELETE"}:
        return "write"
    return method.lower()


def is_authority_field(name: str, extra: Iterable[str] = ()) -> bool:
    """Whether a field name looks like it carries authority."""
    lowered = name.lower()
    if lowered in {e.lower() for e in extra}:
        return True
    if lowered in AUTHORITY_FIELDS:
        return True
    return any(lowered.endswith(f"_{field}") or lowered.startswith(f"{field}_") for field in AUTHORITY_FIELDS)
