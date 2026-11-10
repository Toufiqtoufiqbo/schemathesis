"""Schemathesis check that enforces the learned laws."""

from __future__ import annotations

# The engine lives in `schemathesis.laws`; the imports below are rewritten from
# the standalone `mizan` package when this patch is generated.
from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any

from schemathesis.laws.core import Policy, Principal, Violation
from schemathesis.laws.taint import Ledger, TaintAnalyzer

POLICY_ENV = "MIZAN_POLICY"
LEDGER_ENV = "MIZAN_LEDGER"

_registered = False


def load_policy(path: str | Path | None = None) -> Policy:
    """Load a learned policy from disk (``MIZAN_POLICY`` by default)."""
    candidate = path or os.environ.get(POLICY_ENV)
    if not candidate:
        return Policy()
    file = Path(candidate)
    if not file.exists():
        return Policy()
    return Policy.from_dict(json.loads(file.read_text(encoding="utf-8")))


def _identity_of(case: Any) -> str | None:
    identity = getattr(case, "auth_identity", None)
    return str(identity) if identity else None


def _body_of(response: Any) -> Any:
    try:
        return response.json()
    except Exception:
        return None


def build_check_class() -> Any:
    """Build the Schemathesis check class.

    The class is created lazily so that importing Mizan never requires
    Schemathesis to be installed.
    """
    import schemathesis

    @schemathesis.check
    class MizanLawCheck:
        """Check that the caller stays inside the authority its identity grants.

        Configure it with ``MIZAN_POLICY`` (a policy learned by ``mizan learn``)
        and, optionally, ``MIZAN_LEDGER`` (a ledger of attributed writes).
        """

        def __init__(self) -> None:
            self.policy = load_policy()
            self.ledger_path = os.environ.get(LEDGER_ENV)
            self._seen_events: set[str] = set()
            self._taint = TaintAnalyzer(self.policy)

        # -- read side ---------------------------------------------------- #

        def after_response(self, ctx: Any, response: Any, case: Any) -> None:
            identity = _identity_of(case)
            if identity is None:
                return
            body = _body_of(response)
            if isinstance(body, dict):
                owner = None
                for key in ("owner_id", "user_id", "owner"):
                    if isinstance(body.get(key), (str, int)):
                        owner = str(body[key])
                        break
                if owner is not None and owner != identity:
                    principal = self.policy.principal(identity)
                    if principal.roles:
                        # A known role may legitimately widen the scope; the
                        # learned rules decide.
                        pass
                    if not self.policy.principals or not principal.is_privileged():
                        raise AssertionError(
                            f"L2 - `{identity}` received an object owned by `{owner}`. "
                            "The response crosses an ownership boundary."
                        )
            self._check_writes(identity)

        # -- write side --------------------------------------------------- #

        def _check_writes(self, identity: str) -> None:
            if not self.ledger_path:
                return
            path = Path(self.ledger_path)
            if not path.exists():
                return
            ledger = Ledger.load(path)
            fresh = [event for event in ledger.events if event.request_id not in self._seen_events]
            if not fresh:
                return
            for event in fresh:
                self._seen_events.add(event.request_id)
            for violation in self._taint.analyze(fresh):
                raise AssertionError(_render(violation))

    return MizanLawCheck


def _render(violation: Violation) -> str:
    return f"{violation.law} - {violation.title}: {violation.detail}"


def register() -> None:
    """Register Mizan's checks with Schemathesis (idempotent)."""
    global _registered
    if _registered:
        return
    build_check_class()
    _registered = True
