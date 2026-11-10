"""Law-driven security checks for Schemathesis.

Schemathesis already covers the read side of object-level authorization. This
package adds the *write* side and the data-level view:

* :mod:`schemathesis.laws.core` - the law model, the policy, the access matrix
* :mod:`schemathesis.laws.taint` - attribute writes to principals, flag cross-identity writes and authority creation
* :mod:`schemathesis.laws.proof` - proof bundles that can be replayed
* :mod:`schemathesis.laws.checks` - the Schemathesis check that enforces the laws

Example
-------

.. code-block:: bash

    export MIZAN_POLICY=mizan-policy.json
    export MIZAN_LEDGER=ledger.jsonl
    schemathesis run http://127.0.0.1:8000/openapi.json --checks MizanLawCheck
"""

from __future__ import annotations

from schemathesis.laws.core import (
    LAWS,
    AccessMatrix,
    Law,
    Policy,
    Principal,
    Resource,
    Rule,
    Step,
    Violation,
)
from schemathesis.laws.proof import ProofBundle
from schemathesis.laws.taint import Ledger, PostgresLogParser, TaintAnalyzer, WriteEvent

__all__ = [
    "LAWS",
    "AccessMatrix",
    "Law",
    "Ledger",
    "Policy",
    "PostgresLogParser",
    "Principal",
    "ProofBundle",
    "Resource",
    "Rule",
    "Step",
    "TaintAnalyzer",
    "Violation",
    "WriteEvent",
    "register",
]


def register() -> None:
    """Register the law checks with Schemathesis."""
    from schemathesis.laws.checks import register as _register

    _register()
