"""Proof bundles: a finding that can be replayed, diffed and regressed against."""

from __future__ import annotations

# The engine lives in `schemathesis.laws`; the imports below are rewritten from
# the standalone `mizan` package when this patch is generated.
from __future__ import annotations

import json
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from schemathesis.laws.core import Violation

_SLUG = re.compile(r"[^a-z0-9]+")


def slugify(text: str) -> str:
    return _SLUG.sub("-", text.lower()).strip("-")[:60]


@dataclass
class ProofBundle:
    """A directory holding everything needed to replay a finding."""

    directory: Path

    @classmethod
    def create(
        cls,
        root: str | Path,
        violation: Violation,
        *,
        evidence: dict[str, Any] | None = None,
        dbdiff: dict[str, Any] | None = None,
        matrix: dict[str, Any] | None = None,
        patch: str | None = None,
        regression_test: str | None = None,
    ) -> Path:
        root = Path(root)
        name = f"{violation.law}-{slugify(violation.title)}"
        directory = root / name
        suffix = 1
        while directory.exists():
            suffix += 1
            directory = root / f"{name}-{suffix}"
        directory.mkdir(parents=True)

        payload = {
            "law": violation.law,
            "law_name": violation.law_name,
            "title": violation.title,
            "detail": violation.detail,
            "severity": violation.severity,
            "principal": violation.principal,
            "resource": violation.resource,
            "action": violation.action,
            "steps": [step.to_dict() for step in violation.steps],
        }
        (directory / "replay.json").write_text(json.dumps(payload, indent=2, ensure_ascii=False), encoding="utf-8")
        (directory / "violation.md").write_text(_render_markdown(violation, evidence), encoding="utf-8")
        (directory / "evidence.json").write_text(
            json.dumps(evidence or violation.evidence, indent=2, ensure_ascii=False, default=str), encoding="utf-8"
        )
        if dbdiff is not None:
            (directory / "dbdiff.json").write_text(json.dumps(dbdiff, indent=2, ensure_ascii=False, default=str), encoding="utf-8")
        if matrix is not None:
            (directory / "matrix.json").write_text(json.dumps(matrix, indent=2, ensure_ascii=False, default=str), encoding="utf-8")
        if patch:
            (directory / "patch.diff").write_text(patch, encoding="utf-8")
        if regression_test:
            (directory / "regression.test").write_text(regression_test, encoding="utf-8")
        return directory

    # -- verification ------------------------------------------------------ #

    @classmethod
    def load(cls, directory: str | Path) -> ProofBundle:
        return cls(directory=Path(directory))

    def replay(self) -> dict[str, Any]:
        return json.loads((self.directory / "replay.json").read_text(encoding="utf-8"))

    def verify(self, session: Any) -> dict[str, Any]:
        """Replay the recorded steps against a live target.

        `session` is a `requests.Session`-like object. The verifier returns a
        structured result instead of raising, so a CI job can decide.
        """
        payload = self.replay()
        results: list[dict[str, Any]] = []
        for step in payload.get("steps", []):
            request_kwargs: dict[str, Any] = {"headers": step.get("headers") or {}}
            if step.get("body") is not None:
                request_kwargs["json"] = step["body"]
            try:
                response = session.request(step["method"], step["url"], **request_kwargs)
            except Exception as exc:  # pragma: no cover - network dependent
                results.append({"step": step, "error": str(exc)})
                continue
            results.append(
                {
                    "step": step,
                    "status": response.status_code,
                    "body": _safe_json(response),
                }
            )
        return {"bundle": str(self.directory), "steps": results, "violation": payload}


def _safe_json(response: Any) -> Any:
    try:
        return response.json()
    except Exception:
        return getattr(response, "text", "")[:2000]


def _render_markdown(violation: Violation, evidence: dict[str, Any] | None) -> str:
    lines = [
        f"# {violation.law} - {violation.law_name}",
        "",
        f"**{violation.title}**",
        "",
        violation.detail,
        "",
        "| | |",
        "|---|---|",
        f"| Severity | `{violation.severity}` |",
        f"| Principal | `{violation.principal or '-'}` |",
        f"| Resource | `{violation.resource or '-'}` |",
        f"| Action | `{violation.action or '-'}` |",
        "",
        "## Reproduction",
        "",
    ]
    for index, step in enumerate(violation.steps, start=1):
        lines.append(f"### Step {index}: `{step.method} {step.url}`")
        if step.headers:
            lines.append("")
            lines.append("```http")
            for name, value in step.headers.items():
                lines.append(f"{name}: {value}")
            lines.append("```")
        if step.body is not None:
            lines.append("")
            lines.append("```json")
            lines.append(json.dumps(step.body, indent=2, ensure_ascii=False))
            lines.append("```")
        if step.status is not None:
            lines.append("")
            lines.append(f"Response: `{step.status}`")
        if step.note:
            lines.append("")
            lines.append(f"> {step.note}")
        lines.append("")
    if evidence:
        lines.extend(["## Evidence", "", "```json", json.dumps(evidence, indent=2, ensure_ascii=False, default=str), "```", ""])
    lines.extend(
        [
            "---",
            "",
            "Generated by Mizan. Every finding in a bundle is reproducible by replaying `replay.json`.",
        ]
    )
    return "\n".join(lines)
