"""Shared engagement state: a coverage matrix and a task tree.

Two ideas ported from the frameworks studied:

  * Coverage matrix (Strix / PentestGPT): endpoint x bug-class x status, so the
    planner can see what has and has not been tested and never leaves a surface
    unexamined. PentestGPT's own docs name lost coverage as its main weakness;
    this fixes it.

  * Task tree (PentestGPT): an append-only, revisioned list of typed tasks the
    planner commits and the executor leases, with a hard task-kind boundary
    (DISCOVER / ENUMERATE / TEST / EXPLOIT / VERIFY / RECOVER).

Both persist as JSON in the engagement directory so agents across phases share
one view and humans can audit it.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field, asdict
from pathlib import Path

# the bug classes the coverage matrix tracks per endpoint
BUG_CLASSES = [
    "reflected-xss", "stored-xss", "dom-xss", "sqli", "command-injection",
    "ssti", "path-traversal", "lfi", "ssrf", "xxe", "open-redirect",
    "crlf-injection", "idor", "csrf", "cors-misconfig", "jwt",
    "graphql-introspection", "sensitive-exposure", "auth-bypass",
    "business-logic", "prototype-pollution", "deserialization",
]

TASK_KINDS = ["DISCOVER", "ENUMERATE", "TEST", "EXPLOIT", "VERIFY", "RECOVER"]
TASK_STATUS = ["blocked", "ready", "active", "done", "failed"]
COVER_STATUS = ["untested", "tested", "finding", "ruled_out", "open_proof_gap"]


@dataclass
class CoverageMatrix:
    endpoints: list[str] = field(default_factory=list)
    # cell[endpoint][bug_class] = status
    cells: dict[str, dict[str, str]] = field(default_factory=dict)

    def ensure(self, endpoint: str) -> None:
        if endpoint not in self.cells:
            self.cells[endpoint] = {bc: "untested" for bc in BUG_CLASSES}
            self.endpoints.append(endpoint)

    def mark(self, endpoint: str, bug_class: str, status: str) -> None:
        self.ensure(endpoint)
        if bug_class not in BUG_CLASSES:
            self.cells[endpoint][bug_class] = status
            return
        # don't downgrade a finding back to tested
        cur = self.cells[endpoint].get(bug_class, "untested")
        rank = {s: i for i, s in enumerate(COVER_STATUS)}
        if rank.get(status, 0) >= rank.get(cur, 0) or status == "finding":
            self.cells[endpoint][bug_class] = status

    def summary(self) -> dict:
        total = len(self.endpoints) * len(BUG_CLASSES)
        tested = sum(1 for e in self.cells.values()
                     for s in e.values() if s != "untested")
        findings = sum(1 for e in self.cells.values()
                       for s in e.values() if s == "finding")
        # endpoints that were exercised by at least one check (the meaningful
        # "did we cover the surface" number; matrix_fill_pct below is the raw
        # cell fraction and is naturally low because most classes don't apply
        # to most endpoints — it is not a recall figure).
        endpoints_tested = sum(1 for e in self.cells.values()
                               if any(s != "untested" for s in e.values()))
        n_ep = len(self.endpoints)
        return {
            "endpoints": n_ep,
            "endpoints_tested": endpoints_tested,
            "surface_coverage_pct": round(100 * endpoints_tested / n_ep, 1) if n_ep else 0.0,
            "cells": total,
            "cells_tested": tested,
            "matrix_fill_pct": round(100 * tested / total, 1) if total else 0.0,
            "findings": findings,
        }

    def to_dict(self) -> dict:
        return {"endpoints": self.endpoints, "cells": self.cells,
                "summary": self.summary()}

    def save(self, path: str | Path) -> None:
        Path(path).write_text(json.dumps(self.to_dict(), indent=2), encoding="utf-8")


@dataclass
class Task:
    id: str
    kind: str
    target: str
    objective: str
    done_when: str = ""
    depends_on: list[str] = field(default_factory=list)
    status: str = "ready"


@dataclass
class TaskTree:
    revision: int = 0
    tasks: list[Task] = field(default_factory=list)
    transitions: list[dict] = field(default_factory=list)  # append-only log

    def add(self, task: Task) -> None:
        self.tasks.append(task)
        self._log("add", task.id, task.status)

    def transition(self, task_id: str, status: str, note: str = "") -> None:
        if status not in TASK_STATUS:
            raise ValueError(f"bad status {status!r}")
        for t in self.tasks:
            if t.id == task_id:
                t.status = status
                self._log("transition", task_id, status, note)
                return
        raise KeyError(task_id)

    def _log(self, op: str, task_id: str, status: str, note: str = "") -> None:
        self.revision += 1
        self.transitions.append({"rev": self.revision, "op": op,
                                 "task": task_id, "status": status, "note": note})

    def open_tasks(self) -> list[Task]:
        return [t for t in self.tasks if t.status in ("ready", "active", "blocked")]

    def to_dict(self) -> dict:
        return {"revision": self.revision,
                "tasks": [asdict(t) for t in self.tasks],
                "transitions": self.transitions}

    def save(self, path: str | Path) -> None:
        Path(path).write_text(json.dumps(self.to_dict(), indent=2), encoding="utf-8")

    @classmethod
    def load(cls, path: str | Path) -> "TaskTree":
        data = json.loads(Path(path).read_text(encoding="utf-8"))
        tree = cls(revision=data.get("revision", 0),
                   transitions=data.get("transitions", []))
        tree.tasks = [Task(**t) for t in data.get("tasks", [])]
        return tree
