"""Spend control.

The grid makes cost countable: one cell is roughly one hunter, one candidate is roughly one
validator. The rule that matters is **reserve validation before you hunt**. A run that
spends its whole budget hunting and then cannot afford to validate produces a pile of
unverified claims, which is worse than producing nothing -- it looks like output.
"""

from __future__ import annotations

from dataclasses import dataclass

from sness.state.db import Database


@dataclass
class BudgetDecision:
    allowed: bool
    reason: str = "ok"


class Budget:
    def __init__(self, db: Database, run_id: str, *, per_repo: int, validator_reserve: float):
        self.db = db
        self.run_id = run_id
        self.per_repo = per_repo
        self.validator_reserve = validator_reserve

    def remaining(self, repo_id: str) -> int:
        return max(0, self.per_repo - self.db.spent_tasks(self.run_id, repo_id))

    def can_dispatch(self, repo_id: str, kind: str) -> BudgetDecision:
        """Validation and recon are never starved; hunting is what gets throttled."""
        remaining = self.remaining(repo_id)
        if remaining <= 0:
            return BudgetDecision(False, f"per-repo budget exhausted ({self.per_repo} tasks)")

        # Validators and recon spend from the reserve; only hunts are held back by it.
        if kind in ("validate", "recon", "judge", "dedup", "fix", "feedback", "trace"):
            return BudgetDecision(True)

        reserve = int(self.per_repo * self.validator_reserve)
        unvalidated = len(self.db.findings(self.run_id, verdict="candidate", repo_id=repo_id))
        needed = max(reserve, unvalidated)
        if remaining <= needed:
            return BudgetDecision(
                False,
                f"holding {remaining} tasks in reserve to validate {unvalidated} open candidates",
            )
        return BudgetDecision(True)

    def summary(self, repo_id: str) -> dict[str, int]:
        return {
            "budget": self.per_repo,
            "spent": self.db.spent_tasks(self.run_id, repo_id),
            "remaining": self.remaining(repo_id),
            "reserve": int(self.per_repo * self.validator_reserve),
        }
