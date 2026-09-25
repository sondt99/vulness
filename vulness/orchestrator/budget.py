"""Spend control.

The grid makes cost countable: one cell is roughly one hunter, one candidate is roughly one
validator. The rule that matters is **reserve validation before you hunt**. A run that
spends its whole budget hunting and then cannot afford to validate produces a pile of
unverified claims, which is worse than producing nothing -- it looks like output.
"""

from __future__ import annotations

from dataclasses import dataclass

from vulness.state.db import Database


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
        # Triage and validation are bounded by how many findings exist, not by how many
        # cells the grid invented, so they cannot run away. Hunting is the unbounded thing,
        # and it is the only thing this budget exists to throttle.
        if kind in ("validate", "recon", "judge", "dedup", "fix", "feedback", "trace", "chain"):
            return BudgetDecision(True)

        remaining = self.remaining(repo_id)
        if remaining <= 0:
            return BudgetDecision(False, f"per-repo budget exhausted ({self.per_repo} tasks)")

        reserve = int(self.per_repo * self.validator_reserve)
        unvalidated = self.db.count_findings(self.run_id, verdict="candidate", repo_id=repo_id)
        # The reserve pays for validating what hunting produced, so it is only owed when
        # something is actually waiting. Holding the floor against an empty backlog strands
        # the last 30% of every budget: one run abandoned 34 of 59 hunts on the reason
        # "holding 3 tasks in reserve to validate 0 open candidates". Validation is exempt
        # from this gate anyway, so a candidate filed by the last hunt still gets paid for.
        needed = max(reserve, unvalidated) if unvalidated else 0
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
