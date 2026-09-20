"""Context budgeting.

    If you fill the context window, the model starts hallucinating. We keep each agent's
    job hyper-focused, keeping context usage below 25% of the total window.
        -- Cloudflare, "Build your own vulnerability harness"

Enforcing that needs two different things, and conflating them is why it is usually
skipped:

**Before dispatch** we can only *estimate*. Prompt text is trimmed to fit a token budget
using a char-based approximation, because no local tokenizer for these models is available
and counting via API would cost a call per task.

**After the run** we can *measure* exactly. Every assistant turn reports its own input
token count, and for a given turn

    occupancy = input_tokens + cache_creation_input_tokens + cache_read_input_tokens

is literally how full the window was at that moment. The peak across turns is the real
number, and it is the one worth alerting on -- a hunter's prompt is small, but forty turns
of reading source files is not.

Two measured constants on this setup, both surprising enough to be worth stating:

- **Claude Code injects ~22k tokens of its own** (system prompt plus tool schemas) before
  a single character of ours. That is ~11% of a 200k window spent before we start, so our
  own share of the 25% target is far smaller than it looks.
- Security source and playbooks run **~3 chars/token**, not the ~4 that prose does. Code,
  punctuation and file paths tokenize densely.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

# Context window per model family. Conservative: an underestimate trims too eagerly,
# an overestimate lets an agent silently fill its window.
MODEL_WINDOWS: dict[str, int] = {
    "sonnet": 200_000,
    "opus": 200_000,
    "haiku": 200_000,
    "glm-5.3": 200_000,
    "glm-5": 128_000,
    "glm-4.6": 128_000,
}
DEFAULT_WINDOW = 128_000

# Measured on claude 2.1.258: the CLI's own system prompt and tool definitions.
HARNESS_BASELINE_TOKENS = 22_000

# Measured against the real tokenizer on security source + playbook text.
CHARS_PER_TOKEN = 3.0

DEFAULT_OCCUPANCY = 0.25


def window_for(model: str) -> int:
    m = (model or "").lower()
    for key, size in MODEL_WINDOWS.items():
        if key in m:
            return size
    return DEFAULT_WINDOW


def estimate_tokens(text: str) -> int:
    """Conservative char-based estimate. Rounds up: over-trimming beats overflowing."""
    if not text:
        return 0
    return int(len(text) / CHARS_PER_TOKEN) + 1


@dataclass
class Section:
    """One labelled piece of a prompt, with a priority for trimming.

    `priority` 0 is never trimmed (the instruction itself, the output contract). Higher
    numbers are shed first. `floor_chars` keeps a trimmed section useful rather than
    leaving a stub that costs tokens and says nothing.
    """

    name: str
    text: str
    priority: int = 0
    floor_chars: int = 0

    @property
    def required(self) -> bool:
        return self.priority == 0


@dataclass
class FitReport:
    budget_tokens: int
    estimated_tokens: int
    trimmed: dict[str, tuple[int, int]] = field(default_factory=dict)  # name -> (was, now)
    dropped: list[str] = field(default_factory=list)
    over_budget: bool = False

    def summary(self) -> str:
        bits = [f"{self.estimated_tokens}/{self.budget_tokens} tok"]
        if self.trimmed:
            bits.append("trimmed " + ", ".join(f"{k} {a}->{b}c" for k, (a, b) in self.trimmed.items()))
        if self.dropped:
            bits.append("dropped " + ", ".join(self.dropped))
        if self.over_budget:
            bits.append("STILL OVER BUDGET")
        return "; ".join(bits)


class ContextBudget:
    """Fits a prompt into a share of the model's window, trimming by priority."""

    def __init__(
        self,
        model: str,
        *,
        occupancy: float = DEFAULT_OCCUPANCY,
        baseline_tokens: int = HARNESS_BASELINE_TOKENS,
    ) -> None:
        self.model = model
        self.window = window_for(model)
        self.occupancy = occupancy
        # The harness baseline is already spent, so it comes out of our share, not the
        # window at large. Budgeting against the raw window would overrun every time.
        self.budget_tokens = max(1_000, int(self.window * occupancy) - baseline_tokens)

    def fit(self, sections: list[Section], separator: str = "\n\n") -> tuple[str, FitReport]:
        """Assemble sections, trimming the lowest-priority ones until the budget holds.

        Iterates to a fixed point rather than trimming once per section: the trim marker
        adds characters back and per-section rounding is upward, so a single pass
        reliably lands a few tokens over and reports failure it could have avoided.
        """
        marker = "\n\n_[trimmed to fit context budget]_"
        marker_cost = estimate_tokens(marker)
        sep_cost = estimate_tokens(separator) * max(0, len(sections) - 1)
        report = FitReport(budget_tokens=self.budget_tokens, estimated_tokens=0)
        kept = {s.name: s.text for s in sections}
        original = {s.name: len(s.text) for s in sections}

        def total() -> int:
            return sum(estimate_tokens(t) for t in kept.values() if t) + sep_cost

        trimmable = sorted((s for s in sections if not s.required), key=lambda x: -x.priority)
        # Sections already reduced to their floor. Tracked explicitly because the trim
        # marker pushes a floored section back above floor_chars, and a length test alone
        # then re-selects it forever while a second oversized section is never reached.
        exhausted: set[str] = set()
        # Bounded: each pass either removes a section or shrinks one toward its floor.
        for _ in range(3 * len(trimmable) + 6):
            if total() <= self.budget_tokens:
                break
            target = next(
                (
                    s
                    for s in trimmable
                    if s.name not in exhausted
                    and kept[s.name]
                    and len(kept[s.name]) > s.floor_chars
                ),
                None,
            )
            if target is None:
                break
            over = total() - self.budget_tokens
            current = kept[target.name]
            # Take the overage plus the marker we are about to add, with a little slack
            # so rounding cannot leave us one token short on the next pass.
            trim_chars = int((over + marker_cost + 8) * CHARS_PER_TOKEN)
            new_len = len(current) - trim_chars
            if new_len <= target.floor_chars:
                # This section cannot absorb the overage. Take it to its floor in one
                # step and move to the next one, rather than converging on it by halves
                # and running out of passes with a second oversized section untouched.
                kept[target.name] = (current[: target.floor_chars] + marker) if target.floor_chars else ""
                exhausted.add(target.name)
            else:
                kept[target.name] = current[:new_len] + marker

        for s in sections:
            if s.required:
                continue
            if not kept[s.name]:
                report.dropped.append(s.name)
            elif len(kept[s.name]) < original[s.name]:
                report.trimmed[s.name] = (original[s.name], len(kept[s.name]))

        body = separator.join(kept[s.name] for s in sections if kept[s.name])
        report.estimated_tokens = estimate_tokens(body)
        report.over_budget = report.estimated_tokens > self.budget_tokens
        return body, report


def peak_occupancy(raw_events: list[dict[str, Any]]) -> int:
    """Exact peak context occupancy, from the agent's own per-turn usage reports.

    This is measurement, not estimation: for each assistant turn the three input counters
    sum to how full the window was on that request. The maximum over the run is the high
    water mark. A task whose peak crosses the target was doing too much and its cell
    should be split -- which is a coverage decision, so it belongs in the database.
    """
    peak = 0
    for event in raw_events:
        # A stream line that parses to a bare string or list is still a valid JSON
        # document, and calling .get() on it raises AttributeError from inside a stage.
        # Observed live: eleven hunt tasks crashed here on real CLI output.
        if not isinstance(event, dict):
            continue
        message = event.get("message")
        usage = (message if isinstance(message, dict) else {}).get("usage") or event.get("usage")
        if not isinstance(usage, dict):
            continue
        turn = (
            int(usage.get("input_tokens") or 0)
            + int(usage.get("cache_creation_input_tokens") or 0)
            + int(usage.get("cache_read_input_tokens") or 0)
        )
        peak = max(peak, turn)
    return peak


def occupancy_fraction(peak_tokens: int, model: str) -> float:
    return peak_tokens / window_for(model) if peak_tokens else 0.0
