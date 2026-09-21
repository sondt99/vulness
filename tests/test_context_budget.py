"""Context budgeting: the blog's 25%-of-window constraint, made enforceable.

Estimation trims before dispatch; measurement reports what actually happened. Both are
tested here because they fail in different ways -- an estimator that overruns silently
fills the window, and a measurement that reads the wrong counters reports comfort.
"""

from __future__ import annotations

import pytest

from vulness.agents.context_budget import (
    HARNESS_BASELINE_TOKENS,
    ContextBudget,
    Section,
    estimate_tokens,
    occupancy_fraction,
    peak_occupancy,
    window_for,
)


def test_budget_subtracts_the_harness_baseline() -> None:
    """Claude Code spends ~22k tokens on its own system prompt before we add anything."""
    b = ContextBudget("sonnet", occupancy=0.25)
    assert b.budget_tokens == int(200_000 * 0.25) - HARNESS_BASELINE_TOKENS
    assert b.budget_tokens < 200_000 * 0.25


@pytest.mark.parametrize(
    "sections",
    [
        [Section("i", "I" * 3000, 0), Section("a", "A" * 40_000, 2, 2000)],
        [Section("i", "I" * 3000, 0), Section("a", "A" * 500_000, 2, 2000), Section("c", "C" * 500_000, 1, 4000)],
        [Section("i", "I" * 2000, 0)] + [Section(f"s{i}", "X" * 80_000, i + 1, 1000) for i in range(4)],
        [Section("i", "I" * 1000, 0), Section("e", "E" * 400_000, 1, 0)],
    ],
    ids=["one-oversized", "two-oversized", "five-sections", "no-floor"],
)
def test_fit_always_converges_under_budget(sections: list[Section]) -> None:
    """Regression: a floored section keeps its trim marker, which pushed it back over
    floor_chars and made the selector pick it forever while a second oversized section
    was never reached."""
    body, report = ContextBudget("sonnet").fit(sections)
    assert not report.over_budget, report.summary()
    assert estimate_tokens(body) <= report.budget_tokens


def test_required_sections_are_never_trimmed() -> None:
    """Priority 0 carries the instruction and the output contract. A hunter can re-read
    source it lost; it cannot recover a mangled JSON schema."""
    instruction = "INSTRUCTION-" * 500
    body, _ = ContextBudget("sonnet").fit(
        [Section("i", instruction, 0), Section("junk", "J" * 900_000, 1, 0)]
    )
    assert instruction in body


def test_lowest_priority_is_shed_first() -> None:
    body, report = ContextBudget("sonnet").fit(
        [
            Section("i", "I" * 1000, 0),
            Section("keep", "K" * 60_000, 1, 1000),
            Section("shed", "S" * 60_000, 9, 1000),
        ]
    )
    assert "shed" in report.trimmed or "shed" in report.dropped
    assert body.count("K") > body.count("S")


def test_peak_occupancy_sums_the_three_input_counters() -> None:
    """With prompt caching, input_tokens alone reads as single digits while tens of
    thousands of cached tokens do the work. Occupancy is the sum, not the visible field."""
    events = [
        {"message": {"usage": {"input_tokens": 5, "cache_read_input_tokens": 90_000}}},
        {"message": {"usage": {"input_tokens": 7, "cache_read_input_tokens": 150_000, "cache_creation_input_tokens": 2_000}}},
        {"type": "noise"},
    ]
    assert peak_occupancy(events) == 152_007
    assert occupancy_fraction(152_007, "sonnet") == pytest.approx(0.76, abs=0.01)


def test_peak_occupancy_tolerates_malformed_events() -> None:
    assert peak_occupancy([{}, {"message": None}, {"usage": "not-a-dict"}]) == 0


def test_unknown_model_gets_conservative_window() -> None:
    """An overestimated window lets an agent quietly fill its context; underestimating
    only trims early."""
    assert window_for("some-future-model") < window_for("sonnet")


def test_peak_occupancy_ignores_the_cumulative_result_event() -> None:
    """Regression: the terminal `result` event's usage is summed across the session, not
    per turn. Counting it reported 353% of a 200k window and produced 19 false alerts.

    Verified against claude 2.1.258: turns reporting cache_read 12,070 and 24,082 yielded
    a result event reading 36,152, which is their sum.
    """
    events = [
        {"type": "assistant", "message": {"usage": {"input_tokens": 2, "cache_creation_input_tokens": 12_012, "cache_read_input_tokens": 12_070}}},
        {"type": "assistant", "message": {"usage": {"input_tokens": 2, "cache_creation_input_tokens": 2_631, "cache_read_input_tokens": 24_082}}},
        {"type": "result", "usage": {"input_tokens": 4, "cache_read_input_tokens": 36_152}},
    ]
    assert peak_occupancy(events) == 26_715  # the larger real turn, not the 36k rollup
    assert occupancy_fraction(peak_occupancy(events), "sonnet") < 0.25
