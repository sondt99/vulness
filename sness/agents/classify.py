"""Response classification.

Cloudflare's sharpest operational warning:

    Sometimes a transient API error comes back as text in the (200 OK) response stream
    instead of throwing a code exception. To the orchestrator, this looks exactly like a
    task that finished cleanly. You must explicitly classify the response text, not just
    trust the exception type, or you end up logging empty runs as successes.

So: exit code, terminal event, AND content are all consulted. A hunter that "found nothing"
because the API was throttled must never be recorded as a clean sweep of the code.
"""

from __future__ import annotations

import re
from typing import Any

from sness.agents.base import Classification

# Prose that means "the backend failed", regardless of a 200 status.
_ERROR_PATTERNS: tuple[re.Pattern[str], ...] = tuple(
    re.compile(p, re.IGNORECASE)
    for p in (
        r"\bAPI Error\b",
        r"\bapi_error\b",
        r"\boverloaded_error\b",
        r"\brate[_ ]?limit(ed|_error)?\b",
        r"\bquota (exceeded|exhausted)\b",
        r"\binsufficient[_ ]quota\b",
        r"\b5\d\d\s+(Internal Server Error|Bad Gateway|Service Unavailable|Gateway Time-?out)\b",
        r"\bInternal server error\b",
        r"\bService (temporarily )?[Uu]navailable\b",
        r"\bupstream (connect|request) (error|timeout)\b",
        r"\bConnection (reset|refused|error)\b",
        r"\brequest (timed out|timeout)\b",
        r"\bECONNRESET\b|\bETIMEDOUT\b|\bEPIPE\b",
        r"\bContext (window )?(exceeded|too long|limit)\b",
        r"\bprompt is too long\b",
        r"\bmax(imum)? context length\b",
        r"\bCredit balance is too low\b",
        r"\bauthentication[_ ]error\b|\binvalid[_ ]api[_ ]key\b|\bUnauthorized\b",
        r"\bClaude (Code )?is unable to\b",
        r"\bI (?:ran into|encountered|hit) an (?:API )?error\b",
    )
)

# Text that looks alarming but is legitimate analysis output, not a backend failure.
# A security agent discusses rate limits and timeouts as *subject matter*.
_BENIGN_CONTEXT = re.compile(
    r"(vulnerab|finding|attack|threat|mitigat|remediat|exploit|the code|this function|"
    r"handler|endpoint|severity|boundary|CWE|denial[- ]of[- ]service)",
    re.IGNORECASE,
)

# Beneath this, a "successful" transcript is almost certainly a truncated failure.
_MIN_MEANINGFUL_CHARS = 40


def looks_like_api_error(text: str) -> tuple[bool, str]:
    """Detect backend failure prose. Returns (is_error, matched_pattern)."""
    if not text:
        return False, ""
    # Errors surface at the very start or the very end of a transcript; the middle is analysis.
    head, tail = text[:600], text[-600:]
    for window in (head, tail):
        for pat in _ERROR_PATTERNS:
            m = pat.search(window)
            if not m:
                continue
            # A long transcript that clearly discusses security is analysis, not an outage --
            # unless the error prose is essentially all there is.
            if len(text) > 1500 and _BENIGN_CONTEXT.search(window):
                continue
            return True, m.group(0)
    return False, ""


def classify(
    *,
    text: str,
    exit_code: int | None = None,
    timed_out: bool = False,
    terminal_event: dict[str, Any] | None = None,
    expects_json: bool = False,
    payload: dict[str, Any] | None = None,
) -> tuple[Classification, str | None]:
    """Decide whether a completed agent run may be trusted. Returns (classification, reason)."""
    if timed_out:
        return "timeout", "wall-clock timeout"

    # A terminal stream event that self-reports an error beats everything else.
    if terminal_event:
        if terminal_event.get("is_error") is True:
            return "api_error_text", f"terminal event is_error: {terminal_event.get('subtype', '')}"
        subtype = str(terminal_event.get("subtype", ""))
        if subtype and subtype not in ("success", "done", "completed"):
            return "api_error_text", f"terminal subtype={subtype}"

    if exit_code not in (None, 0):
        # A non-zero exit whose output is error prose is still an API failure, not a crash:
        # the distinction decides whether we requeue or give up.
        is_err, matched = looks_like_api_error(text)
        if is_err:
            return "api_error_text", f"exit={exit_code}, matched {matched!r}"
        return "crash", f"exit code {exit_code}: {text.strip()[-300:] or 'no output'}"

    stripped = text.strip()
    if not stripped:
        return "empty", "no output"

    is_err, matched = looks_like_api_error(stripped)
    if is_err:
        return "api_error_text", f"matched {matched!r}"

    if len(stripped) < _MIN_MEANINGFUL_CHARS:
        return "empty", f"output too short ({len(stripped)} chars)"

    if expects_json and payload is None:
        return "schema_invalid", "no parseable JSON object in transcript"

    return "ok", None


def is_retryable(classification: Classification) -> bool:
    """Transient backend problems earn a requeue; genuine crashes do not.

    `schema_invalid` belongs here, which is not obvious. Models are stochastic: the same
    validator prompt that returned unparseable prose once returns clean JSON on the next
    attempt. Treating it as fatal silently strands real findings as unvalidated candidates
    -- observed in practice, where a transient parse failure left a confirmed-critical SQL
    injection permanently unreviewed. `crash` stays non-retryable because it means a
    deterministic misconfiguration (bad key, missing binary) that will fail identically forever.
    """
    return classification in ("api_error_text", "timeout", "empty", "schema_invalid")
