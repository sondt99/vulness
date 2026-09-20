"""The agent contract. Every model call in s-ness returns an AgentResult, classified."""

from __future__ import annotations

import json
import re
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Literal

Classification = Literal["ok", "api_error_text", "timeout", "empty", "schema_invalid", "crash"]

# Agents emit structured results inside a fenced block so prose can never be mistaken for data.
_FENCE = re.compile(r"```(?:json)?\s*\n(.*?)\n```", re.DOTALL)


@dataclass
class AgentResult:
    """What came back, and whether we are allowed to believe it."""

    classification: Classification = "ok"
    text: str = ""
    payload: dict[str, Any] | None = None
    tokens_in: int = 0
    tokens_out: int = 0
    cost_usd: float = 0.0
    duration_s: float = 0.0
    model: str = ""
    error: str | None = None
    raw_events: list[dict] = field(default_factory=list)

    @property
    def ok(self) -> bool:
        return self.classification == "ok"

    def extract_json(self) -> dict[str, Any] | None:
        """Pull the last fenced JSON object out of the transcript.

        Last, not first: agents commonly show a worked example before the real answer.
        """
        if self.payload is not None:
            return self.payload
        blocks = _FENCE.findall(self.text)
        for block in reversed(blocks):
            try:
                parsed = json.loads(block)
            except json.JSONDecodeError:
                continue
            if isinstance(parsed, dict):
                return parsed
            if isinstance(parsed, list):
                return {"items": parsed}
        # Fall back to a bare object spanning the tail of the transcript.
        start = self.text.find("{")
        if start >= 0:
            try:
                obj = json.loads(self.text[start:])
                if isinstance(obj, dict):
                    return obj
            except json.JSONDecodeError:
                pass
        return None


class Agent(ABC):
    """A backend that can run one focused prompt to completion."""

    name: str = "agent"
    model: str = ""

    @abstractmethod
    async def run(
        self,
        prompt: str,
        *,
        system: str | None = None,
        cwd: Path | None = None,
        timeout_s: int | None = None,
        schema: dict[str, Any] | None = None,
        allowed_tools: list[str] | None = None,
    ) -> AgentResult:
        """Execute one task. Must never raise for model-side failure -- classify instead."""

    async def health(self) -> tuple[bool, str]:
        return True, "not implemented"
