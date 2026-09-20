"""Prompt library.

Kept as Markdown templates rather than string literals in code, because the prompts are
the product: they get tuned constantly, by hand, often by someone who is not editing
Python that day. `{placeholders}` are filled by `render()`; literal braces in the JSON
output contracts are escaped as `{{` `}}`.
"""

from __future__ import annotations

from functools import lru_cache
from pathlib import Path

_DIR = Path(__file__).parent


@lru_cache(maxsize=32)
def _template(name: str) -> str:
    path = _DIR / f"{name}.md"
    if not path.is_file():
        raise FileNotFoundError(f"no prompt template {name!r} in {_DIR}")
    return path.read_text()


def preamble() -> str:
    """Shared rules every role inherits: the candidate gate, severity anchors, anti-patterns."""
    return _template("_preamble")


def render(name: str, **kw: object) -> str:
    """Fill a template. Missing keys fail loudly here rather than silently in a prompt."""
    try:
        return _template(name).format(**kw)
    except KeyError as e:
        raise KeyError(f"prompt {name!r} needs placeholder {e}") from e


__all__ = ["preamble", "render"]
