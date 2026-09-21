"""GLM backend -- the verifier half of the two-model design.

Claude Code hunts; GLM-5.3 re-reads what the hunt claims. The point is not redundancy but
*decorrelation*: different weights, different training data, different blind spots. A model
grading its own transcript will confirm its own hallucination, so the validator deliberately
runs on another vendor, over the plain OpenAI-compatible HTTP route rather than a CLI.

Different transport, same trap. The CLI can hand back a backend outage as prose inside a
successful run; this endpoint can hand back HTTP 200 with an error object in the body, or a
200 with an empty `content`. Both look like "the validator reviewed it and had no objection".
So every response -- transport failure, HTTP error, and success alike -- goes through the same
classify() gate that the CLI backend uses, and the decision of what may be believed lives in
exactly one place.
"""

from __future__ import annotations

import asyncio
import json
import random
import time
from datetime import UTC, datetime
from email.utils import parsedate_to_datetime
from pathlib import Path
from typing import Any

import httpx

from vulness.agents.base import Agent, AgentResult
from vulness.agents.classify import classify
from vulness.config import VerifyBackend

_COMPLETIONS_PATH = "chat/completions"
_CONNECT_TIMEOUT_S = 15.0
_HEALTH_TIMEOUT_S = 30.0
_BASE_BACKOFF_S = 1.0
_MAX_BACKOFF_S = 60.0
_ERROR_EXCERPT = 400


def _as_int(value: Any) -> int:
    try:
        return max(0, int(value))
    except (TypeError, ValueError):
        return 0


def _retryable_status(status: int) -> bool:
    """429 and 5xx are weather. Every other 4xx is a defect in the request -- a revoked key or
    a wrong model name fails identically on attempt four, so retrying only burns wall clock."""
    return status == 429 or 500 <= status < 600


def _retry_after_seconds(response: httpx.Response | None) -> float | None:
    """Honour the server's own pacing. Guessing shorter than Retry-After extends the ban."""
    if response is None:
        return None
    raw = response.headers.get("retry-after", "").strip()
    if not raw:
        return None
    try:
        return max(0.0, float(raw))
    except ValueError:
        pass
    try:
        when = parsedate_to_datetime(raw)
    except (TypeError, ValueError):
        return None
    if when.tzinfo is None:
        when = when.replace(tzinfo=UTC)
    return max(0.0, (when - datetime.now(UTC)).total_seconds())


def _backoff_delay(attempt: int, response: httpx.Response | None) -> float:
    """Exponential backoff, jittered. Ten validators throttled by the same 429 must not come
    back in lockstep and re-trigger it; the jitter spreads the fleet's retry front."""
    server_hint = _retry_after_seconds(response)
    if server_hint is not None:
        return min(server_hint, _MAX_BACKOFF_S)
    ceiling = min(_BASE_BACKOFF_S * (2**attempt), _MAX_BACKOFF_S)
    return random.uniform(ceiling * 0.5, ceiling)


def _error_object(data: dict[str, Any]) -> dict[str, Any] | None:
    """Find an error payload inside a 2xx body.

    This is the whole reason the module exists in this shape. z.ai returns HTTP 200 for quota
    exhaustion and upstream overload, with the failure described in the body: OpenAI-shaped
    under "error", or the Zhipu envelope's non-zero top-level "code" with no choices.
    """
    err = data.get("error")
    if isinstance(err, dict) and err:
        return err
    if isinstance(err, str) and err.strip():
        return {"message": err.strip()}
    code = data.get("code")
    if code not in (None, 0, "0", 200, "200") and not data.get("choices"):
        message = data.get("message") or data.get("msg") or ""
        return {"code": code, "message": str(message)}
    return None


def _first_choice(data: dict[str, Any]) -> dict[str, Any]:
    choices = data.get("choices")
    if not isinstance(choices, list) or not choices:
        return {}
    return choices[0] if isinstance(choices[0], dict) else {}


def _choice_content(choice: dict[str, Any]) -> str:
    message = choice.get("message")
    if not isinstance(message, dict):
        # Defensive: some gateways emit a delta-shaped choice even on the non-streaming route.
        message = choice.get("delta") if isinstance(choice.get("delta"), dict) else None
    if not isinstance(message, dict):
        return ""
    content = message.get("content")
    if isinstance(content, str):
        return content
    if isinstance(content, list):
        # Anthropic-shaped content blocks leaking through the OpenAI-compatible route.
        return "\n".join(
            block["text"]
            for block in content
            if isinstance(block, dict) and isinstance(block.get("text"), str)
        )
    return ""


def _terminal_subtype(choice: dict[str, Any]) -> str:
    """Map finish_reason onto the subtype vocabulary classify() understands.

    Anything but a clean stop means the answer is partial -- "length" most often, GLM having
    spent the budget in reasoning_content. A truncated verdict is not a verdict, and classify()
    flags every subtype outside the success set, so the mapping has to be exact.
    """
    reason = choice.get("finish_reason") or choice.get("finishReason")
    if not isinstance(reason, str) or not reason or reason == "stop":
        return "success"
    return reason


def _loads_object(content: str) -> dict[str, Any] | None:
    try:
        parsed = json.loads(content)
    except (json.JSONDecodeError, TypeError):
        return None
    if isinstance(parsed, dict):
        return parsed
    if isinstance(parsed, list):
        return {"items": parsed}
    return None


def _schema_directive(schema: dict[str, Any]) -> str:
    rendered = json.dumps(schema, indent=2, ensure_ascii=False)
    return (
        "Reply with a single JSON object and nothing else -- no prose, no code fence. "
        f"It must match this schema:\n{rendered}"
    )


class GLMAgent(Agent):
    """GLM over an OpenAI-compatible endpoint, with one pooled client for the whole fleet."""

    name = "glm"

    def __init__(self, cfg: VerifyBackend | None = None) -> None:
        self.cfg = cfg or VerifyBackend()
        self.model = self.cfg.model
        self._http: httpx.AsyncClient | None = None
        self._lock = asyncio.Lock()

    async def _client(self) -> httpx.AsyncClient:
        """One client, reused. Validators run at fleet concurrency; a per-call client would
        redo TLS every time and leak sockets when a run is cancelled mid-flight."""
        async with self._lock:
            if self._http is None or self._http.is_closed:
                self._http = httpx.AsyncClient(
                    base_url=self.cfg.base_url.rstrip("/"),
                    timeout=httpx.Timeout(float(self.cfg.timeout_s), connect=_CONNECT_TIMEOUT_S),
                    headers={"Accept": "application/json"},
                )
            return self._http

    async def aclose(self) -> None:
        async with self._lock:
            if self._http is not None and not self._http.is_closed:
                await self._http.aclose()
            self._http = None

    def _body(
        self,
        prompt: str,
        *,
        system: str | None,
        schema: dict[str, Any] | None,
    ) -> dict[str, Any]:
        directives = [
            part for part in (system, _schema_directive(schema) if schema else None) if part
        ]
        messages: list[dict[str, str]] = []
        if directives:
            messages.append({"role": "system", "content": "\n\n".join(directives)})
        messages.append({"role": "user", "content": prompt})
        body: dict[str, Any] = {
            "model": self.cfg.model,
            "messages": messages,
            "temperature": self.cfg.temperature,
            "max_tokens": self.cfg.max_tokens,
        }
        if schema is not None:
            # Belt and braces: response_format constrains the decoder, the restated schema in
            # the system message constrains the *shape*. json_object alone guarantees valid
            # JSON, not the fields the caller asked for.
            body["response_format"] = {"type": "json_object"}
        return body

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
        # cwd and allowed_tools are part of the shared Agent contract but have no meaning here:
        # the validator gets no filesystem and no tools, only the evidence the hunter packed
        # into the prompt. That asymmetry is the point -- it cannot re-derive the hunter's view.
        del cwd, allowed_tools
        started = time.monotonic()
        key = self.cfg.api_key()
        if not key:
            # A missing key is a deployment fact, not a model failure. Returning it as a result
            # keeps the hunt running unverified instead of tearing down the whole sweep.
            return AgentResult(
                classification="crash",
                model=self.cfg.model,
                duration_s=time.monotonic() - started,
                error=(
                    f"{self.cfg.api_key_env} not set -- export {self.cfg.api_key_env}=<key> "
                    "(or ZHIPU_API_KEY / ZAI_API_KEY) to enable the GLM validator; findings "
                    "stay unverified until it is."
                ),
            )

        body = self._body(prompt, system=system, schema=schema)
        timeout = httpx.Timeout(
            float(timeout_s if timeout_s is not None else self.cfg.timeout_s),
            connect=_CONNECT_TIMEOUT_S,
        )
        headers = {"Authorization": f"Bearer {key}"}
        client = await self._client()

        attempts = max(1, self.cfg.max_retries)
        response: httpx.Response | None = None
        failure: str | None = None
        used = 0
        for attempt in range(attempts):
            used = attempt + 1
            try:
                response = await client.post(
                    _COMPLETIONS_PATH, json=body, headers=headers, timeout=timeout
                )
            except httpx.HTTPError as exc:
                # Covers connect/read timeouts, resets and protocol errors alike; all transient.
                response, failure = None, f"{type(exc).__name__}: {exc}"
            else:
                if response.status_code < 400:
                    failure = None
                    break
                failure = f"HTTP {response.status_code}: {response.text[:_ERROR_EXCERPT]}"
                if not _retryable_status(response.status_code):
                    break
            if attempt + 1 < attempts:
                await asyncio.sleep(_backoff_delay(attempt, response))

        duration = time.monotonic() - started
        if response is None or response.status_code >= 400:
            return self._failed(response, failure, duration, used, schema)
        return self._succeeded(response, duration, used, schema)

    def _failed(
        self,
        response: httpx.Response | None,
        failure: str | None,
        duration: float,
        attempts: int,
        schema: dict[str, Any] | None,
    ) -> AgentResult:
        status = response.status_code if response is not None else None
        text = failure or "no response from GLM endpoint"
        if status is not None and not _retryable_status(status):
            # Permanent: bad key, bad model, malformed request. Classifying this as a transient
            # API error would put it back in the queue to fail identically, forever.
            return AgentResult(
                classification="crash",
                text=text,
                duration_s=duration,
                model=self.cfg.model,
                error=f"GLM request rejected: {text}",
                raw_events=[{"type": "result", "is_error": True, "status_code": status}],
            )
        terminal: dict[str, Any] = {
            "type": "result",
            "subtype": "http_error" if status is not None else "transport_error",
            "is_error": True,
            "status_code": status,
            "attempts": attempts,
        }
        classification, reason = classify(
            text=text,
            timed_out=False,
            terminal_event=terminal,
            expects_json=schema is not None,
            payload=None,
        )
        return AgentResult(
            classification=classification,
            text=text,
            duration_s=duration,
            model=self.cfg.model,
            error=reason or text,
            raw_events=[terminal],
        )

    def _succeeded(
        self,
        response: httpx.Response,
        duration: float,
        attempts: int,
        schema: dict[str, Any] | None,
    ) -> AgentResult:
        try:
            data = response.json()
        except ValueError:
            data = None
        if not isinstance(data, dict):
            data = {}
            api_error: dict[str, Any] | None = {"message": "non-JSON body on a 2xx response"}
        else:
            api_error = _error_object(data)

        choice = _first_choice(data)
        content = _choice_content(choice)
        # HTTP 200 with the failure in the body. Without this branch an outage is recorded as a
        # validator that read the finding and raised no objection -- a false clean bill.
        text = str(api_error.get("message") or api_error) if api_error else content

        terminal: dict[str, Any] = {
            "type": "result",
            "subtype": "api_error" if api_error else _terminal_subtype(choice),
            "is_error": api_error is not None,
            "status_code": response.status_code,
            "attempts": attempts,
        }
        if api_error is not None:
            terminal["error"] = api_error

        result = AgentResult(
            text=text,
            duration_s=duration,
            model=str(data.get("model") or self.cfg.model),
            raw_events=[terminal, {"type": "response", "body": data}],
        )
        usage = data.get("usage")
        if isinstance(usage, dict):
            result.tokens_in = _as_int(usage.get("prompt_tokens"))
            result.tokens_out = _as_int(usage.get("completion_tokens"))
        # Left at zero on purpose: GLM pricing is not modelled here, and a made-up number in a
        # budget ledger is worse than an honest zero. Token counts above carry the real usage.
        result.cost_usd = 0.0

        payload: dict[str, Any] | None = None
        if schema is not None and not api_error:
            # response_format usually yields a bare object, but GLM still fences it when the
            # prompt showed a fence; extract_json() is the fallback for that case.
            payload = _loads_object(content) or result.extract_json()

        classification, reason = classify(
            text=text,
            timed_out=False,
            terminal_event=terminal,
            expects_json=schema is not None,
            payload=payload,
        )
        result.classification = classification
        result.payload = payload
        result.error = reason
        return result

    async def health(self) -> tuple[bool, str]:
        key = self.cfg.api_key()
        if not key:
            return False, f"{self.cfg.api_key_env} not set"
        body = {
            "model": self.cfg.model,
            "messages": [{"role": "user", "content": "ping"}],
            "max_tokens": 1,
            "temperature": 0.0,
        }
        try:
            client = await self._client()
            response = await client.post(
                _COMPLETIONS_PATH,
                json=body,
                headers={"Authorization": f"Bearer {key}"},
                timeout=httpx.Timeout(_HEALTH_TIMEOUT_S, connect=_CONNECT_TIMEOUT_S),
            )
        except httpx.HTTPError as exc:
            return False, f"{type(exc).__name__}: {exc}"
        if response.status_code >= 400:
            return False, f"HTTP {response.status_code}: {response.text[:_ERROR_EXCERPT]}"
        try:
            data = response.json()
        except ValueError:
            return False, "non-JSON body on a 2xx response"
        if not isinstance(data, dict):
            return False, "unexpected response shape"
        # The 200-with-error trap applies to the ping too: a reachable endpoint that is out of
        # quota answers 200 and would otherwise register as healthy.
        if err := _error_object(data):
            return False, str(err.get("message") or err)
        return True, f"{self.cfg.model} @ {self.cfg.base_url}"
