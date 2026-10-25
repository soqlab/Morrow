"""The single HTTP boundary for every model provider.

One function opens a socket in this package: `_open`. Every adapter goes
through `post_json` or `post_lines`, which means the test suite mocks exactly
one seam and no test can reach a network by accident.

Standard library only. No proxy is inherited (an ambient HTTPS_PROXY must not
receive a model credential) and no redirect is followed (a 302 would move the
request off the destination the tenant approved).
"""

from __future__ import annotations

import json
import socket
import time
import urllib.error
import urllib.request
from typing import Any, Dict, Iterator, List, Optional, Tuple

from services.llm.base import (
    AUTH, BAD_REQUEST, CONNECTION, LLMError, NOT_FOUND, RATE_LIMIT, SERVER, TIMEOUT,
)

#: A model response larger than this is refused rather than buffered.
MAX_RESPONSE_BYTES = 8_000_000
#: A stream longer than this many lines is refused.
MAX_STREAM_LINES = 200_000


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args: Any, **kwargs: Any):  # noqa: D102
        raise LLMError(BAD_REQUEST, "The provider redirected the request.",
                       remedy="Point the base URL straight at the API endpoint; redirects are not followed.")


def _opener() -> urllib.request.OpenerDirector:
    # ProxyHandler({}) disables proxy discovery for this opener only.
    return urllib.request.build_opener(urllib.request.ProxyHandler({}), _NoRedirect())


def _open(url: str, body: bytes, headers: Dict[str, str], timeout: float, method: str = "POST"):
    """The only socket in this package. Tests replace this.

    Returns the open response object; callers must read and close it.
    """
    request = urllib.request.Request(url, data=body, headers=dict(headers), method=method)
    return _opener().open(request, timeout=timeout)  # noqa: S310 - operator-configured endpoint


def classify(status: int, provider: str, detail: str = "") -> LLMError:
    """Map an HTTP status onto a typed error with an operator remedy.

    The body is deliberately not echoed: a provider error body can contain the
    request it is complaining about.
    """
    if status in (401, 403):
        return LLMError(AUTH, f"{provider or 'The provider'} rejected the credential (HTTP {status}).",
                        provider=provider, status=status,
                        remedy="Check the API key for this provider, and that the account is active.")
    if status == 404:
        return LLMError(NOT_FOUND, f"{provider or 'The provider'} does not expose this model or path (HTTP 404).",
                        provider=provider, status=status,
                        remedy="Check the model name and the base URL path.")
    if status == 429:
        return LLMError(RATE_LIMIT, f"{provider or 'The provider'} rate limited the request.",
                        provider=provider, status=status, remedy="Retry shortly, or raise the account's limit.")
    if status in (408, 504):
        return LLMError(TIMEOUT, f"{provider or 'The provider'} timed out (HTTP {status}).",
                        provider=provider, status=status, remedy="Raise MORROW_LLM_TIMEOUT or shorten the question.")
    if 400 <= status < 500:
        return LLMError(BAD_REQUEST, f"{provider or 'The provider'} refused the request (HTTP {status}).",
                        provider=provider, status=status,
                        remedy="The request shape is wrong for this provider; check the adapter's settings.")
    return LLMError(SERVER, f"{provider or 'The provider'} returned HTTP {status}.",
                    provider=provider, status=status, remedy="Check the provider's status page, then retry.")


def _backoff(attempt: int) -> float:
    # 0.5s, 1s, 2s, capped. Deterministic, so a test can assert the schedule.
    return min(8.0, 0.5 * (2 ** attempt))


_sleep = time.sleep  # a seam, so retry tests do not actually wait


def _attempt(url: str, body: bytes, headers: Dict[str, str], timeout: float,
             provider: str) -> Tuple[int, Any]:
    try:
        return 200, _open(url, body, headers, timeout)
    except urllib.error.HTTPError as exc:
        status = int(getattr(exc, "code", 0) or 0)
        try:
            exc.read(65536)
        except Exception:
            pass
        raise classify(status, provider) from None
    except LLMError:
        raise
    except socket.timeout:
        raise LLMError(TIMEOUT, f"{provider or 'The provider'} did not answer within {int(timeout)}s.",
                       provider=provider, remedy="Raise MORROW_LLM_TIMEOUT, or use a smaller model.") from None
    except urllib.error.URLError as exc:
        reason = exc.reason
        if isinstance(reason, socket.timeout) or "timed out" in str(reason).lower():
            raise LLMError(TIMEOUT, f"{provider or 'The provider'} did not answer within {int(timeout)}s.",
                           provider=provider, remedy="Raise MORROW_LLM_TIMEOUT, or use a smaller model.") from None
        raise LLMError(CONNECTION, f"Could not reach {provider or 'the provider'}.", provider=provider,
                       remedy="Check the base URL, DNS and outbound network from this host.") from None
    except Exception:
        raise LLMError(CONNECTION, f"Could not reach {provider or 'the provider'}.", provider=provider,
                       remedy="Check the base URL, DNS and outbound network from this host.") from None


def _with_retries(call, retries: int):
    last: Optional[LLMError] = None
    for attempt in range(max(0, int(retries)) + 1):
        try:
            return call()
        except LLMError as exc:
            last = exc
            if not exc.retryable or attempt >= max(0, int(retries)):
                raise
            _sleep(_backoff(attempt))
    raise last if last else LLMError(SERVER, "The provider call did not run.")


def post_json(url: str, payload: Dict[str, Any], *, headers: Optional[Dict[str, str]] = None,
              timeout: float = 60, retries: int = 2, provider: str = "") -> Dict[str, Any]:
    """POST JSON, return parsed JSON. Retries rate limits, timeouts and 5xx."""
    body = json.dumps(payload, separators=(",", ":"), default=str).encode("utf-8")
    sent = {"Content-Type": "application/json", "Accept": "application/json", **(headers or {})}

    def once() -> Dict[str, Any]:
        response = _attempt(url, body, sent, timeout, provider)[1]
        try:
            raw = response.read(MAX_RESPONSE_BYTES + 1)
        finally:
            try:
                response.close()
            except Exception:
                pass
        if len(raw) > MAX_RESPONSE_BYTES:
            raise LLMError(BAD_REQUEST, "The provider response exceeds the response-size limit.",
                           provider=provider, remedy="Lower the maximum output tokens.")
        try:
            parsed = json.loads(raw.decode("utf-8", errors="replace") or "{}")
        except ValueError:
            raise LLMError(BAD_REQUEST, f"{provider or 'The provider'} did not return JSON.",
                           provider=provider,
                           remedy="Check that the base URL points at the chat-completions API, not a web page.") from None
        if not isinstance(parsed, dict):
            raise LLMError(BAD_REQUEST, f"{provider or 'The provider'} returned an unexpected JSON shape.",
                           provider=provider, remedy="Check the base URL and API version.")
        return parsed

    return _with_retries(once, retries)


def post_lines(url: str, payload: Dict[str, Any], *, headers: Optional[Dict[str, str]] = None,
               timeout: float = 60, retries: int = 2, provider: str = "") -> List[str]:
    """POST JSON and return the response's decoded lines.

    Used for the providers' streaming wire protocols. The lines are collected
    rather than yielded, because the tenant's data boundary scans a complete
    response for credential patterns before any of it is released; see
    docs/AI_PROVIDERS.md.
    """
    body = json.dumps(payload, separators=(",", ":"), default=str).encode("utf-8")
    sent = {"Content-Type": "application/json", "Accept": "text/event-stream", **(headers or {})}

    def once() -> List[str]:
        response = _attempt(url, body, sent, timeout, provider)[1]
        lines: List[str] = []
        total = 0
        try:
            for raw in response:
                total += len(raw)
                if total > MAX_RESPONSE_BYTES or len(lines) > MAX_STREAM_LINES:
                    raise LLMError(BAD_REQUEST, "The provider stream exceeds the response-size limit.",
                                   provider=provider, remedy="Lower the maximum output tokens.")
                lines.append(raw.decode("utf-8", errors="replace").rstrip("\r\n"))
        finally:
            try:
                response.close()
            except Exception:
                pass
        return lines

    return _with_retries(once, retries)


def sse_data(lines: List[str]) -> Iterator[Dict[str, Any]]:
    """Yield the JSON objects carried by `data:` lines of an SSE stream."""
    for line in lines:
        if not line.startswith("data:"):
            continue
        payload = line[5:].strip()
        if not payload or payload == "[DONE]":
            continue
        try:
            parsed = json.loads(payload)
        except ValueError:
            continue
        if isinstance(parsed, dict):
            yield parsed


def json_lines(lines: List[str]) -> Iterator[Dict[str, Any]]:
    """Yield objects from a newline-delimited JSON stream (Ollama's shape)."""
    for line in lines:
        text = line.strip()
        if not text:
            continue
        try:
            parsed = json.loads(text)
        except ValueError:
            continue
        if isinstance(parsed, dict):
            yield parsed
