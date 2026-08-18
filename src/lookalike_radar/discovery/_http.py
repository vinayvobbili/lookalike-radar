"""A tiny HTTP seam so discovery sources are testable without a network.

Every network-backed source takes a ``Fetcher``. The default uses ``requests``
(imported lazily, so installing the core package without the ``[http]`` extra
still imports fine — you only hit the missing dependency if you actually make a
call). Tests inject a stub fetcher and never touch the network.
"""

from __future__ import annotations

from typing import Any, Dict, Optional, Protocol, runtime_checkable

DEFAULT_UA = "lookalike-radar (+https://github.com/vinayvobbili/lookalike-radar)"


@runtime_checkable
class Fetcher(Protocol):
    def get_json(self, url: str, *, params: Optional[Dict[str, Any]] = None,
                 headers: Optional[Dict[str, str]] = None) -> Any: ...

    def get_text(self, url: str, *, params: Optional[Dict[str, Any]] = None,
                 headers: Optional[Dict[str, str]] = None) -> str: ...


class RequestsFetcher:
    """Default ``Fetcher`` backed by ``requests`` (lazy import)."""

    def __init__(self, timeout: int = 15, user_agent: str = DEFAULT_UA):
        self.timeout = timeout
        self.user_agent = user_agent
        self._session = None

    def _sess(self):
        if self._session is None:
            try:
                import requests  # noqa: PLC0415 - lazy so core stays dependency-free
            except ImportError as exc:  # pragma: no cover
                raise ImportError(
                    "network discovery needs the 'http' extra: "
                    "pip install 'lookalike-radar[http]'"
                ) from exc
            self._session = requests.Session()
            self._session.headers.update({"User-Agent": self.user_agent})
        return self._session

    def get_json(self, url, *, params=None, headers=None):
        r = self._sess().get(url, params=params, headers=headers, timeout=self.timeout)
        r.raise_for_status()
        return r.json()

    def get_text(self, url, *, params=None, headers=None):
        r = self._sess().get(url, params=params, headers=headers, timeout=self.timeout)
        r.raise_for_status()
        return r.text


def default_fetcher() -> Fetcher:
    return RequestsFetcher()
