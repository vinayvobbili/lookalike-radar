"""Pluggable notification sinks.

Where findings *go* is the caller's concern, not the engine's — one team wants
Webex adaptive cards, another wants Slack, a third wants a webhook or just a log
line. So delivery is a Protocol: implement :meth:`Sink.emit` and hand your sink
to a scan. The engine ships two reference sinks with zero external dependencies
(console, JSONL); the richer ones stay in your application.
"""

from __future__ import annotations

import json
import sys
from typing import Iterable, List, Protocol, TextIO, Union, runtime_checkable

from .findings import Finding


@runtime_checkable
class Sink(Protocol):
    """Receives findings for delivery/notification."""

    def emit(self, findings: Union[Finding, Iterable[Finding]]) -> None:
        ...


def _as_list(findings: Union[Finding, Iterable[Finding]]) -> List[Finding]:
    if isinstance(findings, Finding):
        return [findings]
    return list(findings)


class ConsoleSink:
    """A human-readable reference sink — one line per finding, tier-first."""

    def __init__(self, stream: TextIO = sys.stdout):
        self.stream = stream

    def emit(self, findings: Union[Finding, Iterable[Finding]]) -> None:
        for f in _as_list(findings):
            tier = f.tier.value if f.tier else "--"
            brand = f"[{f.brand}] " if f.brand else ""
            self.stream.write(f"{tier}  {brand}{f.domain}  ({f.source})\n")
        self.stream.flush()


class JsonlSink:
    """Appends each finding as a JSON line — a durable, greppable audit trail."""

    def __init__(self, path: str):
        self.path = path

    def emit(self, findings: Union[Finding, Iterable[Finding]]) -> None:
        with open(self.path, "a", encoding="utf-8") as fh:
            for f in _as_list(findings):
                fh.write(json.dumps(f.to_dict()) + "\n")


class MultiSink:
    """Fan a finding out to several sinks; one sink failing doesn't stop the rest."""

    def __init__(self, *sinks: Sink):
        self.sinks: List[Sink] = list(sinks)

    def emit(self, findings: Union[Finding, Iterable[Finding]]) -> None:
        items = _as_list(findings)
        for sink in self.sinks:
            try:
                sink.emit(items)
            except Exception:  # noqa: BLE001 - one broken sink must not drop the others
                continue
