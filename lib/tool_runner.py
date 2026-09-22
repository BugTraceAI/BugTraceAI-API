"""Base ToolRunner abstraction for investigation steps.

All investigation tool wrappers must provide a `.run(...)` coroutine and
a `.name` attribute.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any


@dataclass
class ToolRunner:
    """Wraps a real tool runner to provide a uniform interface."""

    name: str
    max_time: float = 180.0

    async def run(self, **kwargs: Any) -> Any:
        raise NotImplementedError
