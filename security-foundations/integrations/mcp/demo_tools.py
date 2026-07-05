"""Demo tool handlers for the example MCP host (Phase 4).

These are placeholder stand-ins so the example host has something to
dispatch. Operators replace ``DEMO_TOOLS`` with their real MCP tool
handlers. Keeping them out of ``host.py`` keeps the host module
focused on the substrate pipeline (and under its 500-line ceiling).

Each handler is a pure function ``dict -> dict`` with no I/O.
"""

from __future__ import annotations

from collections.abc import Callable
from typing import Any


def tool_read_file(params: dict[str, Any]) -> dict[str, Any]:
    path = params.get("path", "") if isinstance(params, dict) else ""
    return {
        "path": path,
        "contents": f"demo body for {path or '<no path>'}",
    }


def tool_exec_sql(params: dict[str, Any]) -> dict[str, Any]:
    query = params.get("query", "") if isinstance(params, dict) else ""
    return {
        "query": query,
        "rows": [{"id": 1, "name": "alice"}, {"id": 2, "name": "bob"}],
    }


DEMO_TOOLS: dict[str, Callable[[dict[str, Any]], dict[str, Any]]] = {
    "read_file": tool_read_file,
    "exec_sql": tool_exec_sql,
}


__all__ = ["DEMO_TOOLS", "tool_exec_sql", "tool_read_file"]
