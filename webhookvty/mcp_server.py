"""WEBHOOKVTY MCP server — exposes verify as an MCP tool for Cognis.Studio."""
from __future__ import annotations
import json


def serve() -> int:
    """Start an MCP stdio server. Requires the optional 'mcp' extra:
        pip install "cognis-webhookvty[mcp]"
    """
    try:
        from mcp.server.fastmcp import FastMCP
    except Exception:
        print("Install the MCP extra: pip install 'cognis-webhookvty[mcp]'")
        return 1

    from webhookvty.core import load_events, analyze_batch

    app = FastMCP("webhookvty")

    @app.tool()
    def webhookvty_verify(events_json: str) -> str:
        """Verify signed webhooks and detect replay/idempotency bugs.

        Accepts a JSON list of event objects. Returns JSON findings.
        """
        try:
            events = load_events(events_json)
        except (ValueError, json.JSONDecodeError) as exc:
            return json.dumps({"error": str(exc)})
        report = analyze_batch(events)
        return json.dumps(report.to_dict())

    app.run()
    return 0
