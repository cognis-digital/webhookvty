"""WEBHOOKVTY MCP server — exposes scan() as an MCP tool for Cognis.Studio."""
from __future__ import annotations
from webhookvty.core import scan, to_json

def serve() -> int:
    """Start an MCP stdio server. Requires the optional 'mcp' extra:
        pip install "cognis-webhookvty[mcp]"
    """
    try:
        from mcp.server.fastmcp import FastMCP
    except Exception:
        print("Install the MCP extra: pip install 'cognis-webhookvty[mcp]'")
        return 1
    app = FastMCP("webhookvty")

    @app.tool()
    def webhookvty_scan(target: str) -> str:
        """Verifies and replays signed payment webhooks (Stripe/Adyen/PayPal/Plaid) locally, catching signature, idempotency, and replay-attack bugs.. Returns JSON findings."""
        return to_json(scan(target))

    app.run()
    return 0
