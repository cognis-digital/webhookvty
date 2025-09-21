# WEBHOOKVTY — Architecture

> Verifies and replays signed payment webhooks (Stripe/Adyen/PayPal/Plaid) locally, catching signature, idempotency, and replay-attack bugs.

```
input ──▶ collect ──▶ rules/analyzers ──▶ score ──▶ findings ──▶ table · json
                              │                          │
                         (this repo)                 MCP tool (agents)
```

- **collect** normalizes the target (file/dir/API) into records.
- **rules/analyzers** apply the heuristics shipped in `webhookvty/core.py`.
- **score** ranks by severity.
- **MCP server** (`webhookvty mcp`) exposes `scan` for Cognis.Studio agents.

Extend by adding a rule + a test + a `demos/NN-*/SCENARIO.md`. See [CONTRIBUTING.md](../CONTRIBUTING.md).
