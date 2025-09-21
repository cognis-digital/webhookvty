# Demo 01 - Basic webhook verification with a replay bug

This demo runs `webhookvty` over a small batch of recorded payment webhooks in
[`events.json`](./events.json). The batch deliberately mixes good and bad cases
so you can see real verification and bug detection.

## What's in the batch

| idx | provider | event_id | what it demonstrates |
|-----|----------|----------|----------------------|
| 0 | stripe | evt_100 | **Valid** Stripe signature (`t=...,v1=<hmac>`) |
| 1 | hmac    | evt_101 | **Valid** generic HMAC-SHA256 (`sha256=<hex>`) |
| 2 | stripe  | evt_100 | **Replay** - identical signature/body re-delivered |
| 3 | hmac    | evt_102 | **Invalid** signature (tampered body) |

All secrets and signatures in `events.json` are real HMAC-SHA256 values computed
over the exact raw payloads, so verification genuinely passes/fails.

## Run it

```bash
python -m webhookvty verify demos/01-basic/events.json
# or for CI / piping:
python -m webhookvty verify demos/01-basic/events.json --format json
```

## Expected result

- Event 0: valid
- Event 1: valid
- Event 2: signature is valid **but** flagged as a `duplicate_signature` replay
  (and `evt_100` is flagged as a `duplicate_event_id` replay)
- Event 3: invalid (`signature_mismatch`)

Because there are findings (one invalid signature + replays), the tool exits
**non-zero (1)** - so a CI job using it as a gate will fail. The summary line
prints `RESULT: FAIL`.
