"""Core engine for webhookvty.

Real signature verification + replay/idempotency analysis. No third-party deps.

A webhook *event* is a JSON object with these fields:

    {
      "id": "evt_1",                 # optional logical event id (idempotency key)
      "provider": "stripe",          # stripe | adyen | hmac
      "secret": "whsec_...",         # signing secret (provider-specific)
      "payload": "{...raw body...}", # EXACT raw request body as a string
      "headers": {"Stripe-Signature": "t=...,v1=..."},  # provider headers
      "received_at": 1700000000      # optional unix ts the request arrived
    }

Provider details
----------------
stripe : header `Stripe-Signature` of form `t=<ts>,v1=<hexhmac>,...`. Signed
         string is `"{t}.{payload}"`, HMAC-SHA256 hex with the secret.
adyen  : HMAC-SHA256, base64, over the raw payload. Header `Adyen-Signature`
         or field `signature`. Secret is hex-encoded per Adyen's HMAC config.
hmac   : generic HMAC-SHA256 hex over the raw payload. Header `X-Webhook-Signature`
         (optionally `sha256=<hex>` prefix). Covers PayPal-style custom setups.
"""
from __future__ import annotations

import base64
import binascii
import hashlib
import hmac
import json
from dataclasses import dataclass, field, asdict
from typing import Any, Iterable

DEFAULT_TOLERANCE = 300  # seconds; Stripe's recommended replay window


@dataclass
class VerifyResult:
    """Outcome of verifying a single webhook event."""
    index: int
    event_id: str | None
    provider: str
    valid: bool
    reason: str = "ok"
    timestamp: int | None = None  # signed/received timestamp if known

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class BatchReport:
    """Aggregate result over a batch of events."""
    results: list[VerifyResult] = field(default_factory=list)
    replays: list[dict[str, Any]] = field(default_factory=list)
    idempotency_issues: list[dict[str, Any]] = field(default_factory=list)

    @property
    def total(self) -> int:
        return len(self.results)

    @property
    def invalid(self) -> list[VerifyResult]:
        return [r for r in self.results if not r.valid]

    @property
    def ok(self) -> bool:
        """True only if every signature is valid and no replay/idempotency bugs."""
        return (
            not self.invalid
            and not self.replays
            and not self.idempotency_issues
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "total": self.total,
            "valid": self.total - len(self.invalid),
            "invalid": len(self.invalid),
            "replays": self.replays,
            "idempotency_issues": self.idempotency_issues,
            "results": [r.to_dict() for r in self.results],
            "ok": self.ok,
        }


def _as_bytes(s: str | bytes) -> bytes:
    return s if isinstance(s, bytes) else s.encode("utf-8")


def _ci_get(headers: dict[str, str], name: str) -> str | None:
    """Case-insensitive header lookup."""
    if not headers:
        return None
    low = name.lower()
    for k, v in headers.items():
        if k.lower() == low:
            return v
    return None


def _parse_stripe_header(sig: str) -> tuple[int | None, list[str]]:
    """Parse `t=...,v1=...,v1=...` into (timestamp, [v1 sigs])."""
    ts: int | None = None
    v1: list[str] = []
    for part in sig.split(","):
        part = part.strip()
        if "=" not in part:
            continue
        key, _, val = part.partition("=")
        key = key.strip()
        val = val.strip()
        if key == "t":
            try:
                ts = int(val)
            except ValueError:
                ts = None
        elif key == "v1":
            v1.append(val)
    return ts, v1


def verify_stripe(
    payload: str | bytes,
    header: str,
    secret: str,
    *,
    tolerance: int = DEFAULT_TOLERANCE,
    now: int | None = None,
) -> tuple[bool, str, int | None]:
    """Verify a Stripe `Stripe-Signature` header.

    Returns (valid, reason, signed_timestamp).
    """
    if not header:
        return False, "missing_signature_header", None
    ts, sigs = _parse_stripe_header(header)
    if ts is None:
        return False, "missing_timestamp", None
    if not sigs:
        return False, "no_v1_signatures", ts
    signed = b"%d." % ts + _as_bytes(payload)
    expected = hmac.new(_as_bytes(secret), signed, hashlib.sha256).hexdigest()
    matched = any(hmac.compare_digest(expected, s) for s in sigs)
    if not matched:
        return False, "signature_mismatch", ts
    if now is not None and tolerance >= 0 and abs(now - ts) > tolerance:
        return False, "timestamp_outside_tolerance", ts
    return True, "ok", ts


def verify_adyen(
    payload: str | bytes,
    signature_b64: str,
    secret_hex: str,
) -> tuple[bool, str, int | None]:
    """Verify an Adyen-style base64 HMAC-SHA256 signature over the raw payload.

    The secret is hex-encoded (Adyen HMAC keys are hex strings).
    """
    if not signature_b64:
        return False, "missing_signature_header", None
    try:
        key = binascii.unhexlify(secret_hex)
    except (binascii.Error, ValueError):
        # Fall back to raw bytes if the secret is not valid hex.
        key = _as_bytes(secret_hex)
    digest = hmac.new(key, _as_bytes(payload), hashlib.sha256).digest()
    expected = base64.b64encode(digest).decode("ascii")
    if not hmac.compare_digest(expected, signature_b64.strip()):
        return False, "signature_mismatch", None
    return True, "ok", None


def verify_hmac(
    payload: str | bytes,
    signature: str,
    secret: str,
) -> tuple[bool, str, int | None]:
    """Verify a generic hex HMAC-SHA256 signature, with optional `sha256=` prefix."""
    if not signature:
        return False, "missing_signature_header", None
    sig = signature.strip()
    if sig.lower().startswith("sha256="):
        sig = sig[len("sha256="):]
    expected = hmac.new(_as_bytes(secret), _as_bytes(payload), hashlib.sha256).hexdigest()
    if not hmac.compare_digest(expected, sig):
        return False, "signature_mismatch", None
    return True, "ok", None


def _extract_signature(provider: str, headers: dict[str, str]) -> str | None:
    if provider == "stripe":
        return _ci_get(headers, "Stripe-Signature")
    if provider == "adyen":
        return _ci_get(headers, "Adyen-Signature") or _ci_get(headers, "signature")
    # generic / paypal-style
    return (
        _ci_get(headers, "X-Webhook-Signature")
        or _ci_get(headers, "Signature")
        or _ci_get(headers, "X-Hub-Signature-256")
    )


def verify_event(
    event: dict[str, Any],
    index: int = 0,
    *,
    tolerance: int = DEFAULT_TOLERANCE,
    now: int | None = None,
) -> VerifyResult:
    """Verify a single event dict (see module docstring for shape)."""
    provider = str(event.get("provider", "hmac")).lower()
    event_id = event.get("id")
    secret = event.get("secret", "")
    payload = event.get("payload", "")
    if isinstance(payload, (dict, list)):
        # Allow callers to inline a JSON body; serialize deterministically.
        payload = json.dumps(payload, separators=(",", ":"))
    headers = event.get("headers", {}) or {}
    sig = event.get("signature") or _extract_signature(provider, headers)

    if not secret:
        return VerifyResult(index, event_id, provider, False, "missing_secret")

    if provider == "stripe":
        # Use received_at as 'now' if no explicit now was supplied, so a
        # recorded fixture verifies against its own arrival time.
        eff_now = now if now is not None else event.get("received_at")
        valid, reason, ts = verify_stripe(
            payload, sig or "", secret, tolerance=tolerance,
            now=eff_now if isinstance(eff_now, int) else None,
        )
    elif provider == "adyen":
        valid, reason, ts = verify_adyen(payload, sig or "", secret)
        if ts is None:
            ts = event.get("received_at")
    else:
        valid, reason, ts = verify_hmac(payload, sig or "", secret)
        if ts is None:
            ts = event.get("received_at")

    return VerifyResult(index, event_id, provider, valid, reason, ts)


def _body_fingerprint(event: dict[str, Any]) -> str:
    payload = event.get("payload", "")
    if isinstance(payload, (dict, list)):
        payload = json.dumps(payload, separators=(",", ":"), sort_keys=True)
    return hashlib.sha256(_as_bytes(payload)).hexdigest()


def analyze_batch(
    events: Iterable[dict[str, Any]],
    *,
    tolerance: int = DEFAULT_TOLERANCE,
    now: int | None = None,
) -> BatchReport:
    """Verify every event and detect replay / idempotency bugs across the batch.

    Replay: the same signed payload+signature seen more than once, OR the same
            event id delivered more than once. Either lets an attacker (or a
            buggy retry path) double-process a payment.
    Idempotency issue: the same logical event id arrives with DIFFERENT body
            fingerprints (the receiver could process conflicting versions).
    """
    report = BatchReport()
    seen_sig: dict[tuple[str, str], int] = {}
    id_fingerprints: dict[str, set[str]] = {}
    id_first_index: dict[str, int] = {}
    id_count: dict[str, int] = {}

    events = list(events)
    for i, ev in enumerate(events):
        res = verify_event(ev, i, tolerance=tolerance, now=now)
        report.results.append(res)

        provider = res.provider
        sig = ev.get("signature") or _extract_signature(
            provider, ev.get("headers", {}) or {}
        )
        fp = _body_fingerprint(ev)

        # Replay by identical signature material.
        if sig:
            key = (provider, sig)
            if key in seen_sig:
                report.replays.append({
                    "type": "duplicate_signature",
                    "index": i,
                    "first_index": seen_sig[key],
                    "event_id": res.event_id,
                    "provider": provider,
                })
            else:
                seen_sig[key] = i

        # Track by logical event id.
        eid = res.event_id
        if eid is not None:
            id_count[eid] = id_count.get(eid, 0) + 1
            id_first_index.setdefault(eid, i)
            id_fingerprints.setdefault(eid, set()).add(fp)

    # Replay by duplicated event id (a retry without idempotent handling).
    for eid, count in id_count.items():
        if count > 1:
            fps = id_fingerprints.get(eid, set())
            if len(fps) > 1:
                report.idempotency_issues.append({
                    "type": "conflicting_payloads_same_id",
                    "event_id": eid,
                    "first_index": id_first_index[eid],
                    "deliveries": count,
                    "distinct_bodies": len(fps),
                })
            else:
                report.replays.append({
                    "type": "duplicate_event_id",
                    "event_id": eid,
                    "first_index": id_first_index[eid],
                    "deliveries": count,
                })

    return report


def load_events(data: str | bytes) -> list[dict[str, Any]]:
    """Load events from JSON text: either a list or {\"events\": [...]}"""
    obj = json.loads(data)
    if isinstance(obj, dict) and "events" in obj:
        obj = obj["events"]
    if isinstance(obj, dict):
        obj = [obj]
    if not isinstance(obj, list):
        raise ValueError("expected a JSON list of events or {events:[...]}")
    return obj
