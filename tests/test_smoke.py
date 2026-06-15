"""Smoke tests for webhookvty. No network. Recomputes real HMACs."""
import hashlib
import hmac
import json
import os
import subprocess
import sys

import pytest

from webhookvty import (
    TOOL_NAME,
    TOOL_VERSION,
    analyze_batch,
    verify_stripe,
    verify_hmac,
    verify_adyen,
    verify_event,
)
from webhookvty.core import load_events

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DEMO = os.path.join(ROOT, "demos", "01-basic", "events.json")


def _stripe_header(payload: str, secret: str, ts: int) -> str:
    signed = f"{ts}.{payload}".encode()
    mac = hmac.new(secret.encode(), signed, hashlib.sha256).hexdigest()
    return f"t={ts},v1={mac}"


def _hmac_hex(payload: str, secret: str) -> str:
    return hmac.new(secret.encode(), payload.encode(), hashlib.sha256).hexdigest()


def test_version_metadata():
    assert TOOL_NAME == "webhookvty"
    assert TOOL_VERSION.count(".") == 2


def test_verify_stripe_roundtrip():
    payload = '{"id":"evt_1","amount":100}'
    secret = "whsec_abc"
    header = _stripe_header(payload, secret, 1700000000)
    valid, reason, ts = verify_stripe(payload, header, secret, now=1700000010)
    assert valid and reason == "ok" and ts == 1700000000


def test_verify_stripe_tampered_payload_fails():
    secret = "whsec_abc"
    header = _stripe_header('{"amount":100}', secret, 1700000000)
    valid, reason, _ = verify_stripe('{"amount":999}', header, secret, now=1700000000)
    assert not valid and reason == "signature_mismatch"


def test_verify_stripe_outside_tolerance():
    secret = "whsec_abc"
    payload = '{"ok":1}'
    header = _stripe_header(payload, secret, 1700000000)
    valid, reason, _ = verify_stripe(payload, header, secret, now=1700099999, tolerance=300)
    assert not valid and reason == "timestamp_outside_tolerance"


def test_verify_hmac_prefix():
    payload = '{"x":1}'
    secret = "s3cr3t"
    sig = "sha256=" + _hmac_hex(payload, secret)
    valid, reason, _ = verify_hmac(payload, sig, secret)
    assert valid and reason == "ok"


def test_verify_adyen_roundtrip():
    import base64
    payload = '{"pspReference":"abc"}'
    secret_hex = "deadBEEF1234"
    key = bytes.fromhex(secret_hex)
    digest = hmac.new(key, payload.encode(), hashlib.sha256).digest()
    sig = base64.b64encode(digest).decode()
    valid, reason, _ = verify_adyen(payload, sig, secret_hex)
    assert valid and reason == "ok"


def test_missing_secret():
    r = verify_event({"provider": "hmac", "payload": "{}"}, 0)
    assert not r.valid and r.reason == "missing_secret"


def _build_demo_events():
    """Load the demo and patch in correctly-computed signatures."""
    events = load_events(open(DEMO, encoding="utf-8").read())
    # event 0 & 2: stripe valid (same sig => replay)
    for idx in (0, 2):
        ev = events[idx]
        ev["headers"]["Stripe-Signature"] = _stripe_header(
            ev["payload"], ev["secret"], 1700000500
        )
    # event 1: valid generic hmac
    ev1 = events[1]
    ev1["headers"]["X-Webhook-Signature"] = "sha256=" + _hmac_hex(
        ev1["payload"], ev1["secret"]
    )
    # event 3 stays invalid (deadbeef)
    return events


def test_analyze_batch_detects_replay_and_invalid():
    events = _build_demo_events()
    report = analyze_batch(events, now=1700000600)
    assert report.total == 4
    # event 0 and 1 valid, event 3 invalid
    assert report.results[0].valid
    assert report.results[1].valid
    assert not report.results[3].valid
    assert report.results[3].reason == "signature_mismatch"
    # replay detected: duplicate signature and duplicate event id
    kinds = {r["type"] for r in report.replays}
    assert "duplicate_signature" in kinds
    assert "duplicate_event_id" in kinds
    # overall: not ok
    assert report.ok is False


def test_idempotency_conflict():
    events = [
        {"id": "e1", "provider": "hmac", "secret": "k",
         "payload": '{"v":1}',
         "headers": {"X-Webhook-Signature": _hmac_hex('{"v":1}', "k")}},
        {"id": "e1", "provider": "hmac", "secret": "k",
         "payload": '{"v":2}',
         "headers": {"X-Webhook-Signature": _hmac_hex('{"v":2}', "k")}},
    ]
    report = analyze_batch(events)
    assert any(
        i["type"] == "conflicting_payloads_same_id" for i in report.idempotency_issues
    )
    assert report.ok is False


def test_clean_batch_is_ok():
    payload = '{"id":"good","amount":5}'
    events = [{
        "id": "good", "provider": "hmac", "secret": "k",
        "payload": payload,
        "headers": {"X-Webhook-Signature": "sha256=" + _hmac_hex(payload, "k")},
    }]
    report = analyze_batch(events)
    assert report.ok is True
    assert report.invalid == []


def test_cli_exits_nonzero_on_findings(tmp_path):
    events = _build_demo_events()
    f = tmp_path / "ev.json"
    f.write_text(json.dumps({"events": events}), encoding="utf-8")
    proc = subprocess.run(
        [sys.executable, "-m", "webhookvty", "verify", str(f), "--format", "json"],
        cwd=ROOT, capture_output=True, text=True,
    )
    assert proc.returncode == 1
    out = json.loads(proc.stdout)
    assert out["ok"] is False
    assert out["invalid"] == 1


def test_cli_version():
    proc = subprocess.run(
        [sys.executable, "-m", "webhookvty", "--version"],
        cwd=ROOT, capture_output=True, text=True,
    )
    assert proc.returncode == 0
    assert "webhookvty" in proc.stdout
