#!/usr/bin/env python3
"""
FIND-0139 — Insecure Deserialization Remediation Verification Script
Accepts a JSON config, sends serialized payloads, detects anomalies,
outputs structured report, and saves timestamped evidence with SHA-256.
"""

import argparse
import base64
import hashlib
import json
import os
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

import requests

# ── Silence InsecureRequestWarning for test environments ──────────────────────
requests.packages.urllib3.disable_warnings()


# ─────────────────────────────────────────────────────────────────────────────
# Constants
# ─────────────────────────────────────────────────────────────────────────────
JAVA_MAGIC_HEX = "aced"
OOB_WINDOW_SECONDS = 10
TIMING_ANOMALY_THRESHOLD = 5.0
EVIDENCE_DIR = Path("evidence")


# ─────────────────────────────────────────────────────────────────────────────
# Payload Decoding
# ─────────────────────────────────────────────────────────────────────────────
def decode_payload(data: str, encoding: str) -> bytes:
    """
    Decodes a hex or base64 encoded payload string into raw bytes.
    Raises ValueError with a clear message on failure.
    """
    enc = encoding.strip().lower()
    try:
        if enc == "hex":
            return bytes.fromhex(data.strip())
        elif enc in ("base64", "b64"):
            return base64.b64decode(data.strip())
        else:
            raise ValueError(f"Unsupported encoding '{encoding}'. Use 'hex' or 'base64'.")
    except Exception as e:
        raise ValueError(f"Failed to decode payload ({encoding}): {e}")


# ─────────────────────────────────────────────────────────────────────────────
# OOB Callback Poll
# ─────────────────────────────────────────────────────────────────────────────
def poll_oob(
    poll_url: str,
    window: float = OOB_WINDOW_SECONDS,
    interval: float = 1.5
) -> tuple[bool, Optional[dict]]:
    """
    Polls the OOB platform API for a hit within the given time window.
    Returns (hit_detected: bool, response_body: dict | None).

    Distinguishes between:
      - No hit       → (False, None)
      - Hit recorded → (True, response_json)
    """
    if not poll_url:
        return False, None

    deadline = time.time() + window
    while time.time() < deadline:
        try:
            r = requests.get(poll_url, timeout=8, verify=False)
            if r.status_code == 200:
                body = {}
                try:
                    body = r.json()
                except Exception:
                    body = {"raw": r.text}

                # Interpret a hit: non-empty data array, hit count > 0,
                # or any truthy "hits" / "interactions" key
                hits = (
                    body.get("hits")
                    or body.get("interactions")
                    or body.get("data")
                    or body.get("count")
                )
                if hits:
                    return True, body
        except requests.RequestException:
            pass  # Network hiccup — keep polling until deadline
        time.sleep(interval)

    return False, None


# ─────────────────────────────────────────────────────────────────────────────
# Single Test Case Execution
# ─────────────────────────────────────────────────────────────────────────────
def run_test_case(
    tc: dict,
    target: str,
    content_type: str,
    canary_domain: str,
    expected_code: int,
    oob_poll_url: str,
) -> dict:
    """
    Executes a single test case:
      1. Decodes the payload
      2. Sends it to the target with the correct Content-Type
      3. Checks response code, timing, and canary string in body
      4. Polls OOB platform for callback within window
      5. Returns a structured result dict
    """
    tc_id = tc.get("id", "UNKNOWN")
    description = tc.get("description", "")
    encoding = tc.get("encoding", "hex")
    data = tc.get("data", "")

    result = {
        "id": tc_id,
        "description": description,
        "encoding": encoding,
        "status_code": None,
        "elapsed_seconds": None,
        "oob_callback": False,
        "oob_response_body": None,
        "canary_in_body": False,
        "anomalies": [],
        "verdict": "PASS",
        "notes": [],
        "error": None,
    }

    # ── Decode ────────────────────────────────────────────────────────────────
    try:
        raw_bytes = decode_payload(data, encoding)
    except ValueError as e:
        result["error"] = str(e)
        result["verdict"] = "ERROR"
        result["notes"].append("Payload decode failed — cannot send.")
        return result

    # ── Send ──────────────────────────────────────────────────────────────────
    headers = {
        "Content-Type": content_type,
        "X-Test-ID": tc_id,
        "X-Canary-Domain": canary_domain,
    }

    try:
        t_start = time.monotonic()
        resp = requests.post(
            target,
            headers=headers,
            data=raw_bytes,
            timeout=30,
            verify=False,
        )
        elapsed = time.monotonic() - t_start
    except requests.exceptions.Timeout:
        result["error"] = "Request timed out (>30s)"
        result["verdict"] = "ERROR"
        result["anomalies"].append("REQUEST_TIMEOUT")
        return result
    except requests.exceptions.ConnectionError as e:
        result["error"] = f"Connection error: {e}"
        result["verdict"] = "ERROR"
        return result

    result["status_code"] = resp.status_code
    result["elapsed_seconds"] = round(elapsed, 3)

    # ── Anomaly: Unexpected status code ───────────────────────────────────────
    # TC-02 (control/benign) expects 200; all others expect rejection
    is_control = "control" in description.lower() or "benign" in description.lower()

    if is_control:
        if resp.status_code not in (200, 201, 202):
            result["anomalies"].append(f"CONTROL_REJECTED ({resp.status_code})")
            result["notes"].append("Control payload was rejected — server may block all serialized input.")
        else:
            result["notes"].append("Control test accepted as expected.")
    else:
        if resp.status_code != expected_code:
            result["anomalies"].append(
                f"UNEXPECTED_STATUS (got {resp.status_code}, expected {expected_code})"
            )

    # ── Anomaly: Timing ───────────────────────────────────────────────────────
    if elapsed > TIMING_ANOMALY_THRESHOLD:
        result["anomalies"].append(f"TIMING_ANOMALY ({elapsed:.2f}s > {TIMING_ANOMALY_THRESHOLD}s)")

    # ── Anomaly: Canary string in response body ───────────────────────────────
    try:
        body_text = resp.text
    except Exception:
        body_text = ""

    if canary_domain and canary_domain in body_text:
        result["canary_in_body"] = True
        result["anomalies"].append("CANARY_REFLECTED_IN_BODY")

    # ── OOB Poll ─────────────────────────────────────────────────────────────
    if oob_poll_url and not is_control:
        hit, oob_body = poll_oob(oob_poll_url, window=OOB_WINDOW_SECONDS)
        result["oob_callback"] = hit
        if hit:
            result["oob_response_body"] = oob_body
            result["anomalies"].append("OOB_CALLBACK_RECEIVED")

    # ── Special notes ─────────────────────────────────────────────────────────
    raw_hex = raw_bytes[:4].hex().lower()
    if raw_hex != JAVA_MAGIC_HEX and not is_control:
        result["notes"].append("Malformed stream (no AC ED magic bytes) — testing error handling.")

    if "invalid" in description.lower() or "malformed" in description.lower():
        if resp.status_code == expected_code:
            result["notes"].append("Malformed stream correctly rejected.")

    # ── Final Verdict ─────────────────────────────────────────────────────────
    if result["error"]:
        result["verdict"] = "ERROR"
    elif result["anomalies"] and not is_control:
        result["verdict"] = "FAIL"
        # Annotate what specifically failed
        if "OOB_CALLBACK_RECEIVED" in result["anomalies"]:
            chain = description  # e.g. "Spring gadget chain"
            result["notes"].append(f"Class-check bypassed via {chain}")
        if any("TIMING" in a for a in result["anomalies"]):
            result["notes"].append(
                f"Timing anomaly ({elapsed:.2f}s) suggests deserialization activity."
            )
    else:
        result["verdict"] = "PASS"

    return result


# ─────────────────────────────────────────────────────────────────────────────
# Report Rendering
# ─────────────────────────────────────────────────────────────────────────────
def render_report(config: dict, results: list[dict], timestamp: str) -> str:
    """Renders the human-readable remediation verification report."""
    finding = config.get("finding", "unknown")
    target = config.get("target", "unknown")

    lines = [
        "=" * 50,
        "  REMEDIATION VERIFICATION REPORT",
        "=" * 50,
        f"  Finding  : {finding}",
        f"  Target   : {target}",
        f"  Timestamp: {timestamp}",
        "",
    ]

    failed = 0
    total = len(results)

    for r in results:
        oob_str = "YES" if r["oob_callback"] else "NO"
        elapsed_str = f"{r['elapsed_seconds']:.2f}s" if r["elapsed_seconds"] is not None else "N/A"
        status_str = str(r["status_code"]) if r["status_code"] else "N/A"

        lines.append(f"[{r['id']}]")
        lines.append(f"  Description : {r['description']}")
        lines.append(f"  Encoding    : {r['encoding']}")
        lines.append(
            f"  Status      : {status_str} | Time: {elapsed_str} | OOB Callback: {oob_str}"
        )

        if r["error"]:
            lines.append(f"  Result      : ERROR — {r['error']}")
        else:
            lines.append(f"  Result      : {r['verdict']}")

        for note in r["notes"]:
            lines.append(f"  -- {note}")

        if r["anomalies"]:
            for anomaly in r["anomalies"]:
                lines.append(f"  !! ANOMALY  : {anomaly}")

        lines.append("")
        if r["verdict"] == "FAIL":
            failed += 1

    lines.append("=" * 50)
    if failed > 0:
        lines.append("  VERDICT: REMEDIATION FAILED")
    else:
        lines.append("  VERDICT: REMEDIATION PASSED")
    lines.append("=" * 50)
    lines.append(f"  Failed Tests: {failed} / {total}")
    lines.append("")

    return "\n".join(lines)


# ─────────────────────────────────────────────────────────────────────────────
# Evidence Storage (Bonus)
# ─────────────────────────────────────────────────────────────────────────────
def save_evidence(config: dict, results: list[dict], timestamp: str, report_text: str):
    """
    Saves a timestamped JSON evidence file and a SHA-256 hash file
    to the evidence/ directory. Includes OOB response bodies when present.
    """
    EVIDENCE_DIR.mkdir(exist_ok=True)

    safe_ts = timestamp.replace(":", "-").replace("Z", "")
    json_path = EVIDENCE_DIR / f"evidence_{safe_ts}.json"
    hash_path = EVIDENCE_DIR / f"evidence_{safe_ts}.sha256"

    evidence = {
        "timestamp": timestamp,
        "config": config,
        "results": results,
        "report": report_text,
        "oob_responses": {
            r["id"]: r["oob_response_body"]
            for r in results
            if r.get("oob_callback") and r.get("oob_response_body")
        },
    }

    json_bytes = json.dumps(evidence, indent=2, default=str).encode("utf-8")
    sha256_digest = hashlib.sha256(json_bytes).hexdigest()

    json_path.write_bytes(json_bytes)
    hash_path.write_text(f"{sha256_digest}  {json_path.name}\n")

    print(f"\n[+] Evidence saved : {json_path}")
    print(f"[+] SHA-256 hash   : {hash_path}")
    print(f"    {sha256_digest}")


# ─────────────────────────────────────────────────────────────────────────────
# Entry Point
# ─────────────────────────────────────────────────────────────────────────────
def main():
    parser = argparse.ArgumentParser(
        description="FIND-0139 Insecure Deserialization Remediation Verifier"
    )
    parser.add_argument(
        "config",
        nargs="?",
        help="Path to the JSON config file (or pass via stdin with -)",
    )
    parser.add_argument(
        "--no-evidence",
        action="store_true",
        help="Skip saving evidence files",
    )
    args = parser.parse_args()

    # ── Load config ───────────────────────────────────────────────────────────
    if args.config == "-" or args.config is None:
        raw = sys.stdin.read()
    else:
        raw = Path(args.config).read_text()

    try:
        config = json.loads(raw)
    except json.JSONDecodeError as e:
        print(f"[!] Invalid JSON config: {e}", file=sys.stderr)
        sys.exit(1)

    target = config["target"]
    finding = config.get("finding", "unknown")
    content_type = config.get("content_type", "application/x-java-serialized-object")
    payloads = config.get("payloads", [])
    canary_domain = config.get("canary_domain", "")
    expected_code = config.get("expected_rejection_code", 400)
    oob_poll_url = config.get("oob_poll_url", "")

    timestamp = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

    print(f"\n[*] Starting verification: {finding} → {target}")
    print(f"[*] {len(payloads)} test case(s) loaded\n")

    # ── Run all test cases ────────────────────────────────────────────────────
    results = []
    for tc in payloads:
        print(f"  → Sending {tc.get('id')} — {tc.get('description', '')}")
        r = run_test_case(
            tc=tc,
            target=target,
            content_type=content_type,
            canary_domain=canary_domain,
            expected_code=expected_code,
            oob_poll_url=oob_poll_url,
        )
        results.append(r)

    # ── Render and print report ───────────────────────────────────────────────
    report = render_report(config, results, timestamp)
    print("\n" + report)

    # ── Save evidence (bonus) ─────────────────────────────────────────────────
    if not args.no_evidence:
        save_evidence(config, results, timestamp, report)


if __name__ == "__main__":
    main()