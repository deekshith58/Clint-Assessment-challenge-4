# Challenge 4 — Insecure Deserialization Remediation Verification

> **Finding ID:** FIND-0139  
> **Type:** `INSECURE_DESERIALIZATION` — `JAVA_RCE_VIA_OBJECT_DESERIALIZATION`  
> **Endpoint:** `POST /api/v1/session/restore`  
> **Original Evidence:** RCE confirmed via out-of-band HTTP callback (`curl http://attacker.com/proof`)  
> **Client Claim:** *"Fixed by adding input validation that checks the serialized object class before deserialization"*

---

## Table of Contents

- [Overview](#overview)
- [Part A — Threat Modelling the Fix](#part-a--threat-modelling-the-fix)
- [Part B — Test Case Design](#part-b--test-case-design)
- [Part C — AI-Assisted Workflow](#part-c--ai-assisted-workflow)
- [Part D — Implementation](#part-d--implementation)
- [Part E — Systems Design Under Pressure](#part-e--systems-design-under-pressure)
- [Usage](#usage)
- [Submission Checklist](#submission-checklist)

---

## Overview

This repository contains the full submission for Challenge 4 of the Security Automation Remediation Verification series. The challenge involves verifying whether a client's claimed fix for a Java insecure deserialization vulnerability (originally exploited via a ysoserial CommonsCollections6 gadget chain) is genuine and complete.

---

## Part A — Threat Modelling the Fix

### 1. What Is Insecure Deserialization and Why Did It Lead to RCE?

Serialization converts a live Java object into a flat byte stream beginning with the magic bytes `AC ED 00 05`. Deserialization reverses this — the JVM reads the stream and reconstructs objects. Insecure deserialization occurs when an application passes attacker-controlled bytes directly into `ObjectInputStream.readObject()` without validation.

The endpoint `POST /api/v1/session/restore` accepted raw serialized bytes and handed them to `readObject()` without restriction. The attacker supplied a **CommonsCollections6 (CC6)** gadget chain — a sequence of legitimate Apache Commons Collections classes whose `readObject()` methods chain together to invoke `Runtime.exec()` via Java reflection. The chain fires during stream processing, **before the application's own logic executes**. RCE was confirmed by an out-of-band HTTP callback to the attacker's server.

The JVM is uniquely dangerous here because it **automatically invokes `readObject()` on every class it encounters in the stream** as part of deserialization. This happens beneath the application layer. By the time the application receives the reconstructed object, the gadget chain has already executed. No developer-written post-deserialization check can prevent this.

---

### 2. Five Ways the Class-Check Fix Could Be Incomplete or Bypassed

1. **Gadget chains in classpath from other libraries** — The fix likely only blocks CommonsCollections6 specifically. Chains like Spring1, Spring2, Groovy1, and JDK7u21 use entirely different class hierarchies and bypass any CC-specific blocklist.

2. **Class name spoofing via stream manipulation** — A crafted stream can present a whitelisted outer class name in the descriptor while encoding gadget chain classes inside nested objects, bypassing a check that only inspects the top-level class name.

3. **Deserialization of nested objects** — If the check only validates the outermost object class, nested gadget classes within a trusted wrapper are never inspected and fire during reconstruction.

4. **Alternative serialization formats** — Hessian, Kryo, and XML serialization each have their own object graph mechanisms. A check on Java's native format does nothing to protect endpoints that also accept these formats.

5. **Check runs after `readObject()` returns** — Java has no standard API to inspect a class before deserializing it without `ObjectInputFilter`. If the fix inspects the object after `readObject()` returns, the gadget chain has already fired — the check is too late.

---

### 3. Three Measurable Conditions to Declare the Fix Successful

- **Zero OOB callbacks** received across all gadget chain variants — CC6, CC1, CC2, CC4, CC7, Spring1, Spring2, Groovy1, and JDK7u21 — within a 60-second window per test.
- **All serialized payloads** (except the benign control) are rejected with the expected HTTP status code (400 or 415), with no timing anomalies exceeding 5 seconds.
- **URLDNS gadget probe** produces no DNS callback, confirming `ObjectInputStream.readObject()` is not being invoked on untrusted input at all.

---

### 4. Does Updating Commons Collections to 4.1 Eliminate the Risk?

**No.** Updating Commons Collections to 4.1 removes the specific classes that power CC1 through CC7 gadget chains — specifically `InvokerTransformer`'s ability to be used in a deserialization context. This addresses one library-specific attack surface only.

What it does **not** address:
- Spring1 and Spring2 chains use `org.springframework.core` classes entirely unrelated to Commons Collections
- Groovy1 chain uses Groovy's `ConversionHandler`
- JDK7u21 and JDK8u20 chains require **no third-party libraries at all** — only native JDK classes

The library update is a **necessary but deeply insufficient** remediation. The root cause — unconditional deserialization of untrusted input — remains entirely unaddressed.

---

## Part B — Test Case Design

| Test ID | Category | Payload Description | Expected (Vulnerable) | Expected (Fixed) | Pass Condition |
|---------|----------|--------------------|-----------------------|------------------|----------------|
| T01 | Baseline Replay | Original CommonsCollections6 gadget chain replayed exactly as captured with OAST HTTP callback | OAST callback received — RCE confirmed | No callback, request rejected | PASS if zero OAST callback within 60s and server returns rejection code |
| T02 | Alternative Library Chain | Spring1 gadget chain using `MethodInvokeTypeProvider` and `ObjectFactory` — no Commons Collections classes used | OAST callback via Spring chain | No callback, chain blocked or library absent | PASS if no callback — proves removing CC alone is insufficient |
| T03 | Class Name Manipulation | CC6 payload with outer class descriptor renamed to whitelisted class `java.util.HashMap` — tests depth of class-check filter | Filter bypassed, gadget fires, OAST received | Rejected despite spoofed class name | PASS only if server rejects and no callback — proves deep graph inspection |
| T04 | Non-Java Format | Hessian-serialized malicious object graph sent with `Content-Type: x-hessian` — tests alternative format handling | Hessian deserialized, gadget fires if library present | Format rejected entirely | PASS if server returns format rejection with no OAST activity |
| T05 | OOB DNS Probe | URLDNS gadget chain triggering DNS lookup only — no command execution — unique Burp Collaborator subdomain per test | DNS callback confirming `readObject()` invoked | No DNS callback — deserialization not triggered | PASS if zero DNS resolution observed — **most important first-run test** |
| T06 | Benign Control | Legitimate `java.util.ArrayList` with plain strings — no gadget classes anywhere in object graph | Object deserialized, 200 returned | Safe object accepted normally OR rejected gracefully | PASS if response is consistent and predictable — validates test environment |
| T07 | Malformed Stream | Byte stream with invalid magic bytes `DE AD BE EF` instead of `AC ED 00 05` — tests error handling | Unhandled exception, stack trace leaks library names | Generic 400 with no internal detail exposed | PASS if response contains no stack trace or class names |
| T08 ⭐ | Client Fix Validation | CC6 payload wrapped in whitelisted `SessionData` class descriptor — **directly attacks the client's specific class-check claim** | Class name passes filter, gadget fires beneath it, OAST received | Filter performs deep validation, rejects despite whitelisted name | PASS only if no OAST callback — **direct test of client's claimed fix** |
| T09 | Alternative Sink | CommonsCollections2 via `PriorityQueue` + `TransformingComparator` writing file to `/tmp/pwned` — different entry point and sink | File written to server filesystem | No file written, chain blocked regardless of sink | PASS if file absent after request |
| T10 | JDK-Only Chain | JDK7u21 chain using only `AnnotationInvocationHandler` and `LinkedHashSet` — **zero third-party libraries required** | OAST callback using only JDK classes | No callback — deserialization fully prevented or JDK patched | PASS if no callback — **proves library update alone is not sufficient** |

> **Key notes:** T05 (URLDNS) is always run first. T08 is the most critical — it directly tests the client's claimed fix. T02 and T10 together prove that neither removing Commons Collections nor blocking CC6 alone constitutes sufficient remediation.

---

## Part C — AI-Assisted Workflow

### Prompt Used

```
Write a Python function that takes a target API endpoint and a list of
pre-generated serialized payloads as hex or base64 strings, sends each
one with the correct Content-Type header for Java serialized objects,
and detects whether deserialization was triggered by monitoring for an
out-of-band DNS or HTTP callback to a canary domain.
```

### Raw AI Output

```python
import requests, base64, time
import dns.resolver

def send_payloads_and_detect(endpoint, payloads, canary_domain):
    headers = {"Content-Type": "application/x-java-serialized-object"}
    results = []
    for payload in payloads:
        try:
            decoded = base64.b64decode(payload)
        except:
            decoded = bytes.fromhex(payload)
        response = requests.post(endpoint, headers=headers, data=decoded)
        time.sleep(5)
        try:
            dns.resolver.resolve(canary_domain, "A")
            oob_detected = True
        except:
            oob_detected = False
        results.append({"payload": payload[:20],
                         "status_code": response.status_code,
                         "oob_detected": oob_detected})
    return results
```

### Critique — 7 Problems Identified

1. **OOB detection is non-functional** — `dns.resolver.resolve()` performs a standard forward DNS lookup. It tells you nothing about whether the target server triggered a callback. A working implementation must poll a Burp Collaborator or interactsh API.

2. **No correlation between payload and callback** — Every payload uses the same canary domain. Even if detection worked, there is no way to know which payload triggered a hit. Each payload needs a unique subdomain token (e.g. `tc-01-a3f9.canary.net`).

3. **Timing window too short and non-configurable** — A fixed 5-second sleep is inadequate. DNS propagation can push callbacks to 30+ minutes. The window must be configurable and poll-based.

4. **Bare except clauses swallow real errors** — Silent exception handling hides network failures, SSL errors, and malformed payloads.

5. **No distinction between deserialization triggered vs execution triggered** — A DNS callback (URLDNS) proves deserialization occurred. An HTTP callback proves command execution. These map to different severity conclusions.

6. **Content-Type hardcoded globally** — T04 requires Hessian with a different Content-Type. The header must be parameterized per payload.

7. **No request timeout** — `requests.post()` with no timeout blocks indefinitely if the server hangs.

### Corrected Version

```python
import requests, base64, time, uuid
from dataclasses import dataclass
from typing import Optional

@dataclass
class PayloadConfig:
    payload_data: str
    encoding: str                    # "hex" or "base64"
    content_type: str                # per-payload Content-Type
    test_id: str
    expected_callback_type: str      # "dns" | "http" | "none"

def decode_payload(data, encoding):
    if encoding == "base64": return base64.b64decode(data.strip())
    elif encoding == "hex":  return bytes.fromhex(data.strip())
    else: raise ValueError(f"Unsupported encoding: {encoding}")

def poll_interactsh(api_url, token, timeout=30.0, interval=3.0):
    """Polls interactsh API for a hit matching the correlation token.
       Returns (hit_detected: bool, callback_type: str|None).
       Distinguishes dns from http callbacks."""
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            r = requests.get(api_url, params={"id": token}, timeout=8, verify=True)
            if r.status_code == 200:
                for interaction in r.json().get("data", []):
                    proto = interaction.get("protocol", "").lower()
                    if proto in ("dns", "http", "https"):
                        return True, proto
        except requests.RequestException:
            pass  # Network hiccup, keep polling
        time.sleep(interval)
    return False, None

def send_and_detect(endpoint, config, canary_base, interactsh_api):
    token = f"{config.test_id}-{uuid.uuid4().hex[:8]}"
    canary_sub = f"{token}.{canary_base}"
    raw = decode_payload(config.payload_data, config.encoding)
    raw = raw.replace(b"CANARY_PLACEHOLDER", canary_sub.encode())
    headers = {"Content-Type": config.content_type, "X-Test-ID": config.test_id}
    try:
        t0 = time.monotonic()
        resp = requests.post(endpoint, headers=headers, data=raw, timeout=30, verify=False)
        elapsed = time.monotonic() - t0
    except requests.exceptions.Timeout:
        return {"error": "timeout", "verdict": "ERROR"}
    except requests.exceptions.ConnectionError as e:
        return {"error": str(e), "verdict": "ERROR"}
    hit, cb_type = poll_interactsh(interactsh_api, token)
    return {"test_id": config.test_id, "status": resp.status_code,
            "elapsed": round(elapsed, 3), "callback": hit,
            "callback_type": cb_type, "token": token}
```

---

## Part D — Implementation

### Setup

```bash
# Install dependency
pip install requests --break-system-packages

# Run against a real target
python3 deser_verify.py config.json

# Run offline with local mock server (Terminal 1)
python3 -c "
from http.server import HTTPServer, BaseHTTPRequestHandler
class H(BaseHTTPRequestHandler):
    def do_POST(self):
        length = int(self.headers.get('Content-Length', 0))
        self.rfile.read(length)
        tc = self.headers.get('X-Test-ID', '')
        print(f'  [SERVER] Received {tc}')
        self.send_response(200 if tc == 'TC-04' else 400)
        self.send_header('Content-Length', '0')
        self.end_headers()
    def log_message(self, *a): pass
print('[SERVER] Listening on 127.0.0.1:8080...')
HTTPServer(('127.0.0.1', 8080), H).serve_forever()
"

# Run script (Terminal 2)
python3 deser_verify.py config.json
```

### Input Format (`config.json`)

```json
{
  "target": "http://127.0.0.1:8080/post",
  "finding": "insecure_deserialization",
  "content_type": "application/x-java-serialized-object",
  "payloads": [
    {
      "id": "TC-01",
      "description": "CommonsCollections6 gadget chain",
      "encoding": "hex",
      "data": "aced0005737200..."
    },
    {
      "id": "TC-02",
      "description": "Benign serialized object (control)",
      "encoding": "base64",
      "data": "rO0ABXNyAA5qYXZh..."
    },
    {
      "id": "TC-03",
      "description": "Invalid magic bytes — malformed stream",
      "encoding": "hex",
      "data": "deadbeef0001..."
    },
    {
      "id": "TC-04",
      "description": "Spring gadget chain",
      "encoding": "hex",
      "data": "aced0005737200..."
    }
  ],
  "canary_domain": "find0139.oob.yourplatform.com",
  "expected_rejection_code": 400,
  "oob_poll_url": ""
}
```

### Verified Output

```
==================================================
  REMEDIATION VERIFICATION REPORT
==================================================
  Finding  : insecure_deserialization
  Target   : http://127.0.0.1:8080/post
  Timestamp: 2026-03-18T05:26:50Z

[TC-01]
  Description : CommonsCollections6 gadget chain
  Encoding    : hex
  Status      : 400 | Time: 0.01s | OOB Callback: NO
  Result      : PASS

[TC-02]
  Description : Benign serialized object (control)
  Encoding    : base64
  Status      : 200 | Time: 0.00s | OOB Callback: NO
  Result      : PASS
  -- Control test accepted as expected.

[TC-03]
  Description : Invalid magic bytes — malformed stream
  Encoding    : hex
  Status      : 400 | Time: 0.00s | OOB Callback: NO
  Result      : PASS
  -- Malformed stream correctly rejected.

[TC-04]
  Description : Spring gadget chain
  Encoding    : hex
  Status      : 200 | Time: 0.00s | OOB Callback: NO
  Result      : FAIL
  !! ANOMALY  : UNEXPECTED_STATUS (got 200, expected 400)
  -- Class-check bypassed via Spring gadget chain

==================================================
  VERDICT: REMEDIATION FAILED
==================================================
  Failed Tests: 1 / 4

[+] Evidence saved : evidence/evidence_2026-03-18T05-26-50.json
[+] SHA-256 hash   : a8f0367ee63cbb1c3ee60c351e5face94e4ff41e82b1...
```

### Script Architecture

| Function | Purpose |
|----------|---------|
| `decode_payload(data, encoding)` | Decodes hex or base64 with explicit `ValueError` on failure |
| `poll_oob(poll_url, window, interval)` | Deadline-based polling loop against OOB platform API |
| `run_test_case(tc, ...)` | Sends payload, detects all four anomaly classes, returns structured result |
| `render_report(...)` | Produces human-readable terminal report with per-test verdict |
| `save_evidence(...)` | Saves timestamped JSON + SHA-256 hash to `evidence/` directory |

### Anomaly Detection Logic

| Signal Class | Detection Method |
|---|---|
| **Behavioral** | HTTP status code ≠ `expected_rejection_code` |
| **Temporal** | Response time > 5.0 seconds |
| **Content** | Canary domain string appearing in response body |
| **OOB** | HTTP/DNS callback hit at `oob_poll_url` within 10-second window |

### Evidence & Tamper Detection (Bonus)

Every run saves:
- `evidence/evidence_<ISO8601>.json` — full config, all results, rendered report, OOB response bodies
- `evidence/evidence_<ISO8601>.sha256` — SHA-256 digest of the JSON blob

Any post-hoc modification of the report (status codes, verdicts, timestamps) is immediately detectable by re-hashing and comparing against the stored digest.

---

## Part E — Systems Design Under Pressure

> **Question:** Your pipeline runs 500 verification tests overnight. Callbacks arrive in random order, some delayed by up to 30 minutes. How do you design the correlation and result finalization logic so that late-arriving callbacks do not cause you to incorrectly close a finding as fixed?

The core design principle is to **never finalize a result at send time**. Each payload is assigned a globally unique correlation token embedded as a subdomain — for example `tc-01-a3f9.<canary>.net` — so every callback is unambiguously attributed regardless of arrival order.

Results live in three states — **PENDING**, **VULNERABLE**, and **FIXED** — never binary pass/fail at send time. A test moves to VULNERABLE the moment its token appears in any callback. It only moves to FIXED after its individual deadline expires, set to send time plus a configurable grace window of at least **45 minutes** to safely absorb the stated 30-minute worst-case delay plus margin.

A lightweight callback receiver writes every incoming hit to a **persistent store keyed by token**. A finalization worker runs continuously, scanning PENDING tests whose deadlines have passed and promoting them to FIXED only if no matching token exists in the callback store.

This architecture means no result closes prematurely. Late callbacks still land and flip state correctly because the store is **append-only** and the finalization worker never runs ahead of the deadline.

---

## Submission Checklist

- [x] **Part A** — Written answers: insecure deserialization explanation, five bypass mechanisms, three success conditions, Commons Collections analysis
- [x] **Part B** — Test case table: 10 test cases covering all required categories including class-check validation (T08) and JDK-only chain (T10)
- [x] **Part C** — AI prompt, raw output, detailed critique (7 identified problems), corrected implementation with interactsh polling and per-test correlation tokens
- [x] **Part D** — Working script `deser_verify.py` verified on Kali Linux with local mock server, evidence directory with SHA-256 hashing
- [x] **Part E** — 196-word answer with three-state finalization model and append-only callback store design

---
