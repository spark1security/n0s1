# AI Analysis Redesign Plan

## Background & Problem

The current `ai_analysis()` implementation in `spark1.py:156` drives all 4 analysis steps synchronously from the client, finding by finding, causing HTTP timeouts for large reports. The goal is a fire-and-forget async model where the backend scheduler drives the steps it can own (1 and 4), and the client re-invokes only for the step it must own (step 2: executing HTTP request validators with real credentials).

---

## The 4-Step AI Analysis Flow

These steps happen **after** the report has already been uploaded to the backend:

| Step | Owner | What happens |
|------|-------|-------------|
| 1 | **Backend** | `analyze_leak()` generates an `request_validator` (HTTP request params) for each finding |
| 2 | **Client** | `_execute_request(req_validator)` — injects real credential, executes the HTTP request, stores `response_validator` in the report |
| 3 | **Client** | Re-uploads the report enriched with `response_validators` to the backend |
| 4 | **Backend** | `interpret_leak_analysis()` reads each `response_validator` and writes `["ai_report"]["verdict"]` |

The client **must** own step 2 because it is the only party that holds the real (non-mocked) credential needed to make the validation request meaningful.

---

## Desired Behavior Summary

1. **Pro scan with `--ai-analysis`** → scan completes → report uploaded → `ai_analysis_status` set to `"pending"` → client exits immediately.
2. **Pro scan without `--ai-analysis`** → report uploaded only → no AI analysis queued.
3. **New `analyze` command** → accepts `--report-uuid` or `--report-file` → submits/queues report for AI analysis → client exits immediately.
4. **Subsequent `analyze --report-uuid` calls** → client checks status; if `"waiting_client"`, executes HTTP requests and re-uploads; otherwise reports current status and exits.

---

## `ai_analysis_status` State Machine

Add `ai_analysis_status` as a new nullable column on the `Scan` model, separate from the existing `status` column (which tracks upload completion and must not be broken).

```
null              — AI analysis was never requested
"pending"         — queued; backend scheduler will run step 1
"waiting_client"  — step 1 done (request_validators written to report);
                    client must download, execute HTTP requests, and re-upload
"pending_verdict" — client re-uploaded with response_validators;
                    backend scheduler will run step 4
"complete"        — step 4 done; verdicts written to report file
"failed"          — unrecoverable error at any step, or stale > 7 days
```

### State transitions

```
[not set] ──(--ai-analysis flag or analyze command)──► "pending"
"pending"         ──(scheduler: step 1 done)──────────► "waiting_client"
"waiting_client"  ──(client re-uploads responses)──────► "pending_verdict"
"pending_verdict" ──(scheduler: step 4 done)───────────► "complete"
any               ──(error or timeout)──────────────────► "failed"
```

---

## Changes Required

### 1. Backend: `Scan` model (`models.py`)

- Add `ai_analysis_status = db.Column(db.String(32), nullable=True, default=None)`.
- Create a DB migration.

---

### 2. Backend: `upload_report` endpoint — `POST /api/v1/scans`

**File:** `n0s1_backend.py:1034`

Read the optional `"ai_analysis"` boolean field from the report JSON body. Strip it from the report before writing to disk so the stored file stays clean.

```python
report = request.get_json(silent=True)
ai_analysis_requested = bool(report.pop("ai_analysis", False))

# ... validate, write to disk (field already stripped) ...

scan_record = Scan(
    ...
    status="complete",
    ai_analysis_status="pending" if ai_analysis_requested else None,
)
```

---

### 3. Backend: New endpoint — `POST /api/v1/scans/<report_uuid>/analyze`

Queues AI analysis for a report that is already in the database.

```
POST /api/v1/scans/<report_uuid>/analyze
Authorization: Bearer <N0S1_TOKEN>
```

Logic:
- Authenticate via API token.
- Look up `Scan` by `report_uuid` and `user_id`. If not found → 404.
- If `ai_analysis_status` is already `"pending"`, `"waiting_client"`, or `"pending_verdict"` → 409 (already in progress).
- Otherwise set `ai_analysis_status = "pending"` and return 202:
  ```json
  {"report_uuid": "...", "ai_analysis_status": "pending"}
  ```

---

### 4. Backend: New endpoint — `POST /api/v1/scans/analyze` (file-based entry point)

Accepts a local report body, handles UUID assignment, and queues AI analysis. Used by the `analyze` command when no UUID is known yet.

```
POST /api/v1/scans/analyze
Authorization: Bearer <N0S1_TOKEN>
Content-Type: application/json
Body: <report JSON>
```

Logic:
1. Validate the report against `_REPORT_SCHEMA`.
2. Extract `report.get("uuid")`.
3. **If UUID present:**
   - If `Scan` record exists for this `user_id` → overwrite on-disk report file, set `ai_analysis_status="pending"`, return 202.
   - If no `Scan` record → create one with the provided UUID, write file, `ai_analysis_status="pending"`, return 201.
4. **If UUID absent:**
   - Assign a new UUID, write file, create `Scan` record, `ai_analysis_status="pending"`, return 201.
5. Response always includes:
   ```json
   {"report_uuid": "...", "ai_analysis_status": "pending"}
   ```

---

### 5. Backend: New endpoint — `PATCH /api/v1/scans/<report_uuid>`

Used by the client to re-upload the report after executing HTTP request validators (step 3). Overwrites the on-disk report file and advances `ai_analysis_status` to `"pending_verdict"`.

```
PATCH /api/v1/scans/<report_uuid>
Authorization: Bearer <N0S1_TOKEN>
Content-Type: application/json
Body: <updated report JSON with response_validators>
```

Logic:
- Authenticate via API token.
- Look up `Scan` by `report_uuid` and `user_id`. If not found → 404.
- Validate report body against `_REPORT_SCHEMA`.
- Overwrite the on-disk report file.
- Set `ai_analysis_status = "pending_verdict"`.
- Return 200 with scan metadata.

---

### 6. Backend: `_sync_scan_statuses()` extended for AI analysis steps 1 and 4

**File:** `n0s1_backend.py:2275`

Extend the existing background scheduler function. The scheduler inspects `ai_analysis_status` and only runs what it can do without client involvement.

```python
def _sync_scan_statuses():
    # ... existing upload-status reconciliation (unchanged) ...

    # --- Step 1: generate request_validators for pending analyses ---
    ai_pending = Scan.query.filter_by(ai_analysis_status="pending").all()
    for scan in ai_pending:
        try:
            files = search_files(data_dir, scan.report_uuid)
            if not files:
                scan.ai_analysis_status = "failed"
                continue
            with open(files[0]) as f:
                report = json.load(f)
            report = _generate_request_validators(report)  # see §7
            with open(files[0], "w") as f:
                json.dump(report, f)
            scan.ai_analysis_status = "waiting_client"
        except Exception:
            logging.exception("Step 1 failed for %s", scan.report_uuid)
            scan.ai_analysis_status = "failed"
    db.session.commit()

    # --- Step 4: interpret responses and write verdicts ---
    ai_verdict_pending = Scan.query.filter_by(ai_analysis_status="pending_verdict").all()
    for scan in ai_verdict_pending:
        try:
            files = search_files(data_dir, scan.report_uuid)
            if not files:
                scan.ai_analysis_status = "failed"
                continue
            with open(files[0]) as f:
                report = json.load(f)
            report = _generate_verdicts(report)  # see §7
            with open(files[0], "w") as f:
                json.dump(report, f)
            findings = _build_dashboard_findings(report)
            scan.findings_count = len(findings)
            scan.leak_status_top = _compute_leak_status_top(findings)
            scan.ai_analysis_status = "complete"
        except Exception:
            logging.exception("Step 4 failed for %s", scan.report_uuid)
            scan.ai_analysis_status = "failed"
    db.session.commit()

    # --- Mark stale waiting_client / pending_verdict as failed (> 7 days) ---
    stale_statuses = ["waiting_client", "pending_verdict"]
    for stale_status in stale_statuses:
        stale = Scan.query.filter(
            Scan.ai_analysis_status == stale_status,
            Scan.created_at < stale_cutoff
        ).all()
        for scan in stale:
            scan.ai_analysis_status = "failed"
    db.session.commit()
```

---

### 7. Backend: Two focused helpers (replace the old monolithic `_run_ai_analysis`)

**`_generate_request_validators(report)`** — step 1 only:
```python
def _generate_request_validators(report: dict) -> dict:
    """For each finding without a request_validator, call analyze_leak() and store result."""
    findings = report.get("findings", {})
    for id, finding in findings.items():
        if finding.get("ai_report", {}).get("request_validator"):
            continue  # already generated
        secret = finding.get("mocked_secret", "")
        secret_type = finding.get("details", {}).get("matched_regex_config", {}).get("id", "")
        if not secret:
            continue
        try:
            req_validator = analyze_leak(secret_type, secret)
            finding.setdefault("ai_report", {})["request_validator"] = req_validator
            report["findings"][id] = finding
        except Exception:
            logging.exception("_generate_request_validators: failed for finding %s", id)
    return report
```

**`_generate_verdicts(report)`** — step 4 only:
```python
def _generate_verdicts(report: dict) -> dict:
    """For each finding with a response_validator but no verdict, call interpret_leak_analysis()."""
    findings = report.get("findings", {})
    for id, finding in findings.items():
        ai_report = finding.get("ai_report", {})
        if ai_report.get("verdict"):
            continue  # already done
        req_validator = ai_report.get("request_validator")
        resp_validator = ai_report.get("response_validator")
        if not req_validator or not resp_validator:
            continue
        secret_type = finding.get("details", {}).get("matched_regex_config", {}).get("id", "")
        try:
            req_obj = HttpRequest.model_validate(req_validator)
            verdict = interpret_leak_analysis(secret_type, req_obj, resp_validator)
            finding["ai_report"]["verdict"] = verdict
            report["findings"][id] = finding
        except Exception:
            logging.exception("_generate_verdicts: failed for finding %s", id)
    return report
```

Both helpers are idempotent — they skip findings that already have the relevant field, making re-runs safe.

---

### 8. Client: `scanner.py` — Post-scan upload flow

**File:** `scanner.py:604-610`

Pass `ai_analysis=self.ai_analysis` into `upload_report()` so the flag travels in the report body. The backend pops it before writing to disk and sets `ai_analysis_status="pending"` on the `Scan` record if it was `True`. No separate follow-up call needed.

```python
if n0s1_pro:
    upload_http_response = n0s1_pro.upload_report(self.report_json, ai_analysis=self.ai_analysis)
    self._process_report_upload(upload_http_response)
    if self.ai_analysis:
        scanner.log_message(
            f"AI analysis queued. Run: n0s1 analyze --report-uuid {self.report_json.get('uuid')}"
        )
```

Remove the existing call to `n0s1_pro.ai_analysis()` entirely.

---

### 9. Client: `spark1.py` — New methods

**`upload_report(report, ai_analysis=False)`** — extended to embed the control flag in the body:
```python
def upload_report(self, report: dict, ai_analysis: bool = False):
    if report is None:
        return None
    upload_report_url = self.base_url + "/api/v1/scans"
    try:
        payload = dict(report)
        if ai_analysis:
            payload["ai_analysis"] = True  # backend pops this before saving to disk
        r = self._post_request(upload_report_url, json=payload)
        return r
    except Exception as ex:
        logging.info(str(ex))
    return None
```

**`get_scan_status(report_uuid)`** — polls current status:
```python
def get_scan_status(self, report_uuid: str):
    url = f"{self.base_url}/api/v1/scans/{report_uuid}"
    try:
        r = self._get_request(url)
        if r.status_code == 200:
            return r.json()
    except Exception as ex:
        logging.info(str(ex))
    return None
```

**`get_scan_report(report_uuid)`** — downloads the current report file (with request_validators):
```python
def get_scan_report(self, report_uuid: str):
    url = f"{self.base_url}/api/v1/scans/{report_uuid}/findings"
    try:
        r = self._get_request(url)
        if r.status_code == 200:
            return r.json()
    except Exception as ex:
        logging.info(str(ex))
    return None
```

**`upload_responses(report_uuid, report)`** — re-uploads after step 2 (PATCH):
```python
def upload_responses(self, report_uuid: str, report: dict):
    url = f"{self.base_url}/api/v1/scans/{report_uuid}"
    try:
        r = self._patch_request(url, json=report)
        return r
    except Exception as ex:
        logging.info(str(ex))
    return None
```

**`submit_for_ai_analysis(report_uuid, report)`** — used by the `analyze` command when no UUID exists yet:
```python
def submit_for_ai_analysis(self, report_uuid: str = None, report: dict = None):
    try:
        if report_uuid and not report:
            url = f"{self.base_url}/api/v1/scans/{report_uuid}/analyze"
            r = self._post_request(url, json={})
        else:
            # Embed the control flag in the report body; backend strips it before saving to disk
            payload = dict(report or {})
            payload["ai_analysis"] = True
            url = f"{self.base_url}/api/v1/scans/analyze"
            r = self._post_request(url, json=payload)
        return r
    except Exception as ex:
        logging.info(str(ex))
    return None
```

---

### 10. Client: `n0s1.py` — New `analyze` command

**File:** `n0s1.py`

Add subcommand in `init_argparse()`:

```python
analyze_parser = subparsers.add_parser(
    "analyze",
    help="Submit a scan report for AI analysis or advance an in-progress analysis",
    parents=[parent_parser],
)
analyze_parser.add_argument(
    "--report-uuid",
    dest="report_uuid",
    nargs="?",
    type=str,
    help="UUID of a previously uploaded report."
)
# --report-file is inherited from parent_parser
```

Handler in `main()`:

```python
if command == "analyze":
    report_uuid = getattr(args, "report_uuid", None)
    report_file_path = args.report_file

    # If UUID not supplied, try to get it from the report file
    report = None
    if not report_uuid and report_file_path:
        with open(report_file_path) as f:
            report = json.load(f)
        report_uuid = report.get("uuid")

    if not report_uuid and not report:
        scanner.log_message("Provide --report-uuid or --report-file.")
        return

    n0s1_pro = spark1.Spark1(token_auth=N0S1_TOKEN)

    # If we have a UUID, check current status first
    if report_uuid:
        status_data = n0s1_pro.get_scan_status(report_uuid)
        ai_status = (status_data or {}).get("ai_analysis_status")

        if ai_status == "waiting_client":
            # Step 2: client executes HTTP request validators
            remote_report = n0s1_pro.get_scan_report(report_uuid)
            if remote_report:
                updated_report = _execute_request_validators(remote_report, report)
                r = n0s1_pro.upload_responses(report_uuid, updated_report)
                if r and 200 <= r.status_code < 300:
                    scanner.log_message(f"Responses uploaded. Backend will compute verdicts.")
                    scanner.log_message(f"Run again to check status: n0s1 analyze --report-uuid {report_uuid}")
                else:
                    scanner.log_message("Failed to upload responses.")
            return

        if ai_status == "complete":
            scanner.log_message(f"AI analysis complete for report [{report_uuid}].")
            # Optionally download and save final report
            return

        if ai_status in ("pending", "pending_verdict"):
            scanner.log_message(f"AI analysis in progress (status: {ai_status}). Try again later.")
            return

        if ai_status == "failed":
            scanner.log_message(f"AI analysis failed for report [{report_uuid}].")
            return

    # No UUID or no known status — submit the report for the first time
    r = n0s1_pro.submit_for_ai_analysis(report_uuid=report_uuid, report=report)
    if r and 200 <= r.status_code < 300:
        result = r.json()
        uuid_out = result.get("report_uuid")
        scanner.log_message(f"AI analysis queued. Report UUID: [{uuid_out}]")
        scanner.log_message(f"Run later to advance: n0s1 analyze --report-uuid {uuid_out}")
    else:
        scanner.log_message("Failed to queue AI analysis.")
```

**`_execute_request_validators(remote_report, local_report)`** — client-side step 2 helper in `scanner.py` or `spark1.py`:

```python
def _execute_request_validators(remote_report, local_report=None):
    """
    For each finding with a request_validator, inject the real credential
    (from local_report if available, else fall back to mocked_secret),
    execute the HTTP request, and store the response.
    """
    findings = remote_report.get("findings", {})
    local_findings = (local_report or {}).get("findings", {})
    for id, finding in findings.items():
        req_validator = finding.get("ai_report", {}).get("request_validator")
        if not req_validator:
            continue
        # Prefer real credential from local report; fall back to mocked_secret
        cred = local_findings.get(id, {}).get("sensitive_secret") or finding.get("mocked_secret", "")
        if cred:
            req_validator = _inject_cred(req_validator, cred)
        resp = _execute_request(req_validator)
        finding.setdefault("ai_report", {})["response_validator"] = resp
        remote_report["findings"][id] = finding
    return remote_report
```

Also add `"analyze"` to the `commands` list in `main()`.

---

## End-to-End Flow Diagrams

### Flow A: Pro scan with `--ai-analysis`

```
n0s1 jira_scan --ai-analysis
│
├── scan completes
├── upload report → POST /api/v1/scans   (body includes "ai_analysis": true)
│   └── backend: pops field, saves clean report, ai_analysis_status = "pending"
└── client exits, prints: "Run: n0s1 analyze --report-uuid <uuid>"

[backend scheduler, ~5 min later]
├── detects ai_analysis_status="pending"
├── runs analyze_leak() for each finding → writes request_validators to report file
└── ai_analysis_status = "waiting_client"

n0s1 analyze --report-uuid <uuid>
├── GET /api/v1/scans/<uuid>  → status="waiting_client"
├── GET /api/v1/scans/<uuid>/findings  → download report with request_validators
├── _inject_cred() + _execute_request() for each finding  [client-side, real credentials]
├── PATCH /api/v1/scans/<uuid>  → re-upload report with response_validators
│   └── backend: ai_analysis_status = "pending_verdict"
└── client exits, prints: "Run again to check status"

[backend scheduler, ~5 min later]
├── detects ai_analysis_status="pending_verdict"
├── runs interpret_leak_analysis() for each finding → writes verdicts to report file
└── ai_analysis_status = "complete"

n0s1 analyze --report-uuid <uuid>
└── GET /api/v1/scans/<uuid>  → status="complete", prints confirmation
```

### Flow B: `analyze` command with a local report file (no UUID)

```
n0s1 analyze --report-file my_report.json
│
├── reads file, no UUID found
├── POST /api/v1/scans/analyze  (submit_for_ai_analysis())
│   └── backend: assigns new UUID, ai_analysis_status = "pending"
└── client exits, prints UUID

[same scheduler flow as Flow A from "waiting_client" onward]
```

### Flow C: `analyze` command with a local report file (UUID present)

```
n0s1 analyze --report-file my_report.json   (file has "uuid": "abc-123")
│
├── reads file, UUID = "abc-123"
├── GET /api/v1/scans/abc-123  → check status
│   ├── if no record yet → POST /api/v1/scans/analyze (creates record)
│   └── if record exists → check ai_analysis_status and advance accordingly
└── (same polling flow as Flow A)
```

---

## Files to Change

| File | Change |
|------|--------|
| `n0s1_api_backend/src/python/models.py` | Add `ai_analysis_status` column to `Scan` + migration |
| `n0s1_api_backend/src/python/n0s1_backend.py` | Extend `upload_report` (`?ai_analysis=true`); add `POST /scans/<uuid>/analyze`; add `POST /scans/analyze`; add `PATCH /scans/<uuid>`; extend `_sync_scan_statuses` for steps 1 and 4; add `_generate_request_validators` and `_generate_verdicts` helpers |
| `n0s1/src/n0s1/controllers/spark1.py` | Add `request_ai_analysis()`, `get_scan_status()`, `get_scan_report()`, `upload_responses()`, `submit_for_ai_analysis()`; remove old synchronous `ai_analysis()` |
| `n0s1/src/n0s1/scanner.py` | Replace `n0s1_pro.ai_analysis()` call with `n0s1_pro.request_ai_analysis()`; add `_execute_request_validators()` helper |
| `n0s1/src/n0s1/n0s1.py` | Add `analyze` subcommand + handler in `main()` |

---

## What to Remove

- The synchronous per-finding loop in `spark1.py:ai_analysis()` (lines 156–199). This method drove all 4 steps from the client in a single blocking call and is replaced by the state-machine model above.
- The old monolithic `_run_ai_analysis()` concept from the previous plan version — replaced by two focused, idempotent helpers (`_generate_request_validators` and `_generate_verdicts`).
