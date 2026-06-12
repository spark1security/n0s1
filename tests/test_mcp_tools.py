"""Tests for n0s1.mcp_tools.

Uses synthetic secrets (never real credentials).  The underlying
SecretScanner is mocked so no network calls are made.

Run with:
    python -m pytest tests/test_mcp_tools.py   (if pytest is installed)
    python -m unittest tests.test_mcp_tools     (built-in runner)
"""
import json
import sys
import unittest
from unittest.mock import MagicMock, patch

# Ensure src/ is on the path when running from repo root without installation.
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from n0s1.mcp_tools.context import ToolContext
from n0s1.mcp_tools.redaction import redact_match
from n0s1.mcp_tools.schemas import (
    AnalysisStatus,
    Finding,
    FindingsPage,
    ScanResult,
    ScanSummary,
    Severity,
    Status,
    Usage,
)
from n0s1.mcp_tools.usage import estimate_tokens, naive_baseline_tokens, usage_block


# ---------------------------------------------------------------------------
# Shared synthetic fixtures (never real secrets)
# ---------------------------------------------------------------------------

# 20-char all-alnum string — triggers high-entropy redaction path
SYNTHETIC_SECRET = "FAKK1234567890ABCDEF"
SYNTHETIC_KIND = "test-fake-key"

# Report structures that the mock scanner returns
_FINDING_ID = "abc123"
_MOCK_REPORT_JSON = {
    "tool": {"name": "n0s1", "version": "0.0.0", "author": "test"},
    "scan_date": {"timestamp": 0, "date_utc": "2026-01-01T00:00:00"},
    "regex_config": {},
    "findings": {
        _FINDING_ID: {
            "id": _FINDING_ID,
            "url": "https://example.com/issue/1#L42",
            "secret": "<REDACTED>",
            "mocked_secret": "FAKE****EXAMPLE",
            "details": {
                "matched_regex_config": {
                    "id": SYNTHETIC_KIND,
                    "description": "Test fake key",
                    "regex": r"FAKE[A-Z0-9]+",
                },
                "platform": "Jira",
                "ticket_field": "description",
            },
        }
    },
}
_MOCK_SENSITIVE_JSON = {
    "findings": {
        _FINDING_ID: {
            "sensitive_secret": SYNTHETIC_SECRET,
        }
    }
}


_BACKEND_UUID = "backend-uuid-from-server"

# Like _MOCK_REPORT_JSON but with a backend-assigned UUID, as returned when
# ai_analysis=True causes the scanner to upload the report.
_MOCK_REPORT_WITH_BACKEND_UUID = dict(_MOCK_REPORT_JSON)
_MOCK_REPORT_WITH_BACKEND_UUID = {**_MOCK_REPORT_JSON, "uuid": _BACKEND_UUID}


def _make_mock_scanner(report_json=None, sensitive_json=None, raw_chars_scanned=0):
    """Return a mock SecretScanner instance."""
    instance = MagicMock()
    instance.scan.return_value = report_json if report_json is not None else _MOCK_REPORT_JSON
    instance.report_sensitive_json = sensitive_json if sensitive_json is not None else _MOCK_SENSITIVE_JSON
    instance.raw_chars_scanned = raw_chars_scanned
    return instance


def _make_mock_analyzer(ai_status: str):
    """Return a mock SecretScanner whose analyze() and analyze_blocking() return ai_status."""
    instance = MagicMock()
    instance.analyze.return_value = ai_status
    instance.analyze_blocking.return_value = ai_status
    return instance


# ---------------------------------------------------------------------------
# Helper: patch SecretScanner for a single scan call
# ---------------------------------------------------------------------------

def _patched_ctx(callback=None):
    return ToolContext(on_scan_event=callback)


# ---------------------------------------------------------------------------
# Redaction tests
# ---------------------------------------------------------------------------

class TestRedaction(unittest.TestCase):

    def test_high_entropy_format(self):
        result = redact_match("AKIAIOSFODNN7EXAMPLE", "aws-access-token")
        self.assertEqual(result, "AKIA****MPLE")

    def test_high_entropy_exactly_16_chars(self):
        result = redact_match("ABCD1234EFGH5678", "some-key")
        self.assertEqual(result, "ABCD****5678")

    def test_short_secret_uses_kind_form(self):
        result = redact_match("shortval", "github-pat")
        self.assertEqual(result, "<REDACTED:github-pat>")

    def test_non_alnum_uses_kind_form(self):
        # Contains a hyphen → not all alnum
        result = redact_match("ABCD-EFGH-IJKL-MNOP", "some-token")
        self.assertEqual(result, "<REDACTED:some-token>")

    def test_raw_secret_absent_from_output(self):
        raw = SYNTHETIC_SECRET
        result = redact_match(raw, SYNTHETIC_KIND)
        self.assertNotIn(raw, result)

    def test_whitespace_stripped_before_check(self):
        # Leading/trailing spaces should not break the alnum check
        result = redact_match("  AKIAIOSFODNN7EXAMPLE  ", "aws-access-token")
        self.assertEqual(result, "AKIA****MPLE")


# ---------------------------------------------------------------------------
# Usage / token math tests
# ---------------------------------------------------------------------------

class TestUsageMath(unittest.TestCase):

    def test_estimate_tokens_returns_positive_int(self):
        n = estimate_tokens("Hello world, this is a test sentence.")
        self.assertIsInstance(n, int)
        self.assertGreater(n, 0)

    def test_naive_baseline_str(self):
        n = naive_baseline_tokens("some text here")
        self.assertIsInstance(n, int)
        self.assertGreater(n, 0)

    def test_naive_baseline_dict(self):
        n = naive_baseline_tokens({"key": "value", "nested": {"a": 1}})
        self.assertIsInstance(n, int)
        self.assertGreater(n, 0)

    def test_naive_baseline_list(self):
        n = naive_baseline_tokens([{"a": 1}, {"b": 2}])
        self.assertIsInstance(n, int)
        self.assertGreater(n, 0)

    def test_usage_block_savings_math(self):
        large_input = {"data": "x " * 2000}  # large raw payload
        small_output = {"summary": "2 findings"}
        use = usage_block(large_input, small_output)
        # tokens_saved == tokens_in - tokens_out (by construction)
        self.assertEqual(
            use.tokens_saved_estimate,
            use.tokens_in_estimate - use.tokens_out_actual,
        )

    def test_usage_block_tokens_in_ge_tokens_out_for_large_input(self):
        use = usage_block({"data": "x " * 5000}, {"summary": "ok"})
        self.assertGreaterEqual(use.tokens_in_estimate, use.tokens_out_actual)

    def test_usage_block_savings_pct_consistent(self):
        use = usage_block({"data": "word " * 500}, {"r": "small"})
        expected_pct = round(
            use.tokens_saved_estimate / use.tokens_in_estimate * 100, 1
        )
        self.assertAlmostEqual(use.savings_pct, expected_pct, places=1)

    def test_usage_schema_round_trip(self):
        use = usage_block("some raw text repeated many times " * 100, "small")
        validated = Usage.model_validate(use.model_dump())
        self.assertEqual(validated.tokens_in_estimate, use.tokens_in_estimate)
        self.assertEqual(validated.tokens_saved_estimate, use.tokens_saved_estimate)


# ---------------------------------------------------------------------------
# Schema round-trip tests
# ---------------------------------------------------------------------------

class TestSchemaRoundTrip(unittest.TestCase):

    def _make_finding(self):
        return Finding(
            file="https://example.com/issue/1",
            line=42,
            type="aws-access-token",
            severity=Severity.high,
            redacted_match="AKIA****MPLE",
        )

    def test_finding_round_trip(self):
        f = self._make_finding()
        validated = Finding.model_validate(f.model_dump())
        self.assertEqual(validated.type, f.type)
        self.assertEqual(validated.severity, Severity.high)

    def test_scan_result_round_trip(self):
        use = Usage(
            tokens_in_estimate=100,
            tokens_out_actual=10,
            tokens_saved_estimate=90,
            savings_pct=90.0,
        )
        summary = ScanSummary(
            total_findings=1,
            by_severity={Severity.high: 1},
            by_type={"aws-access-token": 1},
        )
        result = ScanResult(
            report_uuid="test-uuid",
            status="complete",
            summary=summary,
            findings=[self._make_finding()],
            usage=use,
        )
        validated = ScanResult.model_validate(result.model_dump())
        self.assertEqual(validated.report_uuid, "test-uuid")
        self.assertEqual(validated.summary.total_findings, 1)
        self.assertEqual(len(validated.findings), 1)

    def test_status_round_trip(self):
        s = Status(report_uuid="u1", status="complete", progress_pct=100.0)
        validated = Status.model_validate(s.model_dump())
        self.assertEqual(validated.progress_pct, 100.0)

    def test_status_with_ai_analysis_status(self):
        s = Status(
            report_uuid="u1",
            status="complete",
            progress_pct=100.0,
            ai_analysis_status="complete",
        )
        validated = Status.model_validate(s.model_dump())
        self.assertEqual(validated.ai_analysis_status, "complete")

    def test_scan_result_with_ai_analysis_status(self):
        use = Usage(
            tokens_in_estimate=10, tokens_out_actual=1,
            tokens_saved_estimate=9, savings_pct=90.0,
        )
        summary = ScanSummary(total_findings=0, by_severity={}, by_type={})
        result = ScanResult(
            report_uuid="u2", status="complete", summary=summary,
            usage=use, ai_analysis_status="pending",
        )
        validated = ScanResult.model_validate(result.model_dump())
        self.assertEqual(validated.ai_analysis_status, "pending")

    def test_analysis_status_round_trip(self):
        a = AnalysisStatus(
            report_uuid="u3",
            ai_analysis_status="waiting_client",
            message="Templates ready.",
        )
        validated = AnalysisStatus.model_validate(a.model_dump())
        self.assertEqual(validated.report_uuid, "u3")
        self.assertEqual(validated.ai_analysis_status, "waiting_client")

    def test_findings_page_round_trip(self):
        use = Usage(
            tokens_in_estimate=50,
            tokens_out_actual=5,
            tokens_saved_estimate=45,
            savings_pct=90.0,
        )
        fp = FindingsPage(
            report_uuid="u2",
            findings=[self._make_finding()],
            next_cursor=None,
            total=1,
            usage=use,
        )
        validated = FindingsPage.model_validate(fp.model_dump())
        self.assertEqual(validated.total, 1)


# ---------------------------------------------------------------------------
# Redaction safety tests (scan results must not leak raw secrets)
# ---------------------------------------------------------------------------

class TestRedactionSafety(unittest.TestCase):
    """Assert that SYNTHETIC_SECRET never appears in serialised tool output."""

    def _assert_secret_absent(self, payload):
        serialised = json.dumps(payload)
        self.assertNotIn(
            SYNTHETIC_SECRET,
            serialised,
            f"Raw synthetic secret found in serialised output: {serialised[:300]}",
        )

    def _run_scan_with_mock(self, tool_fn, *args, **kwargs):
        ctx = _patched_ctx()
        with patch("n0s1.mcp_tools.tools._scanner.SecretScanner") as MockScanner:
            MockScanner.return_value = _make_mock_scanner()
            return tool_fn(*args, ctx=ctx, **kwargs)

    def test_scan_jira_no_raw_secret(self):
        from n0s1.mcp_tools.tools import scan_jira
        result = self._run_scan_with_mock(scan_jira, "https://example.atlassian.net")
        self._assert_secret_absent(result.model_dump())

    def test_scan_confluence_no_raw_secret(self):
        from n0s1.mcp_tools.tools import scan_confluence
        result = self._run_scan_with_mock(scan_confluence, "https://example.atlassian.net")
        self._assert_secret_absent(result.model_dump())

    def test_scan_slack_no_raw_secret(self):
        from n0s1.mcp_tools.tools import scan_slack
        result = self._run_scan_with_mock(scan_slack, "https://example.slack.com")
        self._assert_secret_absent(result.model_dump())

    def test_scan_asana_no_raw_secret(self):
        from n0s1.mcp_tools.tools import scan_asana
        result = self._run_scan_with_mock(scan_asana, "https://app.asana.com")
        self._assert_secret_absent(result.model_dump())

    def test_scan_linear_no_raw_secret(self):
        from n0s1.mcp_tools.tools import scan_linear
        result = self._run_scan_with_mock(scan_linear, "https://linear.app")
        self._assert_secret_absent(result.model_dump())

    def test_scan_zendesk_no_raw_secret(self):
        from n0s1.mcp_tools.tools import scan_zendesk
        result = self._run_scan_with_mock(scan_zendesk, "example")
        self._assert_secret_absent(result.model_dump())

    def test_scan_wrike_no_raw_secret(self):
        from n0s1.mcp_tools.tools import scan_wrike
        result = self._run_scan_with_mock(scan_wrike, "https://www.wrike.com")
        self._assert_secret_absent(result.model_dump())

    def test_scan_github_no_raw_secret(self):
        from n0s1.mcp_tools.tools import scan_github
        result = self._run_scan_with_mock(scan_github, "myorg/myrepo")
        self._assert_secret_absent(result.model_dump())

    def test_scan_gitlab_no_raw_secret(self):
        from n0s1.mcp_tools.tools import scan_gitlab
        result = self._run_scan_with_mock(scan_gitlab, "mygroup/myproject")
        self._assert_secret_absent(result.model_dump())

    def test_get_scan_findings_no_raw_secret(self):
        from n0s1.mcp_tools.tools import get_scan_findings, scan_jira
        ctx = _patched_ctx()
        with patch("n0s1.mcp_tools.tools._scanner.SecretScanner") as MockScanner:
            MockScanner.return_value = _make_mock_scanner()
            result = scan_jira("https://example.atlassian.net", ctx=ctx)
        page = get_scan_findings(result.report_uuid, ctx=ctx)
        self._assert_secret_absent(page.model_dump())


# ---------------------------------------------------------------------------
# ToolContext callback tests
# ---------------------------------------------------------------------------

class TestToolContextCallback(unittest.TestCase):

    def _run_with_callback(self, tool_fn, *args, **kwargs):
        events = []
        ctx = ToolContext(on_scan_event=events.append)
        with patch("n0s1.mcp_tools.tools._scanner.SecretScanner") as MockScanner:
            MockScanner.return_value = _make_mock_scanner()
            result = tool_fn(*args, ctx=ctx, **kwargs)
        return result, events

    def test_scan_jira_fires_callback_once(self):
        from n0s1.mcp_tools.tools import scan_jira
        _, events = self._run_with_callback(scan_jira, "https://example.atlassian.net")
        self.assertEqual(len(events), 1)

    def test_scan_confluence_fires_callback_once(self):
        from n0s1.mcp_tools.tools import scan_confluence
        _, events = self._run_with_callback(scan_confluence, "https://example.atlassian.net")
        self.assertEqual(len(events), 1)

    def test_scan_slack_fires_callback_once(self):
        from n0s1.mcp_tools.tools import scan_slack
        _, events = self._run_with_callback(scan_slack, "https://example.slack.com")
        self.assertEqual(len(events), 1)

    def test_scan_asana_fires_callback_once(self):
        from n0s1.mcp_tools.tools import scan_asana
        _, events = self._run_with_callback(scan_asana, "https://app.asana.com")
        self.assertEqual(len(events), 1)

    def test_scan_linear_fires_callback_once(self):
        from n0s1.mcp_tools.tools import scan_linear
        _, events = self._run_with_callback(scan_linear, "https://linear.app")
        self.assertEqual(len(events), 1)

    def test_scan_zendesk_fires_callback_once(self):
        from n0s1.mcp_tools.tools import scan_zendesk
        _, events = self._run_with_callback(scan_zendesk, "example")
        self.assertEqual(len(events), 1)

    def test_scan_wrike_fires_callback_once(self):
        from n0s1.mcp_tools.tools import scan_wrike
        _, events = self._run_with_callback(scan_wrike, "https://www.wrike.com")
        self.assertEqual(len(events), 1)

    def test_scan_github_fires_callback_once(self):
        from n0s1.mcp_tools.tools import scan_github
        _, events = self._run_with_callback(scan_github, "myorg/myrepo")
        self.assertEqual(len(events), 1)

    def test_scan_gitlab_fires_callback_once(self):
        from n0s1.mcp_tools.tools import scan_gitlab
        _, events = self._run_with_callback(scan_gitlab, "mygroup/myproject")
        self.assertEqual(len(events), 1)

    def test_event_payload_has_required_keys(self):
        from n0s1.mcp_tools.tools import scan_jira
        _, events = self._run_with_callback(scan_jira, "https://example.atlassian.net")
        event = events[0]
        for key in ("report_uuid", "tool_name", "tokens_in_estimate",
                    "tokens_out_actual", "tokens_saved_estimate"):
            self.assertIn(key, event, f"Missing key {key!r} in event payload")

    def test_get_scan_status_fires_no_callback(self):
        from n0s1.mcp_tools.tools import get_scan_status, scan_jira
        events = []
        ctx = ToolContext(on_scan_event=events.append)
        with patch("n0s1.mcp_tools.tools._scanner.SecretScanner") as MockScanner:
            MockScanner.return_value = _make_mock_scanner()
            result = scan_jira("https://example.atlassian.net", ctx=ctx)
        events.clear()  # ignore the scan_jira event
        get_scan_status(result.report_uuid, ctx=ctx)
        self.assertEqual(len(events), 0)

    def test_get_scan_findings_fires_no_callback(self):
        from n0s1.mcp_tools.tools import get_scan_findings, scan_jira
        events = []
        ctx = ToolContext(on_scan_event=events.append)
        with patch("n0s1.mcp_tools.tools._scanner.SecretScanner") as MockScanner:
            MockScanner.return_value = _make_mock_scanner()
            result = scan_jira("https://example.atlassian.net", ctx=ctx)
        events.clear()
        get_scan_findings(result.report_uuid, ctx=ctx)
        self.assertEqual(len(events), 0)


# ---------------------------------------------------------------------------
# Functional integration tests (no network)
# ---------------------------------------------------------------------------

class TestToolFunctions(unittest.TestCase):
    """Verify return types, status, and pagination without network calls."""

    def _scan(self, tool_fn, *args, report=None, sensitive=None, **kwargs):
        ctx = _patched_ctx()
        with patch("n0s1.mcp_tools.tools._scanner.SecretScanner") as MockScanner:
            MockScanner.return_value = _make_mock_scanner(report, sensitive)
            return tool_fn(*args, ctx=ctx, **kwargs), ctx

    def test_scan_jira_returns_scan_result(self):
        from n0s1.mcp_tools.tools import scan_jira
        result, _ = self._scan(scan_jira, "https://example.atlassian.net")
        self.assertIsInstance(result, ScanResult)
        self.assertEqual(result.status, "complete")

    def test_scan_jira_with_project_and_since(self):
        from n0s1.mcp_tools.tools import scan_jira
        result, _ = self._scan(
            scan_jira, "https://example.atlassian.net",
            project_key="ABC", since="2024-01-01"
        )
        self.assertEqual(result.status, "complete")

    def test_scan_github_splits_owner_repo(self):
        from n0s1.mcp_tools.tools import scan_github
        with patch("n0s1.mcp_tools.tools._scanner.SecretScanner") as MockScanner:
            instance = _make_mock_scanner()
            MockScanner.return_value = instance
            scan_github("myorg/myrepo", ctx=_patched_ctx())
        call_kwargs = MockScanner.call_args[1]
        self.assertEqual(call_kwargs.get("owner"), "myorg")
        self.assertEqual(call_kwargs.get("repo"), "myrepo")

    def test_scan_gitlab_splits_group_project(self):
        from n0s1.mcp_tools.tools import scan_gitlab
        with patch("n0s1.mcp_tools.tools._scanner.SecretScanner") as MockScanner:
            MockScanner.return_value = _make_mock_scanner()
            scan_gitlab("mygroup/myproject", ctx=_patched_ctx())
        call_kwargs = MockScanner.call_args[1]
        self.assertEqual(call_kwargs.get("owner"), "mygroup")
        self.assertEqual(call_kwargs.get("repo"), "myproject")

    def test_failed_scan_returns_failed_status(self):
        from n0s1.mcp_tools.tools import scan_jira
        ctx = _patched_ctx()
        with patch("n0s1.mcp_tools.tools._scanner.SecretScanner") as MockScanner:
            MockScanner.return_value.scan.side_effect = RuntimeError("auth failed")
            result = scan_jira("https://example.atlassian.net", ctx=ctx)
        self.assertEqual(result.status, "failed")

    def test_get_scan_status_complete(self):
        from n0s1.mcp_tools.tools import get_scan_status, scan_jira
        ctx = _patched_ctx()
        with patch("n0s1.mcp_tools.tools._scanner.SecretScanner") as MockScanner:
            MockScanner.return_value = _make_mock_scanner()
            result = scan_jira("https://example.atlassian.net", ctx=ctx)
        status = get_scan_status(result.report_uuid, ctx=ctx)
        self.assertIsInstance(status, Status)
        self.assertEqual(status.status, "complete")
        self.assertEqual(status.progress_pct, 100.0)

    def test_get_scan_status_unknown_uuid_returns_pending(self):
        from n0s1.mcp_tools.tools import get_scan_status
        status = get_scan_status("no-such-uuid", ctx=_patched_ctx())
        self.assertEqual(status.status, "pending")

    def test_get_scan_findings_returns_findings_page(self):
        from n0s1.mcp_tools.tools import get_scan_findings, scan_jira
        ctx = _patched_ctx()
        with patch("n0s1.mcp_tools.tools._scanner.SecretScanner") as MockScanner:
            MockScanner.return_value = _make_mock_scanner()
            result = scan_jira("https://example.atlassian.net", ctx=ctx)
        page = get_scan_findings(result.report_uuid, ctx=ctx)
        self.assertIsInstance(page, FindingsPage)
        self.assertEqual(page.total, 1)
        self.assertEqual(len(page.findings), 1)

    def test_get_scan_findings_unknown_uuid_raises(self):
        from n0s1.mcp_tools.tools import get_scan_findings
        with self.assertRaises(KeyError):
            get_scan_findings("no-such-uuid", ctx=_patched_ctx())

    def test_get_scan_findings_severity_filter(self):
        from n0s1.mcp_tools.tools import get_scan_findings, scan_jira
        ctx = _patched_ctx()
        with patch("n0s1.mcp_tools.tools._scanner.SecretScanner") as MockScanner:
            MockScanner.return_value = _make_mock_scanner()
            result = scan_jira("https://example.atlassian.net", ctx=ctx)
        # high severity matches the mock
        page = get_scan_findings(result.report_uuid, severity=Severity.high, ctx=ctx)
        self.assertEqual(page.total, 1)
        # low severity matches nothing
        page_low = get_scan_findings(result.report_uuid, severity=Severity.low, ctx=ctx)
        self.assertEqual(page_low.total, 0)

    def test_get_scan_findings_pagination_cursor(self):
        from n0s1.mcp_tools.tools import _PAGE_SIZE, get_scan_findings, scan_jira
        # Build a report with _PAGE_SIZE + 1 findings
        n = _PAGE_SIZE + 1
        findings_dict = {}
        for i in range(n):
            fid = f"finding_{i}"
            findings_dict[fid] = {
                "id": fid,
                "url": f"https://example.com/issue/{i}",
                "secret": "<REDACTED>",
                "mocked_secret": "FAKE****MPLE",
                "details": {
                    "matched_regex_config": {"id": "test-key", "description": "", "regex": ""},
                    "platform": "Jira",
                    "ticket_field": "description",
                },
            }
        big_report = dict(_MOCK_REPORT_JSON)
        big_report["findings"] = findings_dict
        big_sensitive = {"findings": {fid: {"sensitive_secret": SYNTHETIC_SECRET} for fid in findings_dict}}

        ctx = _patched_ctx()
        with patch("n0s1.mcp_tools.tools._scanner.SecretScanner") as MockScanner:
            MockScanner.return_value = _make_mock_scanner(big_report, big_sensitive)
            result = scan_jira("https://example.atlassian.net", ctx=ctx)

        page1 = get_scan_findings(result.report_uuid, ctx=ctx)
        self.assertEqual(len(page1.findings), _PAGE_SIZE)
        self.assertIsNotNone(page1.next_cursor)

        page2 = get_scan_findings(result.report_uuid, page=page1.next_cursor, ctx=ctx)
        self.assertEqual(len(page2.findings), 1)
        self.assertIsNone(page2.next_cursor)

    def test_no_findings_empty_summary(self):
        from n0s1.mcp_tools.tools import scan_jira
        empty_report = dict(_MOCK_REPORT_JSON)
        empty_report["findings"] = {}
        ctx = _patched_ctx()
        with patch("n0s1.mcp_tools.tools._scanner.SecretScanner") as MockScanner:
            MockScanner.return_value = _make_mock_scanner(empty_report, None)
            result = scan_jira("https://example.atlassian.net", ctx=ctx)
        self.assertEqual(result.summary.total_findings, 0)
        self.assertEqual(result.findings, [])

    def test_line_number_parsed_from_url(self):
        from n0s1.mcp_tools.tools import scan_jira
        ctx = _patched_ctx()
        with patch("n0s1.mcp_tools.tools._scanner.SecretScanner") as MockScanner:
            MockScanner.return_value = _make_mock_scanner()
            result = scan_jira("https://example.atlassian.net", ctx=ctx)
        # The mock URL has #L42
        self.assertEqual(result.findings[0].line, 42)

    def test_show_matched_secret_never_passed_true(self):
        """Ensure the tools layer never enables raw-secret logging."""
        from n0s1.mcp_tools.tools import scan_jira
        with patch("n0s1.mcp_tools.tools._scanner.SecretScanner") as MockScanner:
            MockScanner.return_value = _make_mock_scanner()
            scan_jira("https://example.atlassian.net", ctx=_patched_ctx())
        call_kwargs = MockScanner.call_args[1]
        self.assertFalse(call_kwargs.get("show_matched_secret_on_logs", False))

    # ------------------------------------------------------------------
    # ai_analysis parameter tests
    # ------------------------------------------------------------------

    def test_scan_with_ai_analysis_sets_status_pending(self):
        from n0s1.mcp_tools.tools import scan_jira
        ctx = _patched_ctx()
        with patch("n0s1.mcp_tools.tools._scanner.SecretScanner") as MockScanner:
            MockScanner.return_value = _make_mock_scanner()
            result = scan_jira(
                "https://example.atlassian.net",
                ai_analysis=True,
                n0s1_token="tok-test",
                ctx=ctx,
            )
        self.assertEqual(result.ai_analysis_status, "pending")

    def test_scan_with_ai_analysis_uses_backend_uuid(self):
        from n0s1.mcp_tools.tools import scan_jira
        ctx = _patched_ctx()
        with patch("n0s1.mcp_tools.tools._scanner.SecretScanner") as MockScanner:
            MockScanner.return_value = _make_mock_scanner(_MOCK_REPORT_WITH_BACKEND_UUID)
            result = scan_jira(
                "https://example.atlassian.net",
                ai_analysis=True,
                n0s1_token="tok-test",
                ctx=ctx,
            )
        self.assertEqual(result.report_uuid, _BACKEND_UUID)

    def test_scan_without_ai_analysis_has_no_ai_status(self):
        from n0s1.mcp_tools.tools import scan_jira
        ctx = _patched_ctx()
        with patch("n0s1.mcp_tools.tools._scanner.SecretScanner") as MockScanner:
            MockScanner.return_value = _make_mock_scanner()
            result = scan_jira("https://example.atlassian.net", ctx=ctx)
        self.assertIsNone(result.ai_analysis_status)

    def test_scan_with_ai_analysis_forwards_n0s1_token(self):
        from n0s1.mcp_tools.tools import scan_jira
        with patch("n0s1.mcp_tools.tools._scanner.SecretScanner") as MockScanner:
            MockScanner.return_value = _make_mock_scanner()
            scan_jira(
                "https://example.atlassian.net",
                ai_analysis=True,
                n0s1_token="my-secret-token",
                ctx=_patched_ctx(),
            )
        call_kwargs = MockScanner.call_args[1]
        self.assertEqual(call_kwargs.get("n0s1_token"), "my-secret-token")
        self.assertTrue(call_kwargs.get("ai_analysis"))

    def test_get_scan_status_exposes_ai_analysis_status(self):
        from n0s1.mcp_tools.tools import get_scan_status, scan_jira
        ctx = _patched_ctx()
        with patch("n0s1.mcp_tools.tools._scanner.SecretScanner") as MockScanner:
            MockScanner.return_value = _make_mock_scanner(_MOCK_REPORT_WITH_BACKEND_UUID)
            result = scan_jira(
                "https://example.atlassian.net",
                ai_analysis=True,
                ctx=ctx,
            )
        status = get_scan_status(result.report_uuid, ctx=ctx)
        self.assertEqual(status.ai_analysis_status, "pending")

    def test_get_scan_status_ai_analysis_status_none_when_not_requested(self):
        from n0s1.mcp_tools.tools import get_scan_status, scan_jira
        ctx = _patched_ctx()
        with patch("n0s1.mcp_tools.tools._scanner.SecretScanner") as MockScanner:
            MockScanner.return_value = _make_mock_scanner()
            result = scan_jira("https://example.atlassian.net", ctx=ctx)
        status = get_scan_status(result.report_uuid, ctx=ctx)
        self.assertIsNone(status.ai_analysis_status)


# ---------------------------------------------------------------------------
# analyze_report tests
# ---------------------------------------------------------------------------

class TestAnalyzeReport(unittest.TestCase):
    """Tests for the analyze_report MCP tool."""

    def _call(self, ai_status: str, report_uuid: str = "test-uuid", **kwargs):
        from n0s1.mcp_tools.tools import analyze_report
        ctx = _patched_ctx()
        with patch("n0s1.mcp_tools.tools._scanner.SecretScanner") as MockScanner:
            MockScanner.return_value = _make_mock_analyzer(ai_status)
            result = analyze_report(report_uuid, ctx=ctx, **kwargs)
        return result

    def test_returns_analysis_status_instance(self):
        result = self._call("pending")
        self.assertIsInstance(result, AnalysisStatus)

    def test_status_pending(self):
        result = self._call("pending")
        self.assertEqual(result.ai_analysis_status, "pending")
        self.assertEqual(result.report_uuid, "test-uuid")
        self.assertTrue(len(result.message) > 0)

    def test_status_waiting_client(self):
        result = self._call("waiting_client")
        self.assertEqual(result.ai_analysis_status, "waiting_client")
        self.assertIn("analyze_report", result.message)

    def test_status_pending_verdict(self):
        result = self._call("pending_verdict")
        self.assertEqual(result.ai_analysis_status, "pending_verdict")

    def test_status_complete(self):
        result = self._call("complete")
        self.assertEqual(result.ai_analysis_status, "complete")
        self.assertIn("complete", result.message.lower())

    def test_status_failed(self):
        result = self._call("failed")
        self.assertEqual(result.ai_analysis_status, "failed")

    def test_status_submitted(self):
        result = self._call("submitted")
        self.assertEqual(result.ai_analysis_status, "submitted")

    def test_status_error(self):
        result = self._call("error")
        self.assertEqual(result.ai_analysis_status, "error")

    def test_n0s1_token_forwarded_to_scanner(self):
        from n0s1.mcp_tools.tools import analyze_report
        ctx = _patched_ctx()
        with patch("n0s1.mcp_tools.tools._scanner.SecretScanner") as MockScanner:
            MockScanner.return_value = _make_mock_analyzer("pending")
            analyze_report(
                "test-uuid",
                n0s1_token="my-n0s1-key",
                report_file="/tmp/report.json",
                ctx=ctx,
            )
        call_kwargs = MockScanner.call_args[1]
        self.assertEqual(call_kwargs.get("n0s1_token"), "my-n0s1-key")
        self.assertEqual(call_kwargs.get("report_file"), "/tmp/report.json")
        self.assertEqual(call_kwargs.get("report_uuid"), "test-uuid")

    def test_analyze_report_updates_store_when_uuid_known(self):
        from n0s1.mcp_tools.tools import analyze_report, get_scan_status, scan_jira
        ctx = _patched_ctx()
        # First, run a scan with ai_analysis so the UUID is in the store
        with patch("n0s1.mcp_tools.tools._scanner.SecretScanner") as MockScanner:
            MockScanner.return_value = _make_mock_scanner(_MOCK_REPORT_WITH_BACKEND_UUID)
            scan_jira("https://example.atlassian.net", ai_analysis=True, ctx=ctx)

        # Now advance the analysis — mock returns "complete"
        with patch("n0s1.mcp_tools.tools._scanner.SecretScanner") as MockScanner:
            MockScanner.return_value = _make_mock_analyzer("complete")
            analyze_report(_BACKEND_UUID, ctx=ctx)

        # The store should reflect the updated status
        status = get_scan_status(_BACKEND_UUID, ctx=ctx)
        self.assertEqual(status.ai_analysis_status, "complete")

    def test_analyze_report_does_not_fire_scan_event(self):
        from n0s1.mcp_tools.tools import analyze_report
        events = []
        ctx = ToolContext(on_scan_event=events.append)
        with patch("n0s1.mcp_tools.tools._scanner.SecretScanner") as MockScanner:
            MockScanner.return_value = _make_mock_analyzer("pending")
            analyze_report("test-uuid", ctx=ctx)
        self.assertEqual(len(events), 0)

    def test_wait_seconds_calls_analyze_blocking(self):
        from n0s1.mcp_tools.tools import analyze_report
        ctx = _patched_ctx()
        with patch("n0s1.mcp_tools.tools._scanner.SecretScanner") as MockScanner:
            mock_analyzer = _make_mock_analyzer("complete")
            MockScanner.return_value = mock_analyzer
            result = analyze_report("test-uuid", wait_seconds=120, ctx=ctx)
        mock_analyzer.analyze_blocking.assert_called_once_with(120)
        mock_analyzer.analyze.assert_not_called()
        self.assertEqual(result.ai_analysis_status, "complete")

    def test_no_wait_seconds_calls_analyze(self):
        from n0s1.mcp_tools.tools import analyze_report
        ctx = _patched_ctx()
        with patch("n0s1.mcp_tools.tools._scanner.SecretScanner") as MockScanner:
            mock_analyzer = _make_mock_analyzer("pending")
            MockScanner.return_value = mock_analyzer
            analyze_report("test-uuid", ctx=ctx)
        mock_analyzer.analyze.assert_called_once()
        mock_analyzer.analyze_blocking.assert_not_called()

    def test_status_timeout(self):
        result = self._call("timeout")
        self.assertEqual(result.ai_analysis_status, "timeout")
        self.assertIn("timed out", result.message.lower())

    def test_timeout_message_mentions_retry(self):
        result = self._call("timeout")
        self.assertIn("again", result.message.lower())


if __name__ == "__main__":
    unittest.main()
