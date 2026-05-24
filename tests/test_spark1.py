"""Unit tests for spark1.encrypt_sensitive_report, upload_key, and upload_report.

No network calls are made — all HTTP is mocked.
"""
import base64
import copy
import sys
import os
import unittest
from unittest.mock import MagicMock, patch, call

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from n0s1.controllers.spark1 import (
    Spark1,
    encrypt_sensitive_report,
    _has_sensitive_secrets,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_sensitive_json(*secrets):
    """Build a minimal report_sensitive_json with the given secret strings."""
    return {
        "findings": {
            f"finding_{i}": {"sensitive_secret": s}
            for i, s in enumerate(secrets)
        }
    }


def _make_spark1():
    """Return a Spark1 instance with a dummy token (no network)."""
    return Spark1(token_auth="n0s1-test-token-fake")


def _mock_response(status_code, json_body=None):
    r = MagicMock()
    r.status_code = status_code
    r.json.return_value = json_body or {}
    return r


# ---------------------------------------------------------------------------
# encrypt_sensitive_report
# ---------------------------------------------------------------------------

class TestEncryptSensitiveReport(unittest.TestCase):

    def test_returns_raw_key_of_32_bytes(self):
        sj = _make_sensitive_json("mysecret")
        _, raw_key = encrypt_sensitive_report(sj)
        self.assertEqual(len(raw_key), 32)

    def test_secret_is_replaced_with_base64_ciphertext(self):
        sj = _make_sensitive_json("AKIAIOSFODNN7EXAMPLE")
        encrypt_sensitive_report(sj)
        ct = sj["findings"]["finding_0"]["sensitive_secret"]
        # Must be decodable base64 and no longer the plaintext
        decoded = base64.b64decode(ct)
        self.assertNotEqual(ct, "AKIAIOSFODNN7EXAMPLE")
        self.assertGreater(len(decoded), 12)  # nonce (12) + ciphertext

    def test_ciphertext_decrypts_to_original(self):
        plaintext = "AKIAIOSFODNN7EXAMPLE"
        sj = _make_sensitive_json(plaintext)
        _, raw_key = encrypt_sensitive_report(sj)

        ct_b64 = sj["findings"]["finding_0"]["sensitive_secret"]
        ct_bytes = base64.b64decode(ct_b64)
        nonce, ciphertext = ct_bytes[:12], ct_bytes[12:]
        aesgcm = AESGCM(raw_key)
        recovered = aesgcm.decrypt(nonce, ciphertext, None).decode()
        self.assertEqual(recovered, plaintext)

    def test_multiple_findings_all_encrypted_with_same_key(self):
        secrets = ["secret_a", "secret_b", "secret_c"]
        sj = _make_sensitive_json(*secrets)
        _, raw_key = encrypt_sensitive_report(sj)

        aesgcm = AESGCM(raw_key)
        for i, plaintext in enumerate(secrets):
            ct_b64 = sj["findings"][f"finding_{i}"]["sensitive_secret"]
            ct_bytes = base64.b64decode(ct_b64)
            nonce, ct = ct_bytes[:12], ct_bytes[12:]
            recovered = aesgcm.decrypt(nonce, ct, None).decode()
            self.assertEqual(recovered, plaintext)

    def test_empty_secret_is_left_unchanged(self):
        sj = {"findings": {"f1": {"sensitive_secret": ""}, "f2": {"sensitive_secret": "real"}}}
        _, raw_key = encrypt_sensitive_report(sj)
        self.assertEqual(sj["findings"]["f1"]["sensitive_secret"], "")
        self.assertNotEqual(sj["findings"]["f2"]["sensitive_secret"], "real")

    def test_missing_sensitive_secret_key_is_skipped(self):
        sj = {"findings": {"f1": {"other_field": "value"}}}
        original = copy.deepcopy(sj)
        encrypt_sensitive_report(sj)
        self.assertEqual(sj, original)

    def test_mutates_in_place_and_returns_same_dict(self):
        sj = _make_sensitive_json("mysecret")
        returned, _ = encrypt_sensitive_report(sj)
        self.assertIs(returned, sj)

    def test_empty_findings_returns_key(self):
        sj = {"findings": {}}
        _, raw_key = encrypt_sensitive_report(sj)
        self.assertEqual(len(raw_key), 32)

    def test_none_input_returns_key(self):
        _, raw_key = encrypt_sensitive_report(None)
        self.assertEqual(len(raw_key), 32)


# ---------------------------------------------------------------------------
# _has_sensitive_secrets
# ---------------------------------------------------------------------------

class TestHasSensitiveSecrets(unittest.TestCase):

    def test_returns_true_when_secret_present(self):
        self.assertTrue(_has_sensitive_secrets(_make_sensitive_json("s3cr3t")))

    def test_returns_false_when_all_empty(self):
        sj = {"findings": {"f1": {"sensitive_secret": ""}, "f2": {"sensitive_secret": ""}}}
        self.assertFalse(_has_sensitive_secrets(sj))

    def test_returns_false_when_no_findings(self):
        self.assertFalse(_has_sensitive_secrets({"findings": {}}))

    def test_returns_false_for_none(self):
        self.assertFalse(_has_sensitive_secrets(None))

    def test_returns_true_when_at_least_one_secret_present(self):
        sj = {"findings": {"f1": {"sensitive_secret": ""}, "f2": {"sensitive_secret": "real"}}}
        self.assertTrue(_has_sensitive_secrets(sj))


# ---------------------------------------------------------------------------
# Spark1.upload_key
# ---------------------------------------------------------------------------

class TestUploadKey(unittest.TestCase):

    def test_returns_true_on_201(self):
        s = _make_spark1()
        raw_key = os.urandom(32)
        with patch.object(s, "_post_request", return_value=_mock_response(201)) as mock_post:
            result = s.upload_key("uuid-123", raw_key)
        self.assertTrue(result)
        mock_post.assert_called_once()

    def test_posts_base64_encoded_key(self):
        s = _make_spark1()
        raw_key = os.urandom(32)
        expected_b64 = base64.b64encode(raw_key).decode()
        with patch.object(s, "_post_request", return_value=_mock_response(201)) as mock_post:
            s.upload_key("uuid-123", raw_key)
        _, kwargs = mock_post.call_args
        self.assertEqual(kwargs["json"]["encrypted_key"], expected_b64)

    def test_posts_to_correct_url(self):
        s = _make_spark1()
        with patch.object(s, "_post_request", return_value=_mock_response(201)) as mock_post:
            s.upload_key("uuid-abc", os.urandom(32))
        url = mock_post.call_args[0][0]
        self.assertIn("/api/v1/scans/uuid-abc/key", url)

    def test_returns_false_on_409(self):
        s = _make_spark1()
        with patch.object(s, "_post_request", return_value=_mock_response(409)):
            result = s.upload_key("uuid-123", os.urandom(32))
        self.assertFalse(result)

    def test_returns_false_on_network_error(self):
        s = _make_spark1()
        with patch.object(s, "_post_request", side_effect=Exception("timeout")):
            result = s.upload_key("uuid-123", os.urandom(32))
        self.assertFalse(result)

    def test_returns_false_for_empty_report_uuid(self):
        s = _make_spark1()
        with patch.object(s, "_post_request") as mock_post:
            result = s.upload_key("", os.urandom(32))
        self.assertFalse(result)
        mock_post.assert_not_called()

    def test_returns_false_for_none_raw_key(self):
        s = _make_spark1()
        with patch.object(s, "_post_request") as mock_post:
            result = s.upload_key("uuid-123", None)
        self.assertFalse(result)
        mock_post.assert_not_called()


# ---------------------------------------------------------------------------
# Spark1.upload_report (with sensitive_json wiring)
# ---------------------------------------------------------------------------

class TestUploadReportWithSensitiveJson(unittest.TestCase):

    def test_upload_report_without_sensitive_json_is_unchanged(self):
        """Existing callers that pass no sensitive_json still work."""
        s = _make_spark1()
        report = {"findings": []}
        upload_resp = _mock_response(201, {"report_uuid": "uuid-123"})
        with patch.object(s, "_post_request", return_value=upload_resp) as mock_post:
            with patch.object(s, "upload_key") as mock_key:
                r = s.upload_report(report)
        self.assertEqual(r.status_code, 201)
        mock_key.assert_not_called()

    def test_upload_report_with_no_secrets_skips_key_upload(self):
        s = _make_spark1()
        sensitive = {"findings": {"f1": {"sensitive_secret": ""}}}
        upload_resp = _mock_response(201, {"report_uuid": "uuid-123"})
        with patch.object(s, "_post_request", return_value=upload_resp):
            with patch.object(s, "upload_key") as mock_key:
                s.upload_report({"findings": []}, sensitive_json=sensitive)
        mock_key.assert_not_called()

    def test_upload_report_encrypts_and_uploads_key_on_success(self):
        s = _make_spark1()
        sensitive = _make_sensitive_json("AKIAIOSFODNN7EXAMPLE")
        upload_resp = _mock_response(201, {"report_uuid": "uuid-abc"})
        with patch.object(s, "_post_request", return_value=upload_resp):
            with patch.object(s, "upload_key", return_value=True) as mock_key:
                s.upload_report({"findings": []}, sensitive_json=sensitive)
        mock_key.assert_called_once()
        report_uuid_arg, raw_key_arg = mock_key.call_args[0]
        self.assertEqual(report_uuid_arg, "uuid-abc")
        self.assertEqual(len(raw_key_arg), 32)

    def test_upload_report_encrypts_sensitive_json_in_place(self):
        s = _make_spark1()
        sensitive = _make_sensitive_json("AKIAIOSFODNN7EXAMPLE")
        upload_resp = _mock_response(201, {"report_uuid": "uuid-abc"})
        with patch.object(s, "_post_request", return_value=upload_resp):
            with patch.object(s, "upload_key", return_value=True):
                s.upload_report({"findings": []}, sensitive_json=sensitive)
        # sensitive_secret should now be ciphertext, not plaintext
        ct = sensitive["findings"]["finding_0"]["sensitive_secret"]
        self.assertNotEqual(ct, "AKIAIOSFODNN7EXAMPLE")
        base64.b64decode(ct)  # must be valid base64

    def test_upload_report_skips_key_upload_when_scan_upload_fails(self):
        s = _make_spark1()
        sensitive = _make_sensitive_json("s3cr3t")
        with patch.object(s, "_post_request", return_value=_mock_response(500)):
            with patch.object(s, "upload_key") as mock_key:
                s.upload_report({"findings": []}, sensitive_json=sensitive)
        mock_key.assert_not_called()

    def test_upload_report_logs_warning_when_key_upload_fails(self):
        s = _make_spark1()
        sensitive = _make_sensitive_json("s3cr3t")
        upload_resp = _mock_response(201, {"report_uuid": "uuid-abc"})
        with patch.object(s, "_post_request", return_value=upload_resp):
            with patch.object(s, "upload_key", return_value=False):
                with self.assertLogs("root", level="WARNING") as log:
                    s.upload_report({"findings": []}, sensitive_json=sensitive)
        self.assertTrue(any("key upload failed" in m for m in log.output))

    def test_upload_report_returns_none_when_report_is_none(self):
        s = _make_spark1()
        self.assertIsNone(s.upload_report(None))

    def test_upload_report_still_returns_response_even_if_key_upload_fails(self):
        s = _make_spark1()
        sensitive = _make_sensitive_json("s3cr3t")
        upload_resp = _mock_response(201, {"report_uuid": "uuid-abc"})
        with patch.object(s, "_post_request", return_value=upload_resp):
            with patch.object(s, "upload_key", return_value=False):
                with self.assertLogs("root", level="WARNING"):
                    r = s.upload_report({"findings": []}, sensitive_json=sensitive)
        self.assertEqual(r.status_code, 201)

    def test_ai_analysis_flag_is_forwarded(self):
        s = _make_spark1()
        upload_resp = _mock_response(201, {"report_uuid": "uuid-123"})
        with patch.object(s, "_post_request", return_value=upload_resp) as mock_post:
            s.upload_report({"findings": []}, ai_analysis=True)
        payload = mock_post.call_args[1]["json"]
        self.assertTrue(payload.get("ai_analysis"))


if __name__ == "__main__":
    unittest.main()
