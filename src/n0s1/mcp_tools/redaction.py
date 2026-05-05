"""Redaction helpers for n0s1 MCP tool outputs.

Convention (Phase A1.1):
  - High-entropy alphanumeric values (all [A-Za-z0-9], length >= 16):
      show first 4 chars + "****" + last 4 chars.
      e.g. "AKIAIOSFODNN7EXAMPLE" -> "AKIA****MPLE"
  - Everything else:
      "<REDACTED:{kind}>"
      e.g. "<REDACTED:github_pat>"

Phase A3 will replace the second form with HMAC-hashed deterministic
redaction; do not implement that here.
"""
import re

_ALNUM_RE = re.compile(r'^[A-Za-z0-9]+$')


def redact_match(raw: str, kind: str) -> str:
    """Return a non-reversible placeholder for *raw*.

    Args:
        raw:  The raw matched secret string.
        kind: The regex rule id (e.g. "aws-access-token", "github-pat").

    Returns:
        A redacted string that contains no reversible portion of the secret.
    """
    stripped = raw.strip()
    if len(stripped) >= 16 and _ALNUM_RE.match(stripped):
        return f"{stripped[:4]}****{stripped[-4:]}"
    return f"<REDACTED:{kind}>"
