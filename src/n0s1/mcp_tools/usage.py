"""Token-usage estimation using the cl100k_base tiktoken encoding.

cl100k_base is the de-facto baseline across Claude, GPT-4-class, and
Gemini token counts, making it a reasonable cross-model approximation.

If tiktoken is not importable (e.g. during lightweight unit tests), a
word-count heuristic (~1.3 tokens/word) is used as a fallback so that the
module remains importable without the extra dependency at test time.
"""
import json
from typing import Union

try:
    import tiktoken as _tiktoken

    _ENC = _tiktoken.get_encoding("cl100k_base")
except Exception:  # pragma: no cover
    _ENC = None

from n0s1.mcp_tools.schemas import Usage

# Typical ratio of characters to tokens for mixed prose + code content.
# cl100k_base averages ~4 chars/token for English text.
_CHARS_PER_TOKEN = 4


def estimate_tokens(text: str) -> int:
    """Return the estimated token count for *text*.

    Uses cl100k_base when tiktoken is available; falls back to a
    word-count heuristic otherwise.
    """
    if _ENC is not None:
        return len(_ENC.encode(text))
    # Heuristic: average English word is ~1.3 tokens
    return max(1, int(len(text.split()) * 1.3))


def _mocked_secret_chars(input_data: Union[dict, list]) -> int:
    """Sum of len(mocked_secret) across all findings in a report or findings collection."""
    if isinstance(input_data, dict):
        raw = input_data.get("findings", {})
        findings = list(raw.values()) if isinstance(raw, dict) else raw
    else:
        findings = input_data
    return sum(
        len(f.get("mocked_secret") or "")
        for f in findings
        if isinstance(f, dict)
    )


def naive_baseline_tokens(input_data: Union[int, str, dict, list]) -> int:
    """Tokens an agent would spend reading raw SaaS content directly.

    Accepts either:
    - An ``int`` — the raw character count accumulated by the scanner during
      the scan (preferred: avoids storing all content in memory).
    - A ``str``, ``dict``, or ``list`` — serialised and tokenised directly.
    """
    if isinstance(input_data, int):
        return max(1, input_data // _CHARS_PER_TOKEN)
    text = input_data if isinstance(input_data, str) else json.dumps(input_data)
    return estimate_tokens(text)


def usage_block(
    input_data: Union[int, str, dict, list],
    output_payload: Union[str, dict, list],
) -> Usage:
    """Build a :class:`Usage` instance from raw input and MCP output.

    Args:
        input_data:     Either the total character count of raw SaaS content
                        the scanner processed (``int``), or the raw content
                        itself as a str/dict/list.  Used to estimate the
                        baseline token cost an agent would have paid without
                        the MCP filtering layer.
        output_payload: The structured MCP response the agent actually receives.
                        When a ``dict`` or ``list``, token count is derived from
                        the sum of all ``mocked_secret`` field lengths across
                        findings (the content the agent actually sees).

    Returns:
        A :class:`Usage` with accurate savings figures.
    """
    tokens_in = naive_baseline_tokens(input_data)
    if isinstance(output_payload, (dict, list)):
        tokens_out = max(1, _mocked_secret_chars(output_payload) // _CHARS_PER_TOKEN)
    else:
        tokens_out = estimate_tokens(output_payload)
    saved = max(0, tokens_in - tokens_out)
    pct = round(saved / tokens_in * 100, 1) if tokens_in > 0 else 0.0
    return Usage(
        tokens_in_estimate=tokens_in,
        tokens_out_actual=tokens_out,
        tokens_saved_estimate=saved,
        savings_pct=pct,
    )
