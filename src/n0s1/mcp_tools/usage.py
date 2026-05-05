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


def estimate_tokens(text: str) -> int:
    """Return the estimated token count for *text*.

    Uses cl100k_base when tiktoken is available; falls back to a
    word-count heuristic otherwise.
    """
    if _ENC is not None:
        return len(_ENC.encode(text))
    # Heuristic: average English word is ~1.3 tokens
    return max(1, int(len(text.split()) * 1.3))


def naive_baseline_tokens(input_data: Union[str, dict, list]) -> int:
    """Tokens an agent would spend reading raw SaaS content directly.

    Serialises *input_data* to JSON (or uses it as-is if already a str)
    and tokenises the result — representing the cost of reading the raw
    payload without the MCP filtering layer.
    """
    text = input_data if isinstance(input_data, str) else json.dumps(input_data)
    return estimate_tokens(text)


def usage_block(
    input_data: Union[str, dict, list],
    output_payload: Union[str, dict],
) -> Usage:
    """Build a :class:`Usage` instance from raw input and MCP output.

    Args:
        input_data:     The raw SaaS content (or a representative proxy) that
                        the scanner consumed.  Used to estimate the baseline
                        token cost an agent would have paid.
        output_payload: The structured MCP response the agent actually receives.

    Returns:
        A :class:`Usage` with accurate savings figures.
    """
    tokens_in = naive_baseline_tokens(input_data)
    out_text = output_payload if isinstance(output_payload, str) else json.dumps(output_payload)
    tokens_out = estimate_tokens(out_text)
    saved = max(0, tokens_in - tokens_out)
    pct = round(saved / tokens_in * 100, 1) if tokens_in > 0 else 0.0
    return Usage(
        tokens_in_estimate=tokens_in,
        tokens_out_actual=tokens_out,
        tokens_saved_estimate=saved,
        savings_pct=pct,
    )
