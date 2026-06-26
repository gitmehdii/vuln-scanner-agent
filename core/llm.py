"""
LLM client — centralized model config, HTTP call, and cost tracking.
All agents import from here instead of hardcoding model names.
"""

import os
from typing import Optional

import httpx

from core.logger import get_logger

logger = get_logger(__name__)

# DeepSeek V3 — fast and cheap, for analysis tasks
FAST_MODEL = "deepseek/deepseek-chat"

# DeepSeek R1 — reasoning model, for strategy and attack code generation
REASONING_MODEL = "deepseek/deepseek-r1"

# Pricing per 1M tokens in USD — approximate, see openrouter.ai/models
_PRICING: dict[str, dict[str, float]] = {
    "deepseek/deepseek-chat": {"input": 0.27,  "output": 1.10},
    "deepseek/deepseek-r1":   {"input": 0.55,  "output": 2.19},
    "gpt-4o":                 {"input": 5.00,  "output": 15.00},
    "gpt-4o-mini":            {"input": 0.15,  "output": 0.60},
}


class _CostTracker:
    def __init__(self):
        self._total_usd = 0.0
        self._input_tokens = 0
        self._output_tokens = 0
        self._calls = 0

    def record(self, model: str, input_tokens: int, output_tokens: int) -> float:
        rates = _PRICING.get(model, {"input": 0.0, "output": 0.0})
        cost = (input_tokens * rates["input"] + output_tokens * rates["output"]) / 1_000_000
        self._total_usd += cost
        self._input_tokens += input_tokens
        self._output_tokens += output_tokens
        self._calls += 1
        return cost

    @property
    def total_usd(self) -> float:
        return self._total_usd

    @property
    def calls(self) -> int:
        return self._calls

    def summary(self) -> str:
        return (
            f"${self._total_usd:.5f}  "
            f"({self._input_tokens:,} in / {self._output_tokens:,} out tokens, "
            f"{self._calls} appels)"
        )


# Singleton — accumulé sur toute la durée du processus
cost_tracker = _CostTracker()


def get_api_config() -> tuple[str, str]:
    """Return (url, api_key) based on available env vars."""
    if os.getenv("OPENROUTER_API_KEY"):
        return "https://openrouter.ai/api/v1/chat/completions", os.getenv("OPENROUTER_API_KEY")
    elif os.getenv("OPENAI_API_KEY"):
        return "https://api.openai.com/v1/chat/completions", os.getenv("OPENAI_API_KEY")
    return "", ""


async def llm_call(
    prompt: str,
    reasoning: bool = False,
    system: Optional[str] = None,
    max_tokens: int = 1000,
    temperature: float = 0.1,
    timeout: int = 60,
) -> str:
    """Single LLM call. reasoning=True uses R1, False uses V3."""
    url, key = get_api_config()
    if not key:
        raise RuntimeError("No API key found. Set OPENROUTER_API_KEY or OPENAI_API_KEY.")

    if os.getenv("OPENROUTER_API_KEY"):
        model = REASONING_MODEL if reasoning else FAST_MODEL
    else:
        model = "gpt-4o" if reasoning else "gpt-4o-mini"

    messages = []
    if system:
        messages.append({"role": "system", "content": system})
    messages.append({"role": "user", "content": prompt})

    async with httpx.AsyncClient(timeout=timeout) as client:
        resp = await client.post(
            url,
            headers={"Authorization": f"Bearer {key}"},
            json={
                "model": model,
                "messages": messages,
                "max_tokens": max_tokens,
                "temperature": temperature,
            },
        )
        resp.raise_for_status()
        data = resp.json()

    usage = data.get("usage", {})
    if usage:
        in_tok = usage.get("prompt_tokens", 0)
        out_tok = usage.get("completion_tokens", 0)
        call_cost = cost_tracker.record(model, in_tok, out_tok)
        short_model = model.split("/")[-1]
        logger.info(
            "LLM call",
            model=short_model,
            in_tok=in_tok,
            out_tok=out_tok,
            cost=f"${call_cost:.5f}",
            total=f"${cost_tracker.total_usd:.5f}",
        )

    return data["choices"][0]["message"]["content"].strip()
