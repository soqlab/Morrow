"""Any OpenAI-compatible endpoint, named by base URL.

This is the configuration-only form of bring-your-own-model, and it is the
right answer for most self-hosted servers and gateways:

    MORROW_LLM_PROVIDER=openai-compatible
    MORROW_LLM_BASE_URL=http://127.0.0.1:8000/v1      # vLLM
    MORROW_LLM_MODEL=meta-llama/Llama-3.1-8B-Instruct

Known-good targets: Groq (https://api.groq.com/openai/v1), OpenRouter
(https://openrouter.ai/api/v1), Together (https://api.together.xyz/v1), vLLM,
LM Studio (http://127.0.0.1:1234/v1) and llama.cpp's server
(http://127.0.0.1:8080/v1). Gateways that want extra routing headers get them
from MORROW_LLM_HEADERS.

Tool calling is declared off by default here, because "OpenAI-compatible"
covers servers that do not implement it and a tool request they ignore comes
back as prose. Set MORROW_LLM_TOOLS=1 when the endpoint supports it; the agent
then uses tools, and otherwise answers without them and says so.
"""

from __future__ import annotations

from typing import Any, Dict, List

from services.llm.openai_shape import OpenAIShaped

#: Base URLs an operator can name instead of typing, for the docs and the console.
KNOWN_ENDPOINTS = {
    "groq": "https://api.groq.com/openai/v1",
    "openrouter": "https://openrouter.ai/api/v1",
    "together": "https://api.together.xyz/v1",
    "vllm": "http://127.0.0.1:8000/v1",
    "lmstudio": "http://127.0.0.1:1234/v1",
    "lm-studio": "http://127.0.0.1:1234/v1",
    "llamacpp": "http://127.0.0.1:8080/v1",
    "llama-cpp": "http://127.0.0.1:8080/v1",
}


class OpenAICompatibleProvider(OpenAIShaped):
    id = "openai-compatible"
    default_base_url = ""
    default_model = ""
    # Honest capability declaration: opt in with MORROW_LLM_TOOLS=1, do not assume.
    supports_tools = False

    def check(self) -> Dict[str, Any]:
        missing: List[str] = []
        if not self.settings.base_url:
            missing.append("MORROW_LLM_BASE_URL")
        if not self.settings.model:
            missing.append("MORROW_LLM_MODEL")
        return {"ready": not missing, "missing": missing,
                "detail": "configured" if not missing else "set " + ", ".join(missing)}
