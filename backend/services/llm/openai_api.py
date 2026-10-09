"""OpenAI, api.openai.com."""

from __future__ import annotations

from typing import Any, Dict, List

from services.llm.openai_shape import OpenAIShaped


class OpenAIProvider(OpenAIShaped):
    id = "openai"
    privacy_provider = "openai"
    default_base_url = "https://api.openai.com/v1"
    default_model = "gpt-4o-mini"

    def wire_payload(self, clean: Dict[str, Any]) -> Dict[str, Any]:
        # Never let a prompt or a completion be retained for training.
        return {**clean, "store": False}

    def check(self) -> Dict[str, Any]:
        result = super().check()
        missing: List[str] = list(result["missing"])
        if not self.settings.api_key:
            missing.append("OPENAI_API_KEY")
        return {"ready": not missing, "missing": missing,
                "detail": "configured" if not missing else "set " + ", ".join(missing)}
