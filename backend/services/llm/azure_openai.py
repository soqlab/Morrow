"""Azure OpenAI.

Azure differs from OpenAI in three ways that matter here: the model lives in
the URL as a *deployment* name, the API version is a required query parameter,
and the credential is an `api-key` header rather than a bearer token.
"""

from __future__ import annotations

from typing import Any, Dict, List

from services.llm.base import CONFIG, LLMError
from services.llm.openai_shape import OpenAIShaped

DEFAULT_API_VERSION = "2024-10-21"


class AzureOpenAIProvider(OpenAIShaped):
    id = "azure-openai"
    default_model = ""

    def endpoint(self) -> str:
        base = (self.settings.base_url or "").rstrip("/")
        if not base:
            raise LLMError(CONFIG, "Azure OpenAI needs the resource endpoint.", provider=self.id,
                           remedy="Set MORROW_LLM_BASE_URL to https://<resource>.openai.azure.com")
        deployment = self.settings.deployment or self.settings.model
        if not deployment:
            raise LLMError(CONFIG, "Azure OpenAI needs a deployment name.", provider=self.id,
                           remedy="Set MORROW_LLM_AZURE_DEPLOYMENT (or MORROW_LLM_MODEL) to the deployment name.")
        version = self.settings.api_version or DEFAULT_API_VERSION
        if "/openai/deployments/" in base:
            return f"{base}?api-version={version}"
        return f"{base}/openai/deployments/{deployment}/chat/completions?api-version={version}"

    def auth_headers(self) -> Dict[str, str]:
        return {"api-key": self.settings.api_key} if self.settings.api_key else {}

    def wire_payload(self, clean: Dict[str, Any]) -> Dict[str, Any]:
        # The deployment carries the model on Azure; sending `model` as well is
        # accepted but meaningless, and some API versions reject an unknown one.
        payload = {key: value for key, value in clean.items() if key != "model"}
        return payload

    def check(self) -> Dict[str, Any]:
        missing: List[str] = []
        if not self.settings.base_url:
            missing.append("MORROW_LLM_BASE_URL")
        if not (self.settings.deployment or self.settings.model):
            missing.append("MORROW_LLM_AZURE_DEPLOYMENT")
        if not self.settings.api_key:
            missing.append("MORROW_LLM_API_KEY")
        return {"ready": not missing, "missing": missing,
                "detail": "configured" if not missing else "set " + ", ".join(missing)}
