"""Local-only chat client for an Ollama-hosted pretrained language model."""

import requests
from urllib.parse import urlparse

from config.settings import SettingsManager


DEFAULT_BASE_URL = "http://127.0.0.1:11434"
DEFAULT_MODEL = "qwen3:4b"


class OllamaUnavailable(RuntimeError):
    pass


class OllamaClient:
    def __init__(self, base_url=None, timeout=4):
        configured = base_url or SettingsManager.get("ai_model_base_url") or DEFAULT_BASE_URL
        self.base_url = configured.strip().rstrip("/")
        self.timeout = timeout
        parsed = urlparse(self.base_url)
        if parsed.scheme != "http" or parsed.hostname not in {"127.0.0.1", "localhost", "::1"}:
            raise ValueError("HavocGuard only sends endpoint context to an Ollama service on this computer.")

    def list_models(self):
        try:
            response = requests.get(f"{self.base_url}/api/tags", timeout=self.timeout)
            response.raise_for_status()
            models = response.json().get("models", [])
            return [item.get("name", "") for item in models if item.get("name") and "cloud" not in item.get("name", "").casefold()]
        except (requests.RequestException, ValueError) as exc:
            raise OllamaUnavailable(
                "Ollama is not responding on this computer. Install and start Ollama, then download a local model such as `ollama pull qwen3:4b`."
            ) from exc

    def chat(self, messages, model=None):
        model = (model or SettingsManager.get("ai_model") or DEFAULT_MODEL).strip()
        if not model or "cloud" in model.casefold():
            raise ValueError("Select a local Ollama model. Cloud models are disabled so endpoint data stays on this computer.")
        payload = {
            "model": model,
            "messages": messages,
            "stream": False,
            # Release Qwen from GPU/system memory shortly after an Analyst
            # request so the endpoint stays light when the model is idle.
            "keep_alive": "2m",
            "options": {"temperature": 0.2, "num_ctx": 8192},
        }
        try:
            response = requests.post(f"{self.base_url}/api/chat", json=payload, timeout=180)
            if response.status_code == 404:
                raise OllamaUnavailable(f"Model `{model}` is not installed locally. Run `ollama pull {model}` and try again.")
            response.raise_for_status()
            answer = response.json().get("message", {}).get("content", "").strip()
            if not answer:
                raise OllamaUnavailable("The local model returned an empty response. Try again or select another model.")
            return answer
        except requests.Timeout as exc:
            raise OllamaUnavailable("The local model took too long to answer. Try a smaller model or ask a shorter question.") from exc
        except requests.RequestException as exc:
            raise OllamaUnavailable("Could not reach the local Ollama model. Check that Ollama is running and retry.") from exc
