"""
provider.py — AI provider resolution for BugTraceAI-API (Phase 5 / Apex analysis).

The active provider is chosen from config/apex.json (or the APEX_PROVIDER env var)
and its definition is loaded from config/providers/<id>.json.

Three provider kinds are supported:
  - "ollama"    → local Ollama server     (POST /api/generate, {prompt, options})
  - "openai"    → OpenAI-compatible API   (POST /chat/completions, {messages, ...})
                  covers OpenRouter, Z.ai, and any future OpenAI-style endpoint.
  - "anthropic" → native Anthropic Messages API (POST /v1/messages, x-api-key auth)

Adding a new external provider = drop a new config/providers/<id>.json file.
No code change required.
"""

import json
import logging
import os
import tempfile
from dataclasses import dataclass, field
from pathlib import Path
from threading import Lock
from typing import Any

logger = logging.getLogger("bugtrace-api.lib.provider")

CONFIG_DIR = Path(__file__).resolve().parent.parent / "config"
APEX_CONFIG_FILE = CONFIG_DIR / "apex.json"
PROVIDERS_DIR = CONFIG_DIR / "providers"
SECRETS_FILE = Path(
    os.environ.get("PROVIDER_SECRETS_FILE")
    or (CONFIG_DIR / "provider_secrets.json")
)
_CONFIG_LOCK = Lock()


def _env_bool(name: str, default: bool) -> bool:
    val = os.environ.get(name)
    if val is None:
        return default
    return val.strip().lower() in ("1", "true", "yes", "on")


def _load_json(path: Path) -> dict[str, Any]:
    try:
        return json.loads(path.read_text())
    except Exception as e:
        logger.warning(f"[provider] Could not read {path}: {e}")
        return {}


def _load_provider_secrets() -> dict[str, str]:
    """Load UI-managed provider keys without ever logging their values."""
    if not SECRETS_FILE.exists():
        return {}
    raw = _load_json(SECRETS_FILE)
    return {str(key): str(value) for key, value in raw.items() if isinstance(value, str) and value}


def _write_json_atomic(path: Path, payload: dict[str, Any]) -> None:
    """Persist a small configuration file atomically and restrict its mode."""
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp_name = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            json.dump(payload, handle, indent=2)
            handle.write("\n")
        os.chmod(tmp_name, 0o600)
        os.replace(tmp_name, path)
        try:
            os.chmod(path, 0o600)
        except OSError:
            pass
    finally:
        try:
            os.unlink(tmp_name)
        except FileNotFoundError:
            pass


def list_provider_profiles() -> list[dict[str, Any]]:
    """Return provider metadata safe for the WEB configuration screen."""
    profiles: list[dict[str, Any]] = []
    if not PROVIDERS_DIR.exists():
        return profiles
    secrets = _load_provider_secrets()
    for path in sorted(PROVIDERS_DIR.glob("*.json")):
        raw = _load_json(path)
        if not raw.get("id"):
            continue
        provider_id = str(raw["id"])
        key_env = str(raw.get("api_key_env") or "")
        configured = bool(secrets.get(provider_id) or (os.environ.get(key_env) if key_env else ""))
        models = provider_models(provider_id, raw)
        model_chain = provider_model_chain(provider_id, raw)
        profiles.append({
            "id": provider_id,
            "name": raw.get("name", provider_id),
            "kind": raw.get("kind", "ollama"),
            "base_url": raw.get("base_url", ""),
            "model": provider_model(provider_id, raw),
            "model_chain": model_chain,
            "models": models,
            "api_key_configured": configured,
            "api_key_env": key_env or None,
            "api_key_hint": raw.get("api_key_hint", ""),
            "recommended": bool(raw.get("recommended", provider_id == "openrouter")),
            "features": raw.get("features", {}),
        })
    return profiles


def get_provider_profile(provider_id: str) -> dict[str, Any] | None:
    """Return one provider profile, excluding secrets."""
    provider_id = provider_id.strip()
    raw = _load_json(PROVIDERS_DIR / f"{provider_id}.json")
    if not raw:
        return None
    return next((profile for profile in list_provider_profiles() if profile["id"] == provider_id), None)


def active_provider_id() -> str:
    """Resolve the configured active provider id (including env overrides)."""
    return str(_apex_config().get("active_provider", "local"))


def set_active_provider(provider_id: str) -> dict[str, Any]:
    """Persist the active provider in apex.json, unless env explicitly pins it."""
    provider_id = provider_id.strip()
    if not get_provider_profile(provider_id):
        raise ValueError(f"Provider '{provider_id}' not found")
    env_provider = os.environ.get("APEX_PROVIDER", "").strip()
    if env_provider:
        raise RuntimeError("APEX_PROVIDER is fixed by the API runtime environment")
    with _CONFIG_LOCK:
        cfg = _load_json(APEX_CONFIG_FILE)
        cfg["active_provider"] = provider_id
        _write_json_atomic(APEX_CONFIG_FILE, cfg)
    return cfg


def set_provider_api_key(provider_id: str, api_key: str | None) -> bool:
    """Store or remove a provider key in the API config volume.

    Environment keys remain a fallback when no UI-managed key exists. The key
    itself is never returned by any helper or included in log messages.
    """
    profile = get_provider_profile(provider_id)
    if not profile:
        raise ValueError(f"Provider '{provider_id}' not found")
    if not profile.get("api_key_env"):
        if api_key:
            raise ValueError("Provider does not accept an API key")
        return False
    with _CONFIG_LOCK:
        secrets = _load_provider_secrets()
        if api_key and api_key.strip():
            secrets[provider_id] = api_key.strip()
        else:
            secrets.pop(provider_id, None)
        if secrets:
            _write_json_atomic(SECRETS_FILE, secrets)
        elif SECRETS_FILE.exists():
            try:
                SECRETS_FILE.unlink()
            except OSError:
                pass
    return bool(api_key and api_key.strip())


def provider_api_key(provider_id: str, raw: dict[str, Any] | None = None) -> str | None:
    """Resolve a provider key, preferring an explicit UI-managed key."""
    profile = raw or _load_json(PROVIDERS_DIR / f"{provider_id}.json")
    stored = _load_provider_secrets().get(provider_id)
    if stored:
        return stored
    key_env = profile.get("api_key_env") if profile else None
    return os.environ.get(key_env) if key_env else None


def provider_models(provider_id: str, raw: dict[str, Any] | None = None) -> list[str]:
    """Return the selectable models for a provider, preserving config order."""
    profile = raw or _load_json(PROVIDERS_DIR / f"{provider_id}.json")
    configured = profile.get("models") if isinstance(profile.get("models"), list) else []
    candidates = [profile.get("model"), *configured, *(profile.get("model_failover") or [])]
    models: list[str] = []
    for value in candidates:
        model = str(value or "").strip()
        if model and model not in models:
            models.append(model)
    return models


def provider_model(provider_id: str, raw: dict[str, Any] | None = None) -> str:
    """Resolve the model used by a provider, including a persisted UI override."""
    profile = raw or _load_json(PROVIDERS_DIR / f"{provider_id}.json")
    env_name = str(profile.get("model_env") or "").strip()
    env_model = os.environ.get(env_name, "").strip() if env_name else ""
    if env_model:
        return env_model

    default = str(profile.get("model") or "").strip()
    configured_models = provider_models(provider_id, profile)
    overrides = _apex_config().get("provider_models", {})
    chains = _apex_config().get("provider_model_chains", {})
    chain = chains.get(provider_id) if isinstance(chains, dict) else None
    if isinstance(chain, list):
        for value in chain:
            candidate = str(value or "").strip()
            if candidate in configured_models:
                return candidate
    override = overrides.get(provider_id) if isinstance(overrides, dict) else None
    if isinstance(override, str) and override.strip() in configured_models:
        return override.strip()
    return default


def provider_model_chain(provider_id: str, raw: dict[str, Any] | None = None) -> list[str]:
    """Resolve the ordered primary + fallback model chain for a provider.

    The WEB API-provider screen can persist up to three models.  Older configs
    only have a single ``provider_models`` override and/or the provider preset's
    static ``model_failover`` list, so those remain valid fallbacks.
    """
    profile = raw or _load_json(PROVIDERS_DIR / f"{provider_id}.json")
    available = set(provider_models(provider_id, profile))
    cfg = _apex_config()
    chains = cfg.get("provider_model_chains", {})
    if isinstance(chains, dict) and isinstance(chains.get(provider_id), list):
        selected = [
            str(value or "").strip()
            for value in chains[provider_id]
            if str(value or "").strip() in available
        ]
        # Preserve order while ignoring accidental duplicates from hand-edited
        # config files.  An invalid/empty override falls back to the preset.
        selected = list(dict.fromkeys(selected))[:3]
        if selected:
            return selected

    primary = provider_model(provider_id, profile)
    fallback = profile.get("model_failover") if isinstance(profile.get("model_failover"), list) else []
    chain = [primary, *[str(value or "").strip() for value in fallback]]
    return list(dict.fromkeys(value for value in chain if value and value in available))[:3]


def set_provider_model(provider_id: str, model: str) -> str:
    """Persist a validated model override for a provider in apex.json."""
    model = model.strip()
    profile = _load_json(PROVIDERS_DIR / f"{provider_id}.json")
    if not profile:
        raise ValueError(f"Provider '{provider_id}' not found")
    if model not in provider_models(provider_id, profile):
        raise ValueError(f"Model '{model}' is not available for provider '{provider_id}'")
    env_name = str(profile.get("model_env") or "").strip()
    if env_name and os.environ.get(env_name, "").strip():
        raise RuntimeError(f"{env_name} is fixed by the API runtime environment")
    with _CONFIG_LOCK:
        cfg = _load_json(APEX_CONFIG_FILE)
        overrides = cfg.get("provider_models")
        if not isinstance(overrides, dict):
            overrides = {}
        overrides[provider_id] = model
        cfg["provider_models"] = overrides
        # Keep a previously customised fallback chain intact when an older
        # client sends only the legacy single-model field.
        chains = cfg.get("provider_model_chains")
        if isinstance(chains, dict) and isinstance(chains.get(provider_id), list):
            existing = [str(value or "").strip() for value in chains[provider_id]]
            chains[provider_id] = list(dict.fromkeys([model, *existing]))[:3]
            cfg["provider_model_chains"] = chains
        _write_json_atomic(APEX_CONFIG_FILE, cfg)
    return model


def set_provider_model_chain(provider_id: str, models: list[str]) -> list[str]:
    """Persist a validated primary + fallback model chain (maximum three)."""
    profile = _load_json(PROVIDERS_DIR / f"{provider_id}.json")
    if not profile:
        raise ValueError(f"Provider '{provider_id}' not found")
    selected = [str(value or "").strip() for value in models if str(value or "").strip()]
    selected = list(dict.fromkeys(selected))
    if not selected:
        raise ValueError("At least one model must be selected")
    if len(selected) > 3:
        raise ValueError("A provider model chain may contain at most three models")
    available = provider_models(provider_id, profile)
    invalid = [model for model in selected if model not in available]
    if invalid:
        raise ValueError(f"Model '{invalid[0]}' is not available for provider '{provider_id}'")

    env_name = str(profile.get("model_env") or "").strip()
    if env_name and os.environ.get(env_name, "").strip():
        raise RuntimeError(f"{env_name} is fixed by the API runtime environment")
    with _CONFIG_LOCK:
        cfg = _load_json(APEX_CONFIG_FILE)
        overrides = cfg.get("provider_models")
        if not isinstance(overrides, dict):
            overrides = {}
        overrides[provider_id] = selected[0]
        cfg["provider_models"] = overrides
        chains = cfg.get("provider_model_chains")
        if not isinstance(chains, dict):
            chains = {}
        chains[provider_id] = selected
        cfg["provider_model_chains"] = chains
        _write_json_atomic(APEX_CONFIG_FILE, cfg)
    return selected


@dataclass
class Provider:
    id: str
    name: str
    kind: str                      # "ollama" | "openai"
    base_url: str
    model: str
    api_key: str | None = None
    options: dict[str, Any] = field(default_factory=dict)
    headers: dict[str, str] = field(default_factory=dict)
    # Ordered fallback models tried (in addition to `model`) when a call fails or
    # the model refuses. Last entry is typically a refusal-resistant model.
    model_failover: list = field(default_factory=list)
    # Global Apex knobs (resolved alongside the provider for convenience)
    enabled: bool = True
    min_severity: str = "medium"

    @property
    def is_local(self) -> bool:
        return self.kind == "ollama"


def _apex_config() -> dict[str, Any]:
    cfg = _load_json(APEX_CONFIG_FILE)
    # Env overrides for the global knobs
    cfg["enabled"] = _env_bool("APEX_ENABLED", cfg.get("enabled", True))
    # An explicitly non-empty env value pins the provider. An empty compose
    # value intentionally leaves the persisted apex.json selection in charge,
    # which allows the WEB provider screen to switch it at runtime.
    env_provider = os.environ.get("APEX_PROVIDER", "").strip()
    cfg["active_provider"] = env_provider or cfg.get("active_provider", "local")
    configured_min = str(cfg.get("min_severity", "medium")).lower()
    env_min = os.environ.get("APEX_MIN_SEVERITY", "").strip().lower()
    # Older API containers shipped with a hard-coded medium threshold in
    # docker-compose.  Once the persisted config opts into info/low coverage,
    # that legacy value must not silently discard the user's setting.
    if env_min and not (env_min == "medium" and configured_min in {"info", "low"}):
        cfg["min_severity"] = env_min
    else:
        cfg["min_severity"] = configured_min
    return cfg


def get_active_provider() -> Provider:
    """Resolve the active provider from config + env overrides.

    Never raises — on any error falls back to a local Ollama provider so the
    pipeline degrades gracefully (Phase 5 simply skips if it can't connect).
    """
    cfg = _apex_config()
    provider_id = cfg["active_provider"]

    raw = _load_json(PROVIDERS_DIR / f"{provider_id}.json")
    if not raw:
        logger.warning(
            f"[provider] Provider '{provider_id}' not found in {PROVIDERS_DIR} — "
            f"falling back to built-in local defaults"
        )
        raw = {"id": "local", "name": "Local (Ollama)", "kind": "ollama",
               "base_url": "http://localhost:11434", "model": "apex-master:latest"}

    kind = raw.get("kind", "ollama")

    # base_url / model may be overridden by a provider-declared env var (back-compat
    # with the legacy OLLAMA_URL / APEX_MODEL container env).
    base_url = raw.get("base_url", "")
    if raw.get("base_url_env"):
        base_url = os.environ.get(raw["base_url_env"], base_url)

    model_chain = provider_model_chain(provider_id, raw)
    model = model_chain[0] if model_chain else provider_model(provider_id, raw)

    api_key = provider_api_key(provider_id, raw)
    if raw.get("api_key_env") and kind == "openai" and not api_key:
        logger.warning(
            f"[provider] Provider '{provider_id}' needs env "
            f"{raw['api_key_env']} but it is not set — Phase 5 will be skipped"
        )

    return Provider(
        id=raw.get("id", provider_id),
        name=raw.get("name", provider_id),
        kind=kind,
        base_url=base_url,
        model=model,
        api_key=api_key,
        options=raw.get("options", {}),
        headers=raw.get("headers", {}),
        model_failover=model_chain[1:],
        enabled=cfg["enabled"],
        min_severity=cfg["min_severity"],
    )
