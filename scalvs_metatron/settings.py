"""Persisted product settings.

Geo routing is off unless the saved toggle, the process environment, or a
one-shot flag turns it on. The saved value lives in a JSON settings file.
"""

from __future__ import annotations

import json
import os
from pathlib import Path

from scalvs_metatron.paths import settings_path

ENV_GEO_ENABLED = "INFINITUM_GEO_ENABLED"
_TRUTHY = {"1", "true", "yes", "on"}
_FALSY = {"0", "false", "no", "off"}


class SettingsError(ValueError):
    """The settings file or INFINITUM_GEO_ENABLED cannot be used."""


def env_geo_override() -> bool | None:
    """Return the process override, or None when the variable is unset.

    An empty value is treated as unset so a blank export keeps the default.
    """
    if ENV_GEO_ENABLED not in os.environ:
        return None
    raw = os.environ.get(ENV_GEO_ENABLED, "")
    if raw.strip() == "":
        return None
    value = raw.strip().lower()
    if value in _TRUTHY:
        return True
    if value in _FALSY:
        return False
    raise SettingsError(
        f"{ENV_GEO_ENABLED} must be on or off (got {raw!r})"
    )


def read_settings(path: Path | str | None = None) -> dict:
    """Return the raw settings object. Missing file yields an empty object."""
    target = settings_path(path)
    if not target.is_file():
        return {}
    try:
        data = json.loads(target.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise SettingsError(f"settings file is not valid JSON: {target}") from exc
    if not isinstance(data, dict):
        raise SettingsError(f"settings file must be a JSON object: {target}")
    return data


def saved_geo_routing(path: Path | str | None = None) -> bool:
    """Return the persisted geo-routing toggle. Missing key means off."""
    data = read_settings(path)
    if "geo_routing" not in data:
        return False
    value = data["geo_routing"]
    if not isinstance(value, bool):
        raise SettingsError("geo_routing must be a JSON boolean")
    return value


def geo_routing_source(
    *,
    config_path: Path | str | None = None,
    flag: bool | None = None,
) -> str:
    """Name the control that decides whether geo routing is effective."""
    if flag is not None:
        return "flag"
    if env_geo_override() is not None:
        return "environment"
    target = settings_path(config_path)
    if target.is_file() and "geo_routing" in read_settings(target):
        return "config"
    return "default"


def is_geo_enabled(
    *,
    config_path: Path | str | None = None,
    flag: bool | None = None,
) -> bool:
    """Effective geo-routing switch. Default is off.

    Precedence, highest first: process flag, INFINITUM_GEO_ENABLED, the
    persisted ``geo_routing`` value, then off.
    """
    if flag is not None:
        return bool(flag)
    override = env_geo_override()
    if override is not None:
        return override
    return saved_geo_routing(config_path)


def set_geo_routing(enabled: bool, path: Path | str | None = None) -> Path:
    """Persist the geo-routing toggle and leave other keys in place."""
    if not isinstance(enabled, bool):
        raise SettingsError("geo_routing must be a boolean")
    target = settings_path(path)
    data = read_settings(target)
    data["geo_routing"] = enabled
    target.parent.mkdir(parents=True, exist_ok=True)
    payload = json.dumps(data, indent=2, sort_keys=True) + "\n"
    temporary = target.with_name(target.name + ".tmp")
    temporary.write_text(payload, encoding="utf-8")
    os.chmod(temporary, 0o600)
    temporary.replace(target)
    os.chmod(target, 0o600)
    return target


def describe_geo_routing(
    *,
    config_path: Path | str | None = None,
    flag: bool | None = None,
) -> dict[str, str | bool]:
    """User-visible toggle state."""
    target = settings_path(config_path)
    return {
        "geo_routing": saved_geo_routing(target),
        "effective": is_geo_enabled(config_path=target, flag=flag),
        "source": geo_routing_source(config_path=target, flag=flag),
        "config": str(target),
    }
