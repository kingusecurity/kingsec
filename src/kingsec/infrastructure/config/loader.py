"""Loading and startup wiring for configuration.

This module turns "construct the Settings object" into a safe, ergonomic
operation with two responsibilities:

  1. ``load_settings`` — build the config and, if it is invalid, fail fast with
     a single, readable ``ConfigError`` instead of a raw pydantic traceback.
  2. ``get_settings`` — a cached accessor that the composition root (Bootstrap /
     DI, both out of scope for 2.1) will call exactly once at startup.

Secret safety
    ``_format_validation_error`` builds its message from the error *location*
    and *message* only. It deliberately never includes pydantic's ``input``
    field, because that field contains the offending raw value — which, for the
    API key, would be the secret itself. This is how a validation failure is
    prevented from leaking a secret into a crash log.
"""

from __future__ import annotations

from functools import lru_cache
from pathlib import Path

from pydantic import ValidationError

from .errors import ConfigError
from .settings import Settings


def _format_validation_error(exc: ValidationError) -> str:
    """Render a pydantic ``ValidationError`` as an operator-friendly message.

    We reconstruct the environment-variable name for each bad field so the
    operator knows exactly which knob to turn, and we omit the raw input value
    so secrets are never echoed.
    """
    lines = ["KingSec configuration is invalid. Fix the following and restart:"]
    # include_url=False drops the "for further information visit ..." links that
    # add noise to a startup log.
    for error in exc.errors(include_url=False):
        location = ".".join(str(part) for part in error["loc"])
        env_name = "KINGSEC_" + "__".join(str(part) for part in error["loc"]).upper()
        # error["msg"] is the human message; error["input"] is intentionally
        # NOT included (it may hold a secret).
        lines.append(f"  - {location}  (env: {env_name}): {error['msg']}")
    return "\n".join(lines)


def load_settings(env_file: str | Path | None = None) -> Settings:
    """Build and validate the configuration, or fail fast.

    Parameters
    ----------
    env_file:
        Optional path to a ``.env`` file. When ``None`` the default from
        ``Settings.model_config`` is used. This parameter exists mainly for
        tests, which point it at a temporary file so they never depend on a
        ``.env`` in the working directory.

    Returns:
    -------
    Settings
        A frozen, fully validated configuration tree.

    Raises:
    ------
    ConfigError
        If any value is missing or invalid. The message lists every problem at
        once so an operator can fix them in a single pass.
    """
    try:
        if env_file is not None:
            # ``_env_file`` is pydantic-settings' documented per-instance
            # override for the .env path.
            return Settings(_env_file=env_file)  # type: ignore[call-arg]
        return Settings()
    except ValidationError as exc:
        # Convert the library error into our clear, secret-safe message and drop
        # the noisy original from the message chain (``from None``) while still
        # preserving it as the cause for debuggers (``from exc``).
        raise ConfigError(_format_validation_error(exc)) from exc


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    """Return the process-wide configuration, loading it once on first call.

    This is the seam the composition root will use. It is cached so the app
    reads the environment a single time at startup and every later caller sees
    the same immutable object.

    Boundary reminder: this lives in ``infrastructure``. The domain layer must
    never import it — configuration is handed to domain code as arguments, not
    fetched by it. Wiring that hand-off is Bootstrap/DI's job (out of scope).
    """
    return load_settings()


def reset_settings_cache() -> None:
    """Clear the cached settings.

    Only useful for tests, which construct many different configurations in one
    process and must not see a stale cached instance between cases.
    """
    get_settings.cache_clear()
