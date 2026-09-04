# -*- encoding: utf-8 -*-
"""Centralized KERIA and KERIpy scheduler configuration."""

import logging
import os
from collections.abc import Mapping
from dataclasses import dataclass

from keri import kering
from keri.app import tocking as keritocking

logger = logging.getLogger(__name__)


def _tock(env, default=0.0):
    """Create one KERIA scheduler definition."""

    return keritocking.Tock(env=env, default=default)


TOCKS = {
    # Process-level coordination and HTTP service loops.
    "agency": _tock("KERIA_AGENCY_TOCK"),
    "agent": _tock("KERIA_AGENT_TOCK"),
    "gracefulShutdown": _tock("KERIA_GRACEFUL_SHUTDOWN_TOCK"),
    "bootServer": _tock("KERIA_BOOT_SERVER_TOCK"),
    "adminServer": _tock("KERIA_ADMIN_SERVER_TOCK"),
    "httpServer": _tock("KERIA_HTTP_SERVER_TOCK"),
    # Periodic maintenance and escrow scans.
    "releaser": _tock("KERIA_RELEASER_TOCK", 60.0),
    "escrower": _tock("KERIA_ESCROWER_TOCK", 1.0),
    # Active Agent queues and coordination paths.
    "initer": _tock("KERIA_INITER_TOCK"),
    "querier": _tock("KERIA_QUERIER_TOCK"),
    "parser": _tock("KERIA_PARSER_TOCK"),
    "witnesser": _tock("KERIA_WITNESSER_TOCK"),
    "delegator": _tock("KERIA_DELEGATOR_TOCK"),
    "exchangeSender": _tock("KERIA_EXCHANGE_SENDER_TOCK"),
    "granter": _tock("KERIA_GRANTER_TOCK"),
    "admitter": _tock("KERIA_ADMITTER_TOCK"),
    "groupRequester": _tock("KERIA_GROUP_REQUESTER_TOCK"),
    "seeker": _tock("KERIA_SEEKER_TOCK"),
    # Preserve the spelling already exposed by KERIA 0.4.1 configuration.
    "exchangecue": _tock("KERIA_EXCHANGE_CUE_TOCK"),
    "submitter": _tock("KERIA_SUBMITTER_TOCK"),
}


@dataclass(frozen=True)
class TockConfiguration:
    """Resolved direct-KERIpy and KERIA scheduler dictionaries."""

    keri: dict
    keria: dict


_warnedLegacy = False


def _resolveKeria(config, environ, *, path="tocks.signify"):
    """Resolve one KERIA scheduler mapping with path-aware errors."""

    try:
        return keritocking.resolveTocks(
            config,
            tocks=TOCKS,
            aliases={},
            environ=environ,
            reserved=(),
        )
    except kering.ConfigurationError as ex:
        message = str(ex)
        if " for tocks." in message:
            message = message.replace(" for tocks.", f" for {path}.", 1)
        elif message.startswith("Unknown tock configuration key(s):"):
            message = message.replace(
                "Unknown tock configuration key(s):",
                f"Unknown tock configuration key(s) under {path}:",
                1,
            )
        raise kering.ConfigurationError(message) from ex


def _warnLegacy(legacy, nested):
    """Warn once when reading the flat KERIA 0.4.1 layout."""

    global _warnedLegacy
    if _warnedLegacy:
        return

    conflicts = sorted(key for key in legacy if key in nested)
    detail = ""
    if conflicts:
        detail = f"; nested values win for: {', '.join(conflicts)}"
    logger.warning(
        "Deprecated flat KERIA tock configuration; move these settings under "
        "tocks.signify%s",
        detail,
    )
    _warnedLegacy = True


def resolveTocks(config=None, *, environ=None):
    """Resolve and validate all process-level scheduler configuration once."""

    config = {} if config is None else config
    if not isinstance(config, Mapping):
        raise kering.ConfigurationError(
            "Invalid KERIA configuration: expected a mapping"
        )

    environ = os.environ if environ is None else environ
    if not isinstance(environ, Mapping):
        raise kering.ConfigurationError("Invalid tock environment mapping")

    raw = config.get("tocks", {})
    if not isinstance(raw, Mapping):
        raise kering.ConfigurationError(
            f"Invalid tocks configuration: expected mapping, got {type(raw).__name__}"
        )

    nested = raw.get("signify", {})
    if not isinstance(nested, Mapping):
        raise kering.ConfigurationError(
            "Invalid tocks.signify configuration: expected mapping"
        )

    legacy = {key: raw[key] for key in TOCKS if key in raw}
    direct = {key: value for key, value in raw.items() if key not in legacy}

    # Validate legacy and nested values even when nested precedence shadows one.
    if legacy:
        _resolveKeria(legacy, environ={}, path="tocks")
        _warnLegacy(legacy, nested)
    _resolveKeria(nested, environ={})

    merged = dict(legacy)
    merged.update(nested)

    return TockConfiguration(
        keri=keritocking.resolveTocks(direct, environ=environ),
        keria=_resolveKeria(merged, environ=environ),
    )


def resetWarningState():
    """Clear migration-warning state for isolated tests."""

    global _warnedLegacy
    _warnedLegacy = False
