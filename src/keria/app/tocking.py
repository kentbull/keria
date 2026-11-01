# -*- encoding: utf-8 -*-
"""Centralized KERIA and KERIpy scheduler configuration."""

import logging
import os
from collections.abc import Mapping
from dataclasses import dataclass

from keri import kering
from keri.app import tocking as keritocking

logger = logging.getLogger(__name__)


KERIA_INITER_TOCK_KEY = "KERIA_INITER_TOCK"
KERIA_QUERIER_TOCK_KEY = "KERIA_QUERIER_TOCK"
KERIA_ESCROWER_TOCK_KEY = "KERIA_ESCROWER_TOCK"
KERIA_PARSER_TOCK_KEY = "KERIA_PARSER_TOCK"
KERIA_WITNESSER_TOCK_KEY = "KERIA_WITNESSER_TOCK"
KERIA_DELEGATOR_TOCK_KEY = "KERIA_DELEGATOR_TOCK"
KERIA_EXCHANGE_SENDER_TOCK_KEY = "KERIA_EXCHANGE_SENDER_TOCK"
KERIA_GRANTER_TOCK_KEY = "KERIA_GRANTER_TOCK"
KERIA_ADMITTER_TOCK_KEY = "KERIA_ADMITTER_TOCK"
KERIA_GROUP_REQUESTER_TOCK_KEY = "KERIA_GROUP_REQUESTER_TOCK"
KERIA_SEEKER_TOCK_KEY = "KERIA_SEEKER_TOCK"
KERIA_EXCHANGE_CUE_TOCK_KEY = "KERIA_EXCHANGE_CUE_TOCK"


TOCKS = {
    "initer": keritocking.Tock(KERIA_INITER_TOCK_KEY),
    "querier": keritocking.Tock(KERIA_QUERIER_TOCK_KEY),
    "escrower": keritocking.Tock(KERIA_ESCROWER_TOCK_KEY),
    "parser": keritocking.Tock(KERIA_PARSER_TOCK_KEY),
    "witnesser": keritocking.Tock(KERIA_WITNESSER_TOCK_KEY),
    "delegator": keritocking.Tock(KERIA_DELEGATOR_TOCK_KEY),
    "exchangeSender": keritocking.Tock(KERIA_EXCHANGE_SENDER_TOCK_KEY),
    "granter": keritocking.Tock(KERIA_GRANTER_TOCK_KEY),
    "admitter": keritocking.Tock(KERIA_ADMITTER_TOCK_KEY),
    "groupRequester": keritocking.Tock(KERIA_GROUP_REQUESTER_TOCK_KEY),
    "seeker": keritocking.Tock(KERIA_SEEKER_TOCK_KEY),
    "exchangecue": keritocking.Tock(KERIA_EXCHANGE_CUE_TOCK_KEY),
}


@dataclass
class TockConfiguration:
    """Resolved direct-KERIpy and Signify scheduler dictionaries."""

    keri: dict
    signify: dict


_warnedLegacy = False


def _resolveSignify(config, environ, *, path="tocks.signify"):
    try:
        return keritocking.resolveTocks(
            config,
            definitions=TOCKS,
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
    global _warnedLegacy
    if _warnedLegacy:
        return

    conflicts = sorted(key for key in legacy if key in nested)
    detail = ""
    if conflicts:
        detail = f"; nested values win for: {', '.join(conflicts)}"
    logger.warning(
        "Deprecated flat Signify tock configuration; move these settings under "
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

    # Validate both legacy and nested values even when one shadows the other.
    if legacy:
        _resolveSignify(legacy, environ={}, path="tocks")
        _warnLegacy(legacy, nested)
    _resolveSignify(nested, environ={})

    merged = dict(legacy)
    merged.update(nested)

    return TockConfiguration(
        keri=keritocking.resolveTocks(direct, environ=environ),
        signify=_resolveSignify(merged, environ=environ),
    )


def resetWarningState():
    """Clear migration-warning state for isolated tests."""

    global _warnedLegacy
    _warnedLegacy = False
