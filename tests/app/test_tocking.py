import math

import pytest

from keri import kering
from keri.app import configing

from keria.app import agenting, tocking


EXPECTED_TOCKS = {
    "agency",
    "agent",
    "gracefulShutdown",
    "bootServer",
    "adminServer",
    "httpServer",
    "releaser",
    "initer",
    "querier",
    "escrower",
    "parser",
    "witnesser",
    "delegator",
    "exchangeSender",
    "granter",
    "admitter",
    "groupRequester",
    "seeker",
    "exchangecue",
    "submitter",
}


def test_defines_every_persistent_keria_scheduler_cadence():
    assert set(tocking.TOCKS) == EXPECTED_TOCKS

    resolved = tocking.resolveTocks(environ={})
    assert set(resolved.keria) == EXPECTED_TOCKS
    assert resolved.keria["releaser"] == 60.0
    assert resolved.keria["escrower"] == 1.0
    assert all(
        value == 0.0
        for key, value in resolved.keria.items()
        if key not in {"releaser", "escrower"}
    )


def test_resolves_direct_keripy_and_nested_keria_snapshots():
    resolved = tocking.resolveTocks(
        {
            "tocks": {
                "witnessMsg": 0.002,
                "pollerConnect": 0.007,
                "signify": {"initer": 0.003, "escrower": 0.004},
            }
        },
        environ={},
    )

    assert resolved.keri["witnessMsg"] == 0.002
    assert resolved.keri["pollerConnect"] == 0.007
    assert resolved.keria["initer"] == 0.003
    assert resolved.keria["escrower"] == 0.004
    assert resolved.keria["querier"] == 0.0


def test_every_keria_environment_override():
    config = {"tocks": {"signify": {key: 99.0 for key in tocking.TOCKS}}}
    environ = {
        spec.env: str(index / 1000) for index, spec in enumerate(tocking.TOCKS.values())
    }

    resolved = tocking.resolveTocks(config, environ=environ)

    for index, (key, spec) in enumerate(tocking.TOCKS.items()):
        assert resolved.keria[key] == index / 1000
        assert spec.env.startswith("KERIA_")


@pytest.mark.parametrize(
    "value",
    [True, None, "", "0.5", -0.1, math.nan, math.inf, -math.inf],
)
def test_rejects_invalid_nested_values(value):
    with pytest.raises(kering.ConfigurationError, match=r"tocks\.signify\.escrower"):
        tocking.resolveTocks({"tocks": {"signify": {"escrower": value}}}, environ={})


@pytest.mark.parametrize("value", ["", "nope", "-0.1", "nan", "inf", "-inf"])
def test_rejects_invalid_environment_values(value):
    with pytest.raises(kering.ConfigurationError, match="KERIA_ESCROWER_TOCK"):
        tocking.resolveTocks({}, environ={tocking.TOCKS["escrower"].env: value})


def test_rejects_unknown_direct_and_keria_keys():
    with pytest.raises(kering.ConfigurationError, match="unknownDirect"):
        tocking.resolveTocks({"tocks": {"unknownDirect": 1.0}}, environ={})

    with pytest.raises(kering.ConfigurationError, match="exchangeCue"):
        tocking.resolveTocks({"tocks": {"signify": {"exchangeCue": 1.0}}}, environ={})


def test_preserves_released_exchangecue_spelling():
    resolved = tocking.resolveTocks(
        {"tocks": {"signify": {"exchangecue": 0.0125}}}, environ={}
    )
    assert resolved.keria["exchangecue"] == 0.0125


def test_flat_migration_nested_precedence_and_warning_deduplication(monkeypatch):
    tocking.resetWarningState()
    warnings = []
    monkeypatch.setattr(
        tocking.logger,
        "warning",
        lambda message, *args: warnings.append(message % args),
    )
    config = {
        "tocks": {
            "initer": 0.25,
            "escrower": 0.5,
            "signify": {"escrower": 0.75},
        }
    }

    first = tocking.resolveTocks(config, environ={})
    second = tocking.resolveTocks(config, environ={})

    assert first.keria["initer"] == 0.25
    assert first.keria["escrower"] == 0.75
    assert second.keria == first.keria
    assert len(warnings) == 1
    assert "tocks.signify" in warnings[0]
    assert "escrower" in warnings[0]


def test_invalid_configuration_aborts_agency_startup_without_agents():
    with configing.openCF(name="invalid-keria-tocks", temp=True) as cf:
        cf.put({"tocks": {"signify": {"escrower": math.nan}}})

        with pytest.raises(
            kering.ConfigurationError, match=r"tocks\.signify\.escrower"
        ):
            agenting.Agency(name="invalid", bran=None, temp=True, cf=cf)
