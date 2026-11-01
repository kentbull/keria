import pytest

from keri import kering
from keri.app import configing

from keria.app import agenting, tocking


def test_resolves_direct_keripy_and_nested_signify_snapshots():
    resolved = tocking.resolveTocks(
        {
            "tocks": {
                "witnessMsg": 0.0,
                "pollerIdle": 0.007,
                "signify": {"initer": 0.0, "escrower": 0.001},
            }
        },
        environ={},
    )

    assert isinstance(resolved.keri, dict)
    assert isinstance(resolved.signify, dict)
    assert resolved.keri["witnessMsg"] == 0.0
    assert resolved.keri["pollerIdle"] == 0.007
    assert resolved.signify["initer"] == 0.0
    assert resolved.signify["escrower"] == 0.001
    assert resolved.signify["querier"] == 0.0


def test_every_signify_environment_override():
    config = {
        "tocks": {
            "signify": {key: 99.0 for key in tocking.TOCKS}
        }
    }
    environ = {
        spec.env: str(index / 1000)
        for index, spec in enumerate(tocking.TOCKS.values())
    }

    resolved = tocking.resolveTocks(config, environ=environ)

    for index, (key, spec) in enumerate(tocking.TOCKS.items()):
        assert resolved.signify[key] == index / 1000
        assert spec.env.startswith("KERIA_")
        assert "AGENT" not in spec.env
        assert "SIGNIFY" not in spec.env


@pytest.mark.parametrize(
    "value",
    [True, None, "", "0.5", -0.1, float("nan"), float("inf"), float("-inf")],
)
def test_rejects_invalid_nested_values(value):
    with pytest.raises(kering.ConfigurationError, match=r"tocks\.signify\.escrower"):
        tocking.resolveTocks(
            {"tocks": {"signify": {"escrower": value}}}, environ={}
        )


@pytest.mark.parametrize("value", ["", "nope", "-0.1", "nan", "inf", "-inf"])
def test_rejects_invalid_environment_values(value):
    with pytest.raises(
        kering.ConfigurationError, match=tocking.KERIA_ESCROWER_TOCK_KEY
    ):
        tocking.resolveTocks(
            {}, environ={tocking.KERIA_ESCROWER_TOCK_KEY: value}
        )


def test_rejects_unknown_direct_and_signify_keys():
    with pytest.raises(kering.ConfigurationError, match="unknownDirect"):
        tocking.resolveTocks({"tocks": {"unknownDirect": 1.0}}, environ={})

    with pytest.raises(kering.ConfigurationError, match="exchangeCue"):
        tocking.resolveTocks(
            {"tocks": {"signify": {"exchangeCue": 1.0}}}, environ={}
        )


def test_preserves_released_exchangecue_spelling():
    resolved = tocking.resolveTocks(
        {"tocks": {"signify": {"exchangecue": 0.0125}}}, environ={}
    )
    assert resolved.signify["exchangecue"] == 0.0125


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

    assert first.signify["initer"] == 0.25
    assert first.signify["escrower"] == 0.75
    assert second.signify == first.signify
    assert len(warnings) == 1
    assert "tocks.signify" in warnings[0]
    assert "escrower" in warnings[0]


def test_invalid_configuration_aborts_agency_startup_without_agents():
    with configing.openCF(name="invalid-keria-tocks", temp=True) as cf:
        cf.put({"tocks": {"signify": {"escrower": float("nan")}}})

        with pytest.raises(
            kering.ConfigurationError, match=r"tocks\.signify\.escrower"
        ):
            agenting.Agency(name="invalid", bran=None, temp=True, cf=cf)
