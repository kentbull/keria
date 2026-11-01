from keri.app import agenting


def test_http_messenger_exposes_terminal_hio_result():
    marker = ConnectionResetError("transport failed")
    messenger = agenting.HTTPMessenger(
        hab=None,
        wit="witness",
        url="http://127.0.0.1:1",
    )
    response = messenger.responseDo(tymth=lambda: 0.0)
    assert next(response) == 0.0

    messenger.posted = 1
    messenger.client.connector.error = marker
    messenger.client.connector.txCutoff = True
    assert next(response) is None

    assert messenger.error is marker
    assert messenger.txCutoff
    assert not messenger.cutoff
    assert not messenger.idle

    response.close()
    messenger.client.close()
