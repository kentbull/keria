import unittest
import ssl

from hio.core import tcp
from falcon import falcon
from falcon.testing import helpers
from falcon.http_status import HTTPStatus
from keria.core import httping
from keria.core.httping import HandleCORS


def test_create_http_server_sets_timeout_on_tls_servant(monkeypatch):
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    monkeypatch.setattr(tcp.serving, "initServerContext", lambda **kwa: context)
    app = falcon.App()

    server = httping.createHttpServer(
        3901,
        app,
        keypath="keypath",
        certpath="certpath",
        cafilepath="cafilepath",
    )
    assert isinstance(server.servant, tcp.ServerTls)
    assert server.servant.tymeout == 30.0

    server = httping.createHttpServer(
        3901,
        app,
        keypath="keypath",
        certpath="certpath",
        cafilepath="cafilepath",
        tymeout=45.0,
    )
    assert server.servant.tymeout == 45.0


class HandleCORSTest(unittest.TestCase):
    def setUp(self):
        self.cors_handler = HandleCORS()

    def test_process_request(self):
        req = helpers.create_req(method="GET")
        resp = falcon.Response()

        self.cors_handler.process_request(req, resp)

        self.assertEqual(resp.get_header("Access-Control-Allow-Origin"), "*")
        self.assertEqual(resp.get_header("Access-Control-Allow-Methods"), "*")
        self.assertEqual(resp.get_header("Access-Control-Allow-Headers"), "*")
        self.assertEqual(resp.get_header("Access-Control-Max-Age"), "1728000")

    def test_process_request_options_method(self):
        req = helpers.create_req(method="OPTIONS")
        resp = falcon.Response()

        with self.assertRaises(HTTPStatus) as cm:
            self.cors_handler.process_request(req, resp)

        self.assertEqual(cm.exception.status, falcon.HTTP_200)
