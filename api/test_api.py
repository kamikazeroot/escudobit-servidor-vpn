"""Pruebas de la API de alta. Se ejecutan con: python -m unittest test_api (sin servidor real)."""

import base64
import json
import os
import sys
import tempfile
import threading
import time
import unittest
import urllib.error
import urllib.request

sys.path.insert(0, os.path.dirname(__file__))
import escudobit_api as api  # noqa: E402

KEY = base64.b64encode(bytes(range(32))).decode()
KEY2 = base64.b64encode(bytes(range(1, 33))).decode()


class Rules(unittest.TestCase):

    def test_public_key(self):
        self.assertTrue(api.valid_public_key(KEY))
        self.assertFalse(api.valid_public_key("corta"))
        self.assertFalse(api.valid_public_key("!" * 44))
        self.assertFalse(api.valid_public_key(None))

    def test_addresses(self):
        self.assertEqual("10.66.0.2", api.next_address("10.66.0.0/16", []))
        self.assertEqual("10.66.0.3", api.next_address("10.66.0.0/16", ["10.66.0.2"]))
        self.assertIsNone(api.next_address("10.66.0.0/30", ["10.66.0.2"]))

    def verdict(self, **over):
        p = {
            "requestDetails": {"nonce": api.nonce_for(KEY), "requestPackageName": "com.escudobit.app",
                               "timestampMillis": str(1_000_000)},
            "appIntegrity": {"appRecognitionVerdict": "PLAY_RECOGNIZED", "packageName": "com.escudobit.app"},
            "deviceIntegrity": {"deviceRecognitionVerdict": ["MEETS_DEVICE_INTEGRITY"]},
        }
        for path, value in over.items():
            section, field = path.split("__")
            p[section][field] = value
        return p

    def test_good_verdict(self):
        self.assertIsNone(api.check_verdict(self.verdict(), api.nonce_for(KEY), "com.escudobit.app", now_ms=1_000_500))

    def test_token_for_another_key_is_rejected(self):
        self.assertEqual("nonce", api.check_verdict(self.verdict(), api.nonce_for(KEY2), "com.escudobit.app", now_ms=1_000_500))

    def test_modified_app_or_rooted_phone(self):
        bad_app = self.verdict(appIntegrity__appRecognitionVerdict="UNEVALUATED")
        self.assertEqual("app", api.check_verdict(bad_app, api.nonce_for(KEY), "com.escudobit.app", now_ms=1_000_500))
        bad_device = self.verdict(deviceIntegrity__deviceRecognitionVerdict=[])
        self.assertEqual("dispositivo", api.check_verdict(bad_device, api.nonce_for(KEY), "com.escudobit.app", now_ms=1_000_500))

    def test_unpublished_app_only_when_allowed(self):
        v = self.verdict(appIntegrity__appRecognitionVerdict="UNRECOGNIZED_VERSION")
        self.assertEqual("app", api.check_verdict(v, api.nonce_for(KEY), "com.escudobit.app", now_ms=1_000_500))
        self.assertIsNone(api.check_verdict(v, api.nonce_for(KEY), "com.escudobit.app", allow_unrecognized=True, now_ms=1_000_500))

    def test_old_token(self):
        self.assertEqual("caducado", api.check_verdict(self.verdict(), api.nonce_for(KEY), "com.escudobit.app", now_ms=1_000_000 + 11 * 60_000))

    def test_rate_limit(self):
        r = api.RateLimiter(2)
        self.assertTrue(r.allow("1.1.1.1", now=0))
        self.assertTrue(r.allow("1.1.1.1", now=1))
        self.assertFalse(r.allow("1.1.1.1", now=2))
        self.assertTrue(r.allow("2.2.2.2", now=2))
        self.assertTrue(r.allow("1.1.1.1", now=3700))


class Http(unittest.TestCase):
    """Arranca la API de verdad (con un 'wg' falso) y le hace peticiones."""

    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.mkdtemp()
        fake_wg = os.path.join(cls.tmp, "wg_falso.py")
        cls.log = os.path.join(cls.tmp, "wg.log")
        with open(fake_wg, "w") as f:
            f.write("import sys\nopen(%r, 'a').write(' '.join(sys.argv[1:]) + '\\n')\n" % cls.log)
        os.environ.update({
            "WG_CMD": sys.executable, "INTEGRITY": "off", "SERVER_PUBLIC_KEY": KEY2, "ENDPOINT": "1.2.3.4:51820",
            "DB": os.path.join(cls.tmp, "peers.json"), "RATE_PER_HOUR": "3",
        })
        # El 'wg' falso es "python wg_falso.py ...": se mete el script como primer argumento.
        api.wg_add_peer = lambda key, addr, _f=fake_wg: __import__("subprocess").run(
            [sys.executable, _f, "set", "wg0", "peer", key, "allowed-ips", addr + "/32"], check=True)
        api.DB = api.PeerDb(os.environ["DB"])
        api.LIMITER = api.RateLimiter(3)
        cls.server = api.ThreadingHTTPServer(("127.0.0.1", 0), api.Handler)
        cls.port = cls.server.server_address[1]
        threading.Thread(target=cls.server.serve_forever, daemon=True).start()

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()

    def post(self, data):
        req = urllib.request.Request(f"http://127.0.0.1:{self.port}/v1/alta", data=json.dumps(data).encode(),
                                     headers={"Content-Type": "application/json"})
        try:
            with urllib.request.urlopen(req, timeout=5) as r:
                return r.status, json.load(r)
        except urllib.error.HTTPError as e:
            return e.code, json.load(e)

    def test_enrollment(self):
        status, body = self.post({"publicKey": KEY})
        self.assertEqual(200, status)
        self.assertEqual("10.66.0.2/32", body["address"])
        self.assertEqual(KEY2, body["serverPublicKey"])
        self.assertEqual("1.2.3.4:51820", body["endpoint"])
        # La misma llave otra vez: misma dirección, sin duplicar en WireGuard.
        status, again = self.post({"publicKey": KEY})
        self.assertEqual("10.66.0.2/32", again["address"])
        with open(self.log) as f:
            self.assertEqual(1, f.read().count(KEY))
        # Se guarda en disco.
        with open(os.environ["DB"]) as f:
            self.assertIn(KEY, json.load(f))

    def test_bad_key(self):
        status, _ = self.post({"publicKey": "no-es-una-llave"})
        self.assertEqual(400, status)


if __name__ == "__main__":
    unittest.main()
