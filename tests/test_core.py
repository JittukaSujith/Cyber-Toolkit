"""Offline unit tests for the pure logic in each tool.  Run:  python -m unittest discover -s tests -v"""
import datetime as dt
import pathlib
import sys
import tempfile
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]
for sub in [ROOT, *[p for p in ROOT.iterdir() if p.is_dir() and not p.name.startswith((".", "_", "tests"))]]:
    sys.path.insert(0, str(sub))

from common import validation as v  # noqa: E402
import password_checker, spoof_check, url_scanner, header_checker, tls_analyzer  # noqa: E402
import ip_info, hash_checker, cookie_audit, redirect_tester, cipher_tools, aes_tool, jwt_inspector  # noqa: E402
import device_scanner_gui, web_scanner  # noqa: E402


class TestValidation(unittest.TestCase):
    def test_ports(self):
        self.assertEqual(v.parse_port_spec("80,22,20-22"), [20, 21, 22, 80])
        for bad in ("0", "70000", "abc", "10-5", ""):
            with self.assertRaises(ValueError):
                v.parse_port_spec(bad)

    def test_hosts_and_urls(self):
        self.assertEqual(v.validate_host("Example.COM"), "example.com")
        with self.assertRaises(ValueError):
            v.validate_host("bad host!")
        with self.assertRaises(ValueError):
            v.validate_domain("localhost")
        self.assertEqual(v.normalize_url("example.com"), "https://example.com")
        with self.assertRaises(ValueError):
            v.normalize_url("ftp://example.com")


class TestPassword(unittest.TestCase):
    def test_common_and_strong(self):
        self.assertEqual(password_checker.analyze("P@ssw0rd")["score"], 0)
        self.assertGreaterEqual(password_checker.analyze("x7#Lq!9vR2$mZp")["score"], 3)
        self.assertTrue(password_checker.has_sequence("abcd1"))


class TestEmail(unittest.TestCase):
    def test_spf_dmarc(self):
        self.assertEqual(spoof_check.parse_spf("v=spf1 include:a.com -all")["all"], "-")
        sev = [s for s, _ in spoof_check.analyze_spf(["v=spf1 +all"])]
        self.assertIn("HIGH", sev)
        self.assertEqual(spoof_check.parse_dmarc("v=DMARC1; p=reject; pct=100")["p"], "reject")
        self.assertIn("HIGH", [s for s, _ in spoof_check.analyze_dmarc([])])


class TestUrlScanner(unittest.TestCase):
    def test_scores(self):
        self.assertGreaterEqual(url_scanner.analyze_url("http://paypal.secure-login.verify.xyz/update")[0], 60)
        self.assertEqual(url_scanner.analyze_url("https://www.python.org/")[0], 0)
        self.assertTrue(url_scanner.defang("https://a.com").startswith("hxxps://a[.]com"))


class TestHeaders(unittest.TestCase):
    def test_grade(self):
        good = {"Strict-Transport-Security": "max-age=63072000", "Content-Security-Policy": "default-src 'self'",
                "X-Frame-Options": "DENY", "X-Content-Type-Options": "nosniff",
                "Referrer-Policy": "no-referrer", "Permissions-Policy": "geolocation=()"}
        self.assertEqual(header_checker.grade(header_checker.evaluate_headers(good))[1], "A")
        self.assertEqual(header_checker.grade(header_checker.evaluate_headers({}))[1], "F")


class TestTls(unittest.TestCase):
    def test_self_signed_detection(self):
        from cryptography import x509
        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.hazmat.primitives.asymmetric import rsa
        from cryptography.x509.oid import NameOID
        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "test.local")])
        now = dt.datetime.now(dt.timezone.utc)
        cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(key.public_key())
                .serial_number(1).not_valid_before(now - dt.timedelta(days=400)).not_valid_after(now - dt.timedelta(days=5))
                .add_extension(x509.SubjectAlternativeName([x509.DNSName("test.local")]), False)
                .sign(key, hashes.SHA256()))
        info = tls_analyzer.analyze(cert.public_bytes(serialization.Encoding.DER), "test.local")
        msgs = " ".join(m for _, m in info["issues"])
        self.assertIn("EXPIRED", msgs)
        self.assertIn("Self-signed", msgs)
        self.assertTrue(tls_analyzer.hostname_matches("www.a.com", ["*.a.com"]))
        self.assertFalse(tls_analyzer.hostname_matches("x.y.a.com", ["*.a.com"]))


class TestIpAndHash(unittest.TestCase):
    def test_ip(self):
        self.assertIn("Private", ip_info.classify("192.168.0.1")["type"])
        self.assertIn("Public", ip_info.classify("1.1.1.1")["type"])

    def test_hash(self):
        digest = hash_checker.hash_text("hello")
        self.assertTrue(hash_checker.matches(digest, digest.upper()))
        self.assertFalse(hash_checker.matches(digest, "0" * 64))
        with tempfile.NamedTemporaryFile(delete=False) as f:
            f.write(b"hello")
        self.assertEqual(hash_checker.hash_file(f.name), digest)
        with self.assertRaises(ValueError):
            hash_checker.clean_expected("xyz")


class TestWebBits(unittest.TestCase):
    def test_cookie(self):
        r = cookie_audit.audit_set_cookie("sessionid=1; Path=/", True)
        self.assertTrue(any("HttpOnly" in m for _, m in r["issues"]))
        self.assertEqual(cookie_audit.audit_set_cookie("__Host-s=1; Secure; HttpOnly; Path=/; SameSite=Lax", True)["issues"], [])

    def test_redirect_chain(self):
        notes = redirect_tester.analyze_chain([{"url": "https://a.com", "status": 301, "location": "http://a.com/"}])
        self.assertTrue(any("downgrade" in n for n in notes))

    def test_scanner_parser(self):
        p = web_scanner.PageParser()
        p.feed('<a href="/x">x</a><form method="post" action="/l"><input name="pw" type="password"></form>')
        self.assertEqual(p.links, ["/x"])
        self.assertEqual(p.forms[0]["inputs"][0]["type"], "password")

    def test_device_guess(self):
        self.assertEqual(device_scanner_gui.guess_device({9100}), "Printer")
        with self.assertRaises(ValueError):
            device_scanner_gui.parse_targets("8.8.8.0/24")  # public range refused


class TestCrypto(unittest.TestCase):
    def test_classic(self):
        msg = "The quick brown fox jumps over the lazy dog"
        self.assertEqual(cipher_tools.caesar(cipher_tools.caesar(msg, 5), -5), msg)
        self.assertEqual(cipher_tools.crack_caesar(cipher_tools.caesar(msg, 11))[0][0], 11)
        self.assertEqual(cipher_tools.vigenere(cipher_tools.vigenere("Attack at dawn", "LEMON"), "LEMON", True), "Attack at dawn")
        self.assertEqual(cipher_tools.xor_bytes(cipher_tools.xor_bytes(b"hi", b"k"), b"k"), b"hi")

    def test_aes(self):
        token = aes_tool.encrypt_text("pw", "secret message")
        self.assertEqual(aes_tool.decrypt_text("pw", token), "secret message")
        with self.assertRaises(ValueError):
            aes_tool.decrypt_text("wrong", token)
        blob = bytearray(aes_tool.encrypt_bytes("pw", b"data"))
        blob[-1] ^= 1  # tamper
        with self.assertRaises(ValueError):
            aes_tool.decrypt_bytes("pw", bytes(blob))

    def test_jwt(self):
        token = jwt_inspector.make_demo_token()
        self.assertTrue(jwt_inspector.verify_hmac(token, "secret"))
        self.assertFalse(jwt_inspector.verify_hmac(token, "nope"))
        self.assertEqual(jwt_inspector.check_weak_secrets(token), "secret")
        h, p, s = jwt_inspector.decode_token(token)
        self.assertTrue(any("exp" in m for _, m in jwt_inspector.analyze(h, p, s)))
        none_hdr = {"alg": "none"}
        self.assertEqual(jwt_inspector.analyze(none_hdr, {}, "")[0][0], "HIGH")
        with self.assertRaises(ValueError):
            jwt_inspector.decode_token("not.a.jwt")


if __name__ == "__main__":
    unittest.main()
