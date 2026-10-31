import json
import unittest

from authentication import encode_json, trusted_setup
from eve import tamper
from protocol import build_init_payload, generate_nonce, pack_message, parse_message

class MessageValidationTests(unittest.TestCase):
    def setUp(self):
        alice, _ = trusted_setup()
        self.message = pack_message(build_init_payload(23, 5, 8, generate_nonce()), alice["signing_key"])

    def assertRejected(self, data, allow_test_fixture=True, expected_type="init"):
        with self.assertRaises(ValueError):
            parse_message(data, expected_type, allow_test_fixture)

    def test_valid_message(self):
        payload, signature = parse_message(self.message, "init", True)
        self.assertEqual(payload["A"], 8)
        self.assertEqual(len(signature), 64)

    def test_deterministic_encoding(self):
        self.assertEqual(encode_json({"p": 23, "g": 5, "A": 8}), b'{"A":8,"g":5,"p":23}')

    def test_wrong_types(self):
        for value in ("23", 23.0, True, None):
            self.assertRejected(tamper(self.message, "p", value))

    def test_unexpected_field(self):
        self.assertRejected(tamper(self.message, "extra", 1))

    def test_missing_field(self):
        envelope = json.loads(self.message)
        del envelope["payload"]["A"]
        self.assertRejected(encode_json(envelope))

    def test_duplicate_keys(self):
        self.assertRejected(self.message.replace(b'"A":8', b'"A":8,"A":9'))

    def test_malformed_nonces(self):
        for nonce in ("abcd", "z" * 64, 12345):
            self.assertRejected(tamper(self.message, "nonce_A", nonce))

    def test_wrong_protocol(self):
        self.assertRejected(tamper(self.message, "protocol", "DH-CLASSROOM-AUTH-v2"))

    def test_wrong_identity(self):
        self.assertRejected(tamper(self.message, "initiator", "Eve"))
        self.assertRejected(tamper(self.message, "responder", "Eve"))

    def test_malformed_signature(self):
        envelope = json.loads(self.message)
        envelope["signature"] = "not hex"
        self.assertRejected(encode_json(envelope))

    def test_oversized(self):
        self.assertRejected(b" " * 4097)

    def test_malformed_json(self):
        self.assertRejected(b"not json")
        self.assertRejected(b"\xff\xfe")
        self.assertRejected(b"[]")

    def test_wrong_message_type(self):
        self.assertRejected(self.message, expected_type="finish")

    def test_modulus_size(self):
        self.assertRejected(self.message, allow_test_fixture=False)
        self.assertRejected(tamper(self.message, "p", 2 ** 40 + 15))

if __name__ == "__main__":
    unittest.main()
