import json
import unittest

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from authentication import trusted_setup
from parameters import find_generator, generate_prime, prime_factors
from protocol import create_init, handle_finish, handle_init, handle_response

class CompleteExchangeTests(unittest.TestCase):
    def setUp(self):
        self.alice, self.bob = trusted_setup()

    def test_fixed_p_23_exchange(self):
        init_message = create_init(self.alice, 23, 5, fixture_private_key=6)
        response_message = handle_init(self.bob, init_message, True, fixture_private_key=15)
        finish_message = handle_response(self.alice, response_message, True)
        handle_finish(self.bob, finish_message, True)

        transcript = self.bob["session"]["transcript"]
        self.assertEqual(transcript["A"], 8)
        self.assertEqual(transcript["B"], 19)
        self.assertEqual(self.alice["session"]["shared_secret"], 2)
        self.assertEqual(self.bob["session"]["shared_secret"], 2)

    def test_generated_exchanges(self):
        for bits in (16, 24, 32):
            for _ in range(3):
                p, _ = generate_prime(bits)
                g = find_generator(p, prime_factors(p - 1))

                response_message = handle_init(self.bob, create_init(self.alice, p, g))
                handle_finish(self.bob, handle_response(self.alice, response_message))

                self.assertTrue(self.alice["session"]["completed"])
                self.assertTrue(self.bob["session"]["completed"])
                self.assertEqual(self.alice["session"]["shared_secret"], self.bob["session"]["shared_secret"])

    def test_bob_has_no_secret_before_finish(self):
        handle_init(self.bob, create_init(self.alice, 23, 5), True)
        self.assertNotIn("shared_secret", self.bob["session"])
        self.assertFalse(self.bob["session"]["completed"])

    def test_wrong_trusted_key(self):
        self.bob["trusted_keys"]["Alice"] = Ed25519PrivateKey.generate().public_key()
        with self.assertRaises(InvalidSignature):
            handle_init(self.bob, create_init(self.alice, 23, 5), True)

    def test_fresh_nonces(self):
        first_init = json.loads(create_init(self.alice, 23, 5))["payload"]
        first_response = json.loads(handle_init(self.bob, create_init(self.alice, 23, 5), True))["payload"]
        second_init = json.loads(create_init(self.alice, 23, 5))["payload"]
        second_response = json.loads(handle_init(self.bob, create_init(self.alice, 23, 5), True))["payload"]

        self.assertNotEqual(first_init["nonce_A"], second_init["nonce_A"])
        self.assertNotEqual(first_response["transcript"]["nonce_B"], second_response["transcript"]["nonce_B"])
        self.assertEqual(len(first_init["nonce_A"]), 64)

if __name__ == "__main__":
    unittest.main()
