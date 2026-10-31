import json
import unittest

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from authentication import trusted_setup
from eve import corrupt_signature, tamper, unauthenticated_attack
from protocol import create_init, handle_finish, handle_init, handle_response, pack_message

REJECTED = (ValueError, InvalidSignature)

class AttackTests(unittest.TestCase):
    def setUp(self):
        self.alice, self.bob = trusted_setup()

    def run_exchange(self):
        init_message = create_init(self.alice, 23, 5)
        response_message = handle_init(self.bob, init_message, True)
        finish_message = handle_response(self.alice, response_message, True)
        handle_finish(self.bob, finish_message, True)
        return init_message, response_message, finish_message

    def test_unauthenticated_attack(self):
        result = unauthenticated_attack(23, 5, 6, 15, 3, 7)
        self.assertEqual(result["E1"], 10)
        self.assertEqual(result["E2"], 17)
        self.assertEqual(result["alice_secret"], 6)
        self.assertEqual(result["eve_secret_with_alice"], 6)
        self.assertEqual(result["bob_secret"], 15)
        self.assertEqual(result["eve_secret_with_bob"], 15)
        self.assertNotEqual(result["alice_secret"], result["bob_secret"])

    def test_modify_B_without_new_signature(self):
        init_message = create_init(self.alice, 23, 5, fixture_private_key=6)
        response_message = handle_init(self.bob, init_message, True, fixture_private_key=15)
        with self.assertRaises(InvalidSignature):
            handle_response(self.alice, tamper(response_message, "B", 10), True)
        self.assertIsNone(self.alice["session"])

    def test_modify_A_without_new_signature(self):
        init_message = create_init(self.alice, 23, 5, fixture_private_key=6)
        with self.assertRaises(InvalidSignature):
            handle_init(self.bob, tamper(init_message, "A", 17), True)
        self.assertIsNone(self.bob.get("session"))

    def test_modify_p(self):
        init_message = create_init(self.alice, 23, 5)
        with self.assertRaises(REJECTED):
            handle_init(self.bob, tamper(init_message, "p", 65537), True)

    def test_modify_g(self):
        init_message = create_init(self.alice, 23, 5)
        with self.assertRaises(REJECTED):
            handle_init(self.bob, tamper(init_message, "g", 7), True)

    def test_modify_identity_labels(self):
        init_message = create_init(self.alice, 23, 5)
        with self.assertRaises(REJECTED):
            handle_init(self.bob, tamper(init_message, "initiator", "Eve"), True)

    def test_corrupt_signature(self):
        init_message = create_init(self.alice, 23, 5)
        with self.assertRaises(InvalidSignature):
            handle_init(self.bob, corrupt_signature(init_message), True)

    def test_sign_as_alice_with_eve_key(self):
        init_message = create_init(self.alice, 23, 5)
        payload = json.loads(init_message)["payload"]
        forged_message = pack_message(payload, Ed25519PrivateKey.generate())
        with self.assertRaises(InvalidSignature):
            handle_init(self.bob, forged_message, True)

    def test_replay_old_response_into_fresh_alice_session(self):
        _, old_response, _ = self.run_exchange()
        create_init(self.alice, 23, 5)
        with self.assertRaises(REJECTED):
            handle_response(self.alice, old_response, True)
        self.assertIsNone(self.alice["session"])

    def test_replay_old_finish_into_fresh_bob_session(self):
        _, _, old_finish = self.run_exchange()
        handle_init(self.bob, create_init(self.alice, 23, 5), True)
        with self.assertRaises(REJECTED):
            handle_finish(self.bob, old_finish, True)
        self.assertIsNone(self.bob["session"])

    def test_replayed_init_cannot_complete_without_matching_finish(self):
        old_init, old_response, old_finish = self.run_exchange()
        new_response = handle_init(self.bob, old_init, True)
        self.assertNotEqual(new_response, old_response)
        with self.assertRaises(REJECTED):
            handle_finish(self.bob, old_finish, True)

    def test_duplicate_finish_after_completion(self):
        _, _, finish_message = self.run_exchange()
        with self.assertRaises(REJECTED):
            handle_finish(self.bob, finish_message, True)
        self.assertTrue(self.bob["session"]["completed"])

    def test_malformed_message(self):
        with self.assertRaises(REJECTED):
            handle_init(self.bob, b"not json", True)

    def test_oversized_message(self):
        with self.assertRaises(REJECTED):
            handle_init(self.bob, b" " * 5000, True)

    def test_out_of_order_messages(self):
        _, response_message, finish_message = self.run_exchange()
        self.bob["session"] = None
        with self.assertRaises(REJECTED):
            handle_finish(self.bob, finish_message, True)
        handle_init(self.bob, create_init(self.alice, 23, 5), True)
        with self.assertRaises(REJECTED):
            handle_finish(self.bob, response_message, True)

if __name__ == "__main__":
    unittest.main()
