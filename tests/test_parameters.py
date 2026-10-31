import unittest

from Crypto.Util.number import isPrime

from authentication import trusted_setup
from parameters import generate_prime, validate_prime
from protocol import create_init, handle_init

class PrimeGenerationTests(unittest.TestCase):
    def test_exact_bit_length_and_oddness(self):
        for bits in (16, 24, 32):
            p, elapsed = generate_prime(bits)
            self.assertEqual(p.bit_length(), bits)
            self.assertTrue(2 ** (bits - 1) <= p < 2 ** bits)
            self.assertEqual(p % 2, 1)
            self.assertGreaterEqual(elapsed, 0)

    def test_default_is_16_bits(self):
        p, _ = generate_prime()
        self.assertEqual(p.bit_length(), 16)

    def test_library_validates_returned_primes(self):
        for bits in (16, 24, 32):
            p, _ = generate_prime(bits)
            self.assertTrue(isPrime(p))
            validate_prime(p)

    def test_invalid_requested_sizes(self):
        for bits in (12, 15, 33):
            with self.assertRaises(ValueError):
                generate_prime(bits)
        for bits in (True, False, 16.0, "16"):
            with self.assertRaises(TypeError):
                generate_prime(bits)

class ReceivedModulusTests(unittest.TestCase):
    def test_rejects_composite(self):
        with self.assertRaises(ValueError):
            validate_prime(32769)

    def test_rejects_wrong_types(self):
        for p in ("65521", 65521.0):
            with self.assertRaises(TypeError):
                validate_prime(p)

    def test_rejects_out_of_range_sizes(self):
        for p in (5, 32749, 2 ** 32 + 15):
            with self.assertRaises(ValueError):
                validate_prime(p)

    def test_fixture_path(self):
        with self.assertRaises(ValueError):
            validate_prime(23)
        validate_prime(23, allow_test_fixture=True)
        with self.assertRaises(ValueError):
            validate_prime(21, allow_test_fixture=True)

    def test_composite_rejected_before_generator_check(self):
        alice, bob = trusted_setup()
        init_message = create_init(alice, 32769, 3)
        with self.assertRaisesRegex(ValueError, "not a prime"):
            handle_init(bob, init_message)

if __name__ == "__main__":
    unittest.main()
