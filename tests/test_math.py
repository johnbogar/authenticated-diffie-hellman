import unittest

from modular_math import modular_exponentiation
from parameters import find_generator, prime_factors, verify_generator
from participant import compute_shared_secret

class ExponentiationTests(unittest.TestCase):
    def test_known_result(self):
        self.assertEqual(modular_exponentiation(5, 6, 23), 8)

    def test_exponent_zero(self):
        self.assertEqual(modular_exponentiation(5, 0, 23), 1)

    def test_modulus_one(self):
        self.assertEqual(modular_exponentiation(5, 0, 1), 0)
        self.assertEqual(modular_exponentiation(5, 6, 1), 0)

    def test_negative_base(self):
        self.assertEqual(modular_exponentiation(-5, 3, 23), pow(-5, 3, 23))

    def test_invalid_inputs(self):
        with self.assertRaises(ValueError):
            modular_exponentiation(5, -1, 23)
        with self.assertRaises(ValueError):
            modular_exponentiation(5, 6, 0)
        with self.assertRaises(ValueError):
            modular_exponentiation(5, 6, -23)
        with self.assertRaises(TypeError):
            modular_exponentiation(5.0, 6, 23)
        with self.assertRaises(TypeError):
            modular_exponentiation(5, "6", 23)

    def test_matches_pow(self):
        for base in (-17, -1, 0, 1, 2, 5, 19, 65535, 4294967295):
            for exponent in (0, 1, 2, 15, 1000, 65536):
                for modulus in (1, 2, 23, 65537, 4294967291):
                    self.assertEqual(
                        modular_exponentiation(base, exponent, modulus),
                        pow(base, exponent, modulus),
                    )

class FactorizationTests(unittest.TestCase):
    def test_one(self):
        self.assertEqual(prime_factors(1), set())

    def test_22(self):
        self.assertEqual(prime_factors(22), {2, 11})

    def test_repeated_factors(self):
        self.assertEqual(prime_factors(65536), {2})

    def test_rejects_nonpositive(self):
        with self.assertRaises(ValueError):
            prime_factors(0)

class GeneratorTests(unittest.TestCase):
    def test_p_23(self):
        factors = prime_factors(22)
        self.assertTrue(verify_generator(5, 23, factors))
        self.assertFalse(verify_generator(2, 23, factors))
        self.assertEqual(find_generator(23, factors), 5)

    def test_p_65537(self):
        self.assertTrue(verify_generator(3, 65537, prime_factors(65536)))

class KeyAgreementTests(unittest.TestCase):
    def test_fixed_p_23_example(self):
        A = modular_exponentiation(5, 6, 23)
        B = modular_exponentiation(5, 15, 23)
        self.assertEqual(A, 8)
        self.assertEqual(B, 19)
        self.assertEqual(compute_shared_secret(B, 6, 23), 2)
        self.assertEqual(compute_shared_secret(A, 15, 23), 2)

if __name__ == "__main__":
    unittest.main()
