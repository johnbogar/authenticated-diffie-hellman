from Crypto.Util.number import getPrime, isPrime
import secrets
import time

from modular_math import modular_exponentiation

def generate_prime(bits=16):
    start = time.perf_counter()

    if not isinstance(bits, int) or isinstance(bits, bool):
        raise TypeError("All inputs must be integers.")
    
    if bits < 16 or bits > 32:
        raise ValueError("Bit length must be an integer from 16 through 32, inclusive.")
    
    p = getPrime(bits, randfunc=secrets.token_bytes)

    if p.bit_length() != bits:
        raise RuntimeError(f"The prime number returned ({p}) is {p.bit_length()} bits. Expected bits: {bits}.")
    
    if p % 2 == 0:
        raise RuntimeError(f"The prime number returned ({p}) cannot be a real prime number because it is even.")
    
    elapsed = time.perf_counter() - start
    return p, elapsed

def validate_prime(p, allow_test_fixture=False):
    if not isinstance(p, int):
        raise TypeError("All inputs must be integers.")

    if not is_allowed_modulus_size(p, allow_test_fixture):
        raise ValueError("Modulus must be from 16 through 32 bits, inclusive.")
    
    if not isPrime(p):
        raise ValueError(f"{p} is not a prime number.")

def is_allowed_modulus_size(p, allow_test_fixture=False):
    if allow_test_fixture and p == 23:
        return True

    return 2 ** 15 <= p < 2 ** 32

def prime_factors(n):
    if not isinstance(n, int):
        raise TypeError("All inputs must be integers.")

    if n < 1:
        raise ValueError("n must be a positive integer.")

    result = set()

    if n % 2 == 0:
        result.add(2)

    while n % 2 == 0:
        n = n//2

    divisor = 3
    
    while divisor**2 <= n:
        if n % divisor == 0:
            result.add(divisor)
            while n % divisor == 0:
                n = n//divisor
        divisor += 2

    if n > 1:
        result.add(n)

    return result

def verify_generator(g, p, factors):
    if g < 2 or g > p - 2:
        raise ValueError(f"Generator must be from 2 through {p - 2}, inclusive.")

    for r in factors:
        if modular_exponentiation(g, (p - 1) // r, p) == 1:
            return False

    return True

def find_generator(p, factors):
    for g in range(2, p - 1):
        if verify_generator(g, p, factors):
            return g
