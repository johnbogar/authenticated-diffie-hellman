import time

import Crypto
import cryptography
from cryptography.exceptions import InvalidSignature

from authentication import trusted_setup
from eve import tamper, unauthenticated_attack
from parameters import find_generator, generate_prime, prime_factors
from protocol import create_init, handle_finish, handle_init, handle_response

def run_successful_exchange(alice, bob, bits=16):
    p, _ = generate_prime(bits)
    g = find_generator(p, prime_factors(p - 1))

    print(f"Requested prime size: {bits} bits")
    print("Modulus: generated using library prime generator")
    print(f"Modulus bit length: {p.bit_length()}")

    init_message = create_init(alice, p, g)
    response_message = handle_init(bob, init_message)
    print("Received modulus library validation: PASS")
    print("Generator: validated")
    print("Alice initiation signature: VALID")

    finish_message = handle_response(alice, response_message)
    print("Bob response signature: VALID")

    handle_finish(bob, finish_message)
    print("Alice finish signature: VALID")

    authenticated = alice["session"]["completed"] and bob["session"]["completed"]
    secrets_match = alice["session"]["shared_secret"] == bob["session"]["shared_secret"]
    print(f"Transcript authenticated: {'YES' if authenticated else 'NO'}")
    print(f"Shared-secret equality in local test: {'PASS' if secrets_match else 'FAIL'}")
    print("Explicit key confirmation: NOT IMPLEMENTED")

def run_unauthenticated_attack():
    p, g, a, b, e1, e2 = 23, 5, 6, 15, 3, 7
    result = unauthenticated_attack(p, g, a, b, e1, e2)

    print(f"Classroom fixture: p={p}, g={g}, a={a}, b={b}, e1={e1}, e2={e2}")
    print(f"Eve sends E1 = {result['E1']} to Alice as though it came from Bob.")
    print(f"Eve sends E2 = {result['E2']} to Bob as though it came from Alice.")
    print(f"Alice computes: {result['E1']}^{a} mod {p} = {result['alice_secret']}")
    print(f"Eve computes:   {result['A']}^{e1} mod {p} = {result['eve_secret_with_alice']}")
    print(f"Bob computes:   {result['E2']}^{b} mod {p} = {result['bob_secret']}")
    print(f"Eve computes:   {result['B']}^{e2} mod {p} = {result['eve_secret_with_bob']}")
    print("Alice and Bob now hold different secrets, and Eve knows both.")

def run_authenticated_attack(alice, bob):
    init_message = create_init(alice, 23, 5, fixture_private_key=6)
    response_message = handle_init(bob, init_message, allow_test_fixture=True, fixture_private_key=15)

    tampered_response = tamper(response_message, "B", 10)
    print("Eve modified Bob's public value.")

    try:
        handle_response(alice, tampered_response, allow_test_fixture=True)
        print("Bob response signature: VALID")
    except InvalidSignature:
        print("Bob response signature: INVALID")
        print("Exchange aborted.")

def run_performance(alice, bob, trials=3):
    print(f"PyCryptodome: {Crypto.__version__}")
    print(f"cryptography: {cryptography.__version__}")
    print()
    print("| Bits | Trial | Prime generation (s) | Factorization (s) | Generator search (s) | Authenticated | Secrets match |")
    print("|---|---|---|---|---|---|---|")

    timings = {}

    for bits in (16, 24, 32):
        timings[bits] = {"Prime generation": [], "Factorization": [], "Generator search": []}

        for trial in range(1, trials + 1):
            p, prime_time = generate_prime(bits)

            start = time.perf_counter()
            factors = prime_factors(p - 1)
            factor_time = time.perf_counter() - start

            start = time.perf_counter()
            g = find_generator(p, factors)
            generator_time = time.perf_counter() - start

            try:
                response_message = handle_init(bob, create_init(alice, p, g))
                handle_finish(bob, handle_response(alice, response_message))
                authenticated = alice["session"]["completed"] and bob["session"]["completed"]
                secrets_match = alice["session"]["shared_secret"] == bob["session"]["shared_secret"]
            except (ValueError, InvalidSignature):
                authenticated = secrets_match = False

            timings[bits]["Prime generation"].append(prime_time)
            timings[bits]["Factorization"].append(factor_time)
            timings[bits]["Generator search"].append(generator_time)

            print(f"| {bits} | {trial} | {prime_time:.6f} | {factor_time:.6f} | {generator_time:.6f} | "
                  f"{'Yes' if authenticated else 'No'} | {'Yes' if secrets_match else 'No'} |")

    print()
    print("Timing variation:")
    print()
    print("| Bits | Measurement | Min (s) | Mean (s) | Max (s) |")
    print("|---|---|---|---|---|")

    for bits, measurements in timings.items():
        for name, values in measurements.items():
            print(f"| {bits} | {name} | {min(values):.6f} | {sum(values) / len(values):.6f} | {max(values):.6f} |")

if __name__ == "__main__":
    alice, bob = trusted_setup()

    print("=== Successful authenticated exchange ===")
    run_successful_exchange(alice, bob)

    print("\n=== Eve's attack on the unauthenticated version ===")
    run_unauthenticated_attack()

    print("\n=== Eve's attack on the authenticated version ===")
    run_authenticated_attack(alice, bob)

    print("\n=== Performance ===")
    run_performance(alice, bob)
