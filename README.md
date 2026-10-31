# Authenticated Diffie-Hellman Key Exchange

This project is a Python simulation of an authenticated Diffie-Hellman key exchange between Alice and Bob. The program generates the public parameters using a library prime generator, validates them, and then runs a three-message exchange where each message is signed with a trusted Ed25519 identity key. It also demonstrates how an attacker, Eve, can take over an unauthenticated exchange, and how the signatures allow Alice and Bob to detect her when the exchange is authenticated. It is important to note that this is a local, educational simulation, so there are no network sockets or message encryption, and the 16 to 32-bit primes it uses are far too small to be secure.

## Requirements

The project was written and tested with Python 3.13.7 on macOS. It relies on two outside packages, which are listed in `requirements.txt`:

- **cryptography 47.0.0**, used for Ed25519 signatures
- **pycryptodome 4.1.0**, used for prime generation and primality validation

Everything else comes from Python's standard library, including `secrets`, `json`, `time`, `platform`, and `unittest`. The square-and-multiply algorithm, factorization of p - 1, generator verification, and the Diffie-Hellman calculations are all implemented by hand rather than with library calls.

## Setup

To start, clone the repository and move into the project folder:

```bash
git clone https://github.com/johnbogar/authenticated-diffie-hellman.git
cd authenticated-diffie-hellman
```

Then install the two required packages:

```bash
python3 -m pip install -r requirements.txt
```

## Running the Program

All of the demonstrations and performance trials run from `main.py`. It should be run from the project folder, since the modules import each other by name:

```bash
python3 main.py
```

The output is split into four sections:

1. A successful authenticated exchange using a 16-bit prime, which shows the result of each validation and signature check along the way.
2. Eve's attack on the unauthenticated version, using the classroom fixture of p = 23 and g = 5. Alice and Bob end up holding different secrets, and Eve knows both of them.
3. The same substitution against the authenticated version. This time, Alice rejects Bob's response because the signature no longer matches, and the exchange is aborted.
4. Performance trials, which run three exchanges at each of 16, 24, and 32 bits and record the prime generation, factorization, and generator search times, along with whether each exchange was authenticated.

A copy of one run's output is saved in `sample_output.txt`. Since the primes and private values are generated randomly, the exact numbers and timings will be different each time the program is run.

## Running the Tests

The automated tests are written with `unittest` and can be run from the project folder with:

```bash
python3 -m unittest discover tests -v
```

The tests are separated into five files, following the groups laid out in the project instructions:

- `test_math.py` covers the fixed mathematical tests for square-and-multiply, factorization, generator verification, and the p = 23 key agreement example.
- `test_parameters.py` covers the library prime generator wrapper and the validation of a received modulus.
- `test_messages.py` covers message validation, such as wrong types, duplicate keys, malformed nonces, and oversized messages.
- `test_exchange.py` covers complete exchanges, both with the fixed p = 23 example and with generated primes.
- `test_attacks.py` covers each of Eve's attacks, along with the session state checks for replayed, duplicate, and out-of-order messages.

Small fixed values like p = 23 are only allowed through an explicit test-fixture path, which the tests turn on with `allow_test_fixture=True`. Normal runs of the program reject any modulus outside of 16 to 32 bits. None of the tests check for an exact runtime, since timing depends on the machine the tests are run on.

## Project Structure

- `modular_math.py` contains the square-and-multiply modular exponentiation.
- `parameters.py` contains the library prime generation wrapper, received-modulus validation, factorization of p - 1, and generator verification and search.
- `participant.py` contains Diffie-Hellman key generation, the public value range check, and the shared secret calculation.
- `authentication.py` contains the trusted identity setup, deterministic JSON encoding, and signature verification.
- `protocol.py` contains message building and validation, along with the session state for the three-message exchange.
- `eve.py` contains the unauthenticated attack and the tools Eve uses to tamper with signed messages.
- `main.py` runs the demonstrations and performance timing.
- `tests/` contains the automated tests.
