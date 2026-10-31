import secrets

from modular_math import modular_exponentiation

def is_valid_public_value(value, p):
    return 2 <= value <= p - 2

def generate_dh_keypair(p, g):
    while True:
        private_key = secrets.randbelow(p - 3) + 2
        public_value = modular_exponentiation(g, private_key, p)

        if is_valid_public_value(public_value, p):
            return private_key, public_value

def compute_shared_secret(peer_public_value, private_key, p):
    return modular_exponentiation(peer_public_value, private_key, p)
