from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
import json

def trusted_setup():
    alice_signing_key = Ed25519PrivateKey.generate()
    bob_signing_key = Ed25519PrivateKey.generate()

    alice = {
        "signing_key": alice_signing_key,
        "trusted_keys": {"Bob": bob_signing_key.public_key()},
    }
    bob = {
        "signing_key": bob_signing_key,
        "trusted_keys": {"Alice": alice_signing_key.public_key()},
    }

    return alice, bob

def encode_json(obj):
    return json.dumps(obj, sort_keys=True, separators=(",", ":")).encode("utf-8")

def verify_signature(trusted_keys, identity, signature, message_bytes):
    trusted_keys[identity].verify(signature, message_bytes)
