import json

from authentication import encode_json
from modular_math import modular_exponentiation

def unauthenticated_attack(p, g, a, b, e1, e2):
    A = modular_exponentiation(g, a, p)
    B = modular_exponentiation(g, b, p)
    E1 = modular_exponentiation(g, e1, p)
    E2 = modular_exponentiation(g, e2, p)

    return {
        "A": A,
        "B": B,
        "E1": E1,
        "E2": E2,
        "alice_secret": modular_exponentiation(E1, a, p),
        "eve_secret_with_alice": modular_exponentiation(A, e1, p),
        "bob_secret": modular_exponentiation(E2, b, p),
        "eve_secret_with_bob": modular_exponentiation(B, e2, p),
    }

def tamper(data, field, value):
    envelope = json.loads(data)
    payload = envelope["payload"]
    target = payload["transcript"] if "transcript" in payload else payload
    target[field] = value

    return encode_json(envelope)

def corrupt_signature(data):
    envelope = json.loads(data)
    signature = envelope["signature"]
    envelope["signature"] = ("1" if signature[0] == "0" else "0") + signature[1:]

    return encode_json(envelope)
