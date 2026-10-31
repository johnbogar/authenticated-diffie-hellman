import json
import secrets

from authentication import encode_json, verify_signature
from modular_math import modular_exponentiation
from parameters import is_allowed_modulus_size, prime_factors, validate_prime, verify_generator
from participant import compute_shared_secret, generate_dh_keypair, is_valid_public_value

PROTOCOL = "DH-CLASSROOM-AUTH-v1"
MAX_MESSAGE_SIZE = 4096

ENVELOPE_SCHEMA = {"payload": dict, "signature": str}
INIT_SCHEMA = {
    "protocol": str, "message_type": str, "initiator": str, "responder": str,
    "p": int, "g": int, "A": int, "nonce_A": str,
}
SIGNED_TRANSCRIPT_SCHEMA = {"message_type": str, "transcript": dict}
TRANSCRIPT_SCHEMA = {
    "protocol": str, "initiator": str, "responder": str,
    "p": int, "g": int, "A": int, "B": int, "nonce_A": str, "nonce_B": str,
}

def generate_nonce():
    return secrets.token_bytes(32).hex()

def build_init_payload(p, g, A, nonce_A):
    return {
        "protocol": PROTOCOL, "message_type": "init", "initiator": "Alice", "responder": "Bob",
        "p": p, "g": g, "A": A, "nonce_A": nonce_A,
    }

def build_transcript(init_payload, B, nonce_B):
    return {
        "protocol": init_payload["protocol"],
        "initiator": init_payload["initiator"],
        "responder": init_payload["responder"],
        "p": init_payload["p"], "g": init_payload["g"],
        "A": init_payload["A"], "B": B,
        "nonce_A": init_payload["nonce_A"], "nonce_B": nonce_B,
    }

def build_signed_transcript(message_type, transcript):
    return {"message_type": message_type, "transcript": transcript}

def pack_message(payload, signing_key):
    signature = signing_key.sign(encode_json(payload))
    return encode_json({"payload": payload, "signature": signature.hex()})

def is_hex_string(value, length):
    return len(value) == length and all(c in "0123456789abcdefABCDEF" for c in value)

def reject_duplicate_keys(pairs):
    result = {}

    for key, value in pairs:
        if key in result:
            raise ValueError(f"Duplicate JSON key: {key}.")
        result[key] = value

    return result

def check_fields(obj, schema, name):
    if type(obj) is not dict:
        raise ValueError(f"{name} must be a JSON object.")

    if set(obj) != set(schema):
        raise ValueError(f"{name} has missing or unexpected fields.")

    for field, expected_type in schema.items():
        if type(obj[field]) is not expected_type:
            raise ValueError(f"{name} field '{field}' must be of type {expected_type.__name__}.")

def check_session_fields(fields, nonce_names, allow_test_fixture):
    if fields["protocol"] != PROTOCOL:
        raise ValueError(f"Unknown protocol: {fields['protocol']}.")

    if fields["initiator"] != "Alice" or fields["responder"] != "Bob":
        raise ValueError("Unexpected identity labels.")

    if not is_allowed_modulus_size(fields["p"], allow_test_fixture):
        raise ValueError("Modulus must be from 16 through 32 bits, inclusive.")

    for name in nonce_names:
        if not is_hex_string(fields[name], 64):
            raise ValueError(f"{name} must be a 64-character hexadecimal string.")

def parse_message(data, expected_type, allow_test_fixture=False):
    if len(data) > MAX_MESSAGE_SIZE:
        raise ValueError(f"Message is {len(data)} bytes. Maximum: {MAX_MESSAGE_SIZE}.")

    envelope = json.loads(data.decode("utf-8"), object_pairs_hook=reject_duplicate_keys)

    check_fields(envelope, ENVELOPE_SCHEMA, "Message")

    if not is_hex_string(envelope["signature"], 128):
        raise ValueError("Signature must be a 128-character hexadecimal string.")

    payload = envelope["payload"]

    if payload.get("message_type") != expected_type:
        raise ValueError(f"Expected a '{expected_type}' message, got '{payload.get('message_type')}'.")

    if expected_type == "init":
        check_fields(payload, INIT_SCHEMA, "Init payload")
        check_session_fields(payload, ["nonce_A"], allow_test_fixture)
    else:
        check_fields(payload, SIGNED_TRANSCRIPT_SCHEMA, "Payload")
        check_fields(payload["transcript"], TRANSCRIPT_SCHEMA, "Transcript")
        check_session_fields(payload["transcript"], ["nonce_A", "nonce_B"], allow_test_fixture)

    return payload, bytes.fromhex(envelope["signature"])

def create_init(alice, p, g, fixture_private_key=None):
    if fixture_private_key is None:
        private_key, A = generate_dh_keypair(p, g)
    else:
        private_key, A = fixture_private_key, modular_exponentiation(g, fixture_private_key, p)

    init_payload = build_init_payload(p, g, A, generate_nonce())

    alice["session"] = {"private_key": private_key, "init_payload": init_payload, "completed": False}

    return pack_message(init_payload, alice["signing_key"])

def handle_init(bob, data, allow_test_fixture=False, fixture_private_key=None):
    payload, signature = parse_message(data, "init", allow_test_fixture)
    verify_signature(bob["trusted_keys"], payload["initiator"], signature, encode_json(payload))

    p, g, A = payload["p"], payload["g"], payload["A"]
    validate_prime(p, allow_test_fixture)

    if not verify_generator(g, p, prime_factors(p - 1)):
        raise ValueError(f"{g} is not a generator for p = {p}.")

    if not is_valid_public_value(A, p):
        raise ValueError(f"A must be from 2 through {p - 2}, inclusive.")

    if fixture_private_key is None:
        private_key, B = generate_dh_keypair(p, g)
    else:
        private_key, B = fixture_private_key, modular_exponentiation(g, fixture_private_key, p)

    transcript = build_transcript(payload, B, generate_nonce())

    bob["session"] = {"private_key": private_key, "transcript": transcript, "completed": False}

    return pack_message(build_signed_transcript("response", transcript), bob["signing_key"])

def handle_response(alice, data, allow_test_fixture=False):
    session = alice.get("session")

    if session is None or session["completed"]:
        raise ValueError("No pending session for this response.")

    alice["session"] = None

    payload, signature = parse_message(data, "response", allow_test_fixture)
    transcript = payload["transcript"]

    for field in ("p", "g", "A", "nonce_A"):
        if transcript[field] != session["init_payload"][field]:
            raise ValueError(f"Response field '{field}' does not match the pending session.")

    if not is_valid_public_value(transcript["B"], transcript["p"]):
        raise ValueError(f"B must be from 2 through {transcript['p'] - 2}, inclusive.")

    verify_signature(alice["trusted_keys"], transcript["responder"], signature, encode_json(payload))

    session["transcript"] = transcript
    session["shared_secret"] = compute_shared_secret(transcript["B"], session["private_key"], transcript["p"])
    session["completed"] = True
    alice["session"] = session

    return pack_message(build_signed_transcript("finish", transcript), alice["signing_key"])

def handle_finish(bob, data, allow_test_fixture=False):
    session = bob.get("session")

    if session is None or session["completed"]:
        raise ValueError("No pending session for this finish.")

    bob["session"] = None

    payload, signature = parse_message(data, "finish", allow_test_fixture)

    if payload["transcript"] != session["transcript"]:
        raise ValueError("Finish transcript does not match the pending session.")

    transcript = session["transcript"]
    verify_signature(bob["trusted_keys"], transcript["initiator"], signature, encode_json(payload))

    session["shared_secret"] = compute_shared_secret(transcript["A"], session["private_key"], transcript["p"])
    session["completed"] = True
    bob["session"] = session
