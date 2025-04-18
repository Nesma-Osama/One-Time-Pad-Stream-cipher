import json
import random
import hmac
import hashlib
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Hash import SHA256


def read_config():
    with open("config.json") as f:
        config = json.load(f)
    p, g, a, c, m = (
        config["Encryption"]["p"],
        config["Encryption"]["g"],
        config["Encryption"]["a"],
        config["Encryption"]["c"],
        config["Encryption"]["m"],
    )
    return p, g, a, c, m


def LGC(x, a, c, m):
    print("-------------------------------------------------------------------------")
    print("Function: LGC")
    print("Inputs:")
    print(f"  x = {x}")
    print(f"  a = {a}")
    print(f"  c = {c}")
    print(f"  m = {m}")
    x = (a * x + c) % m
    print("Output:")
    print(f"  x_new = {x}")
    return x


def generate_DF_keys(p, g):
    private_key = random.randint(2, p - 2)
    return private_key, ((g**private_key) % p)


def encrypt_seed(ka, b, p, data):
    print("-------------------------------------------------------------------------")
    print("Function: encrypt_seed")
    print("Inputs:")
    print(f"  Public key (ka) = {ka}")
    print(f"  Private key (b) = {b}")
    print(f"  Prime number (p) = {p}")
    print(f"  Data = {data}")
    data = str(data)
    cipher_seed = json.dumps([(ord(ch) * (ka**b)) % p for ch in data])
    print("Output:")
    print(f"  Encrypted seed = {cipher_seed}")
    return cipher_seed, (ka**b) % p


def dencrypt_seed(s, p, cipher_seed):
    print("-------------------------------------------------------------------------")
    print("[Function] dencrypt_seed")
    print("[Input] Shared key (s):", s)
    print("[Input] Prime number (p):", p)
    print("[Input] Cipher seed:", cipher_seed)

    s_inv = pow(s, -1, p)
    cipher_seed = json.loads(cipher_seed)
    seed = "".join([chr((int(ch) * s_inv) % p) for ch in cipher_seed])

    print("[Output] Decrypted plain seed:", seed)
    return seed


def generate_hmac_key(key):
    print("-------------------------------------------------------------------------")
    print("[Function] generate_hmac_key")
    print("[Input] Shared key:", key)

    key_bytes = key.to_bytes((key.bit_length() + 7) // 8, "big")
    hmac_key = hashlib.sha256(key_bytes).digest()

    print("[Output] HMAC key:", hmac_key)
    return hmac_key


def generate_hmac(message, key):
    print("-------------------------------------------------------------------------")
    print("[Function] generate_hmac")
    print("[Input] Message:", message)
    print("[Input] Key:", key)

    key = generate_hmac_key(key)
    hmac_result = hmac.new(key, message.encode(), hashlib.sha256).hexdigest()

    print("[Output] HMAC key:", key)
    print("[Output] HMAC result:", hmac_result)
    return hmac_result


def is_hmac_valid(key, message, received_hmac):
    print("-------------------------------------------------------------------------")
    print("[Function] is_hmac_valid")
    print("[Input] Key:", key)
    print("[Input] Message:", message)
    print("[Input] Received HMAC:", received_hmac)

    key = generate_hmac_key(key)
    hmac_result = hmac.new(key, message.encode(), hashlib.sha256).hexdigest()

    print("[Computed HMAC]:", hmac_result)
    print(
        "[Validation Result]:",
        "Valid" if hmac.compare_digest(hmac_result, received_hmac) else "Invalid",
    )
    return hmac.compare_digest(hmac_result, received_hmac)


def modify_seed(seed, len_message):
    print("-------------------------------------------------------------------------")
    print("[Function] modify_seed")
    print("[Input] Seed:", seed)
    print("[Input] Length of message:", len_message)

    hashed_key = hashlib.sha256(seed).digest()
    derived_key = hashed_key[0:len_message]

    print("[Output] Hashed key:", hashed_key)
    print("[Output] Derived key (trimmed):", derived_key)
    return derived_key


def xor(message, key):
    print("-------------------------------------------------------------------------")
    print("Function: xor")
    print("Inputs:")
    print(f"  Message = {message}")
    print(f"  Key = {key}")
    message_bytes = message.encode("utf-8") if isinstance(message, str) else message
    key_bytes = key.encode("utf-8") if isinstance(key, str) else key
    # repeated_key = modify_seed(key_bytes, len(message))
    xor_result = bytes([m ^ k for m, k in zip(message_bytes, key_bytes)])
    print("Output:")
    print(f"  XOR result = {xor_result}")
    return xor_result


def send_message(path, sender, initail_seed, a, c, m, chunk_size=10):
    print("-------------------------------------------------------------------------")
    print("[Function] send_message")
    print("[Input] File path:", path)
    print("[Input] Initial seed:", initail_seed)
    print("[Input] LCG Params -> a:", a, "| c:", c, "| m:", m)
    print("[Input] Chunk size:", chunk_size)

    seed = initail_seed
    with open(path, "r") as f:
        while True:
            seed = LGC(seed, a, c, m)
            key = str(seed)
            print("[Step] New LCG Seed:", seed)
            chunk = f.read(len(key))
            if not chunk:
                print("[Info] End of file reached.")
                break
            message = xor(chunk, key)
            print("[Step] Sending encrypted message chunk...")
            sender.send(len(message).to_bytes(4, "big"))
            sender.send(message)

    print("[Output] Message sending completed.")


def receive_message(f, message, seed, a, c, m):
    print("-------------------------------------------------------------------------")
    print("[Function] receive_message")
    print("[Input] Encrypted message:", message)
    print("[Input] Initial seed:", seed)
    print("[Input] LCG Params -> a:", a, "| c:", c, "| m:", m)

    seed = LGC(seed, a, c, m)
    print("[Step] New LCG Seed:", seed)
    key = str(seed)
    data = xor(message, key)

    print("[Output] Decrypted data:", data)
    f.write(data)
    return seed
