import json
import random
import hmac
import hashlib
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
import os


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
    p = int(p, 16)
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


def generate_private_public_keys(p, g):
    private_key = random.SystemRandom().randint(2, p - 2)
    public_key = pow(g, private_key, p)
    return private_key, public_key


def generate_32byte_key(key):
    print("-------------------------------------------------------------------------")
    print("[Function] generate_32byte_key")
    print("[Input] Shared key:", key)

    key_bytes = key.to_bytes((key.bit_length() + 7) // 8, "big")
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=32,  # Output 32 bytes for AES-256
        salt=None,
        info=b"AES-256 key",
    )
    key = hkdf.derive(key_bytes)
    print("[Output] HMAC key:", key)
    print("[Output] HMAC key:", len(key))
    return key


def encrypt_seed_AES(shared_key, seed):
    print("-------------------------------------------------------------------------")
    print("Function: encrypt_seed_AES")
    print("Inputs:")
    print(f"  shared key (ka) = {shared_key}")
    print(f"  seed  = {seed}")
    nonce = os.urandom(16)  # 16-byte nonce (must be unique per key!)
    key = generate_32byte_key(shared_key)
    # Encrypt data (no padding needed!)
    data = str(seed).encode()
    cipher = Cipher(algorithms.AES(key), modes.CTR(nonce))
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(data) + encryptor.finalize()
    return nonce + ciphertext


def decrypt_seed_AES(shared_key, message):
    print("-------------------------------------------------------------------------")
    print("Function: decrypt_seed_AES")
    print("Inputs:")
    print(f"  shared key (ka) = {shared_key}")
    print(f"  message  = {message}")
    nonce = message[:16]
    key = generate_32byte_key(shared_key)
    # Encrypt data (no padding needed!)
    data = message[16:]
    cipher = Cipher(algorithms.AES(key), modes.CTR(nonce))
    decryptor = cipher.decryptor()
    plaintext = decryptor.update(data) + decryptor.finalize()
    return plaintext.decode()


def encrypt_seed(ka, c1, b, p, data):
    print("-------------------------------------------------------------------------")
    print("Function: encrypt_seed")
    print("Inputs:")
    print(f"  Public key (ka) = {ka}")
    print(f"  Private key (b) = {b}")
    print(f"  Prime number (p) = {p}")
    print(f"  Data = {data}")
    data = data
    shared_key = pow(ka, b, p)
    c2 = (data * shared_key) % p
    cipher_json = json.dumps({"c1": (c1), "c2": c2})
    print("Output:")
    print(f"  Encrypted seed = {cipher_json}")
    return cipher_json, shared_key


def get_recieved_parameters(ciphere_text):
    ciphere_text = json.loads(ciphere_text)
    c1 = ciphere_text["c1"]
    c2 = ciphere_text["c2"]
    return c1, c2


def dencrypt_seed(a, p, cipher_text):
    print("-------------------------------------------------------------------------")
    print("[Function] dencrypt_seed")
    print("[Input] Prime number (p):", p)
    print("[Input] Cipher text:", cipher_text)
    c1, c2 = get_recieved_parameters(cipher_text)
    s = pow(c1, a, p)
    s_inv = pow(s, -1, p)
    seed = c2 * s_inv % p
    print("[Output] Decrypted plain seed:", seed)
    return seed


def generate_hmac(message, key):
    print("-------------------------------------------------------------------------")
    print("[Function] generate_hmac")
    print("[Input] Message:", message)
    print("[Input] Key:", key)

    key = generate_32byte_key(key)
    if isinstance(message, str):
        message = message.encode()
    hmac_result = hmac.new(key, message, hashlib.sha256).hexdigest()

    print("[Output] HMAC key:", key)
    print("[Output] HMAC result:", hmac_result)
    return hmac_result


def is_hmac_valid(a, p, cipher_text, received_hmac, AES_shared_key):
    print("-------------------------------------------------------------------------")
    print("[Function] is_hmac_valid")
    print("[Input] Message:", cipher_text)
    print("[Input] Received HMAC:", received_hmac)
    if AES_shared_key is None:
        c1, _ = get_recieved_parameters(cipher_text)
        key = pow(c1, a, p)
    else:
        key = AES_shared_key
    key = generate_32byte_key(key)
    if isinstance(cipher_text, str):
        cipher_text = cipher_text.encode()
    hmac_result = hmac.new(key, cipher_text, hashlib.sha256).hexdigest()

    print("[Computed HMAC]:", hmac_result)
    print(
        "[Validation Result]:",
        "Valid" if hmac.compare_digest(hmac_result, received_hmac) else "Invalid",
    )
    return hmac.compare_digest(hmac_result, received_hmac)


def xor(message, key):
    print("-------------------------------------------------------------------------")
    print("Function: xor")
    print("Inputs:")
    print(f"  Message = {message}")
    print(f"  Key = {key}")
    message_bytes = message.encode("utf-8") if isinstance(message, str) else message
    key_bytes = key.encode("utf-8") if isinstance(key, str) else key
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
