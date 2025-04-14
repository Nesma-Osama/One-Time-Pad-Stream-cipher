import json
import random
import hmac
import hashlib
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Hash import SHA256
import itertools


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
    print(f"LGC function")
    print(f"a= {a} c= {c} m= {m} x= {x}")
    x = (a * x + c) % m
    print(f"x new = {x}")
    return x


def generate_DF_keys(p, g):
    private_key = random.randint(2, p - 2)
    return private_key, ((g**private_key) % p)


def encrypt_seed(ka, b, p, data):
    print("-------------------------------------------------------------------------")
    print(f"encrypt_seed function")
    print(
         f"public key of the reciever {ka} private key {b} prime number {p} data {data}"
     )
    data = str(data)
    cipher_seed = json.dumps([(ord(ch) * (ka**b)) % p for ch in data])
    print(f"Seed Encryption is  {cipher_seed} ")
    return cipher_seed, (ka**b) % p


def dencrypt_seed(s, p, cipher_seed):
    print("-------------------------------------------------------------------------")
    print(f"dencrypt_seed function")
    print(f"shared key {s} prime number {p} chipher seed is {cipher_seed}")
    s_inv = pow(s, -1, p)
    cipher_seed = json.loads(cipher_seed)
    seed = "".join([chr((int(ch) * s_inv) % p) for ch in cipher_seed])
    print(f"Plain seed is {seed}")
    return seed


def generate_hmac_key(key):
    print("-------------------------------------------------------------------------")
    print(f"generate_hmac_key function")
    print(f"Shared Key {key}")
    key_bytes = key.to_bytes((key.bit_length() + 7) // 8, "big")
    hmac_key = hashlib.sha256(key_bytes).digest()
    print(f"Hmac Key {hmac_key} ")
    return hmac_key


def generate_hmac(message, key):
    print("-------------------------------------------------------------------------")
    print("generate_hmac function ")
    print(f"Hmac Message  {message} key {key}")
    key = generate_hmac_key(key)
    hmac_result = hmac.new(key, message.encode(), hashlib.sha256).hexdigest()
    print(f"Hmac Key {key} \nHmac {hmac_result} ")
    return hmac_result


def is_hmac_valid(key, message, received_hmac):
    print("-------------------------------------------------------------------------")
    print("hmac_verification function ")
    print(f"Hmac Message  {message} key {key} received hmac {received_hmac}")
    key = generate_hmac_key(key)
    hmac_result = hmac.new(key, message.encode(), hashlib.sha256).hexdigest()
    print(f"Hmac Key {key} Hmac {hmac_result}")
    if hmac.compare_digest(hmac_result, received_hmac):
        return True
    else:
        return False


def xor(message, key):
    print("-------------------------------------------------------------------------")
    print("xor function ")
    message_bytes = message.encode('utf-8') if isinstance(message, str) else message
    key_bytes = key.encode('utf-8') if isinstance(key, str) else key
    repeated_key= itertools.cycle(key_bytes)
    
    xor_result = bytes([m ^ k for m, k in zip(message_bytes, repeated_key)])
    return xor_result


def send_message(path, sender, initail_seed, a, c, m, chunk_size=10):
    print("-------------------------------------------------------------------------")
    print("send_message function ")
    print(f"input path {path} initial seed {initail_seed} ")
    seed= initail_seed
    with open(path, "r") as f:
        while True:
            chunk = f.read(chunk_size)
            if not chunk:
                break
            seed = LGC(seed, a, c, m)
            key = str(seed)
            print("seed" ,seed)
            message=xor(chunk, key)
            sender.send(len(message).to_bytes(4, 'big') )
            sender.send(message)


def receive_message(f, message, seed, a, c, m):
    print("-------------------------------------------------------------------------")
    print("receive_message function ")
    print(f"seed {seed} message {message} ")
    seed = LGC(seed, a, c, m)
    print("seed" ,seed)
    key =  str(seed)
    data = xor(message, key)  
    print(f"decrypted data  {data}")
    f.write(data)
    return seed
