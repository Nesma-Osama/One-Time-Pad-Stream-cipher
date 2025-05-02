import socket
import random
from utils import *


def main():
    sender = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sender.connect(("127.0.0.1", 9999))
    cipher = input("Enter Chiper (AES/ELgamal) ")
    p, g, mult, c, m = read_config()
    initail_seed = random.randint(1, m)
    b, c1 = generate_private_public_keys(p, g)
    ka = int(sender.recv(1024).decode())
    print(f"Received receiver's public key: {ka}")
    if cipher == "AES":
        sender.send(str(c1).encode())
        shared_key = pow(ka, b, p)
        cipher_seed = encrypt_seed_AES(shared_key, initail_seed)
    else:
        cipher_seed, shared_key = encrypt_seed(ka, c1, b, p, initail_seed)
    hmac_result = generate_hmac(cipher_seed, shared_key)
    # Send length first (4-byte header)
    if cipher == "AES":
        sender.send(len((cipher_seed + hmac_result.encode())).to_bytes(4, "big"))
        sender.sendall(
            (cipher_seed + hmac_result.encode())
        )  # sendall ensures complete transmission
    else:
        sender.send(len((cipher_seed + hmac_result).encode()).to_bytes(4, "big"))
        # Then send actual data
        sender.sendall(
            (cipher_seed + hmac_result).encode()
        )  # sendall ensures complete transmission
    send_message("./input.txt", sender, initail_seed, mult, c, m)


main()
