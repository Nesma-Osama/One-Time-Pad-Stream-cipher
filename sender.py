import socket
import random
from utils import *


def main():
    sender = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sender.connect(("127.0.0.1", 9999))
    p, g, mult, c, m = read_config()
    initail_seed = random.randint(1, m)
    b, kb = generate_DF_keys(p, g)
    print(f"Sender private key: {b}, public key: {kb}")
    sender.send(str(kb).encode())
    ka = int(sender.recv(1024).decode())
    print(f"Received receiver's public key: {ka}")
    cipher_seed, shared_key = encrypt_seed(ka, b, p, initail_seed)
    hmac_result = generate_hmac(cipher_seed, shared_key)
    sender.send((cipher_seed + hmac_result).encode())
    send_message("./input.txt", sender, initail_seed, mult, c, m)


main()
