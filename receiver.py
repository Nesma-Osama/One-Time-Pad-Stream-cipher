import socket
from utils import *


def main():
    receiver = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    receiver.bind(("127.0.0.1", 9999))
    receiver.listen(1)
    print("Receiver is listening on port 9999")
    p, g, mult, c, m = read_config()
    a, ka = generate_private_public_keys(p, g)
    print(f"Receiver's private key: {a}, public key: {ka}")
    is_send = True
    while is_send:
        sender, _ = receiver.accept()
        sender.send(str(ka).encode())
        received_seed = sender.recv(1024).decode()
        if not (is_hmac_valid(a, p, received_seed[:-64], received_seed[-64:])):
            print("message is not authentication")
            break
        seed = int(dencrypt_seed(a, p, received_seed[:-64]))
        with open("output.txt", "wb") as f:
            while True:
                length_bytes = sender.recv(4)
                if not length_bytes or len(length_bytes) != 4:
                    is_send = False
                    break
                chunk_length = int.from_bytes(length_bytes, byteorder="big")
                encrypted_data = b""
                while len(encrypted_data) < chunk_length:
                    packet = sender.recv(chunk_length - len(encrypted_data))
                    if not packet:
                        break
                    encrypted_data += packet
                if not encrypted_data:
                    break
                seed = receive_message(f, encrypted_data, seed, mult, c, m)
        sender.close()


main()
