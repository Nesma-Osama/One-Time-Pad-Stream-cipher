import socket
from utils import *


def receive_binary(sock):
    # Get length header (4 bytes)
    length_bytes = sock.recv(4)
    if not length_bytes:
       return None
    
    length = int.from_bytes(length_bytes, "big")
    chunks = []
    bytes_received = 0
    
    # Receive in chunks
    while bytes_received < length:
        chunk = sock.recv(min(4096, length - bytes_received))
        if not chunk:
            raise ConnectionError(f"Incomplete data (got {bytes_received}/{length} bytes)")
        chunks.append(chunk)
        bytes_received += len(chunk)
    
    return b"".join(chunks).decode()


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
        received_seed = receive_binary(sender)
        if not (is_hmac_valid(a, p, received_seed[:-64], received_seed[-64:])):
            print("message is not authentication")
            break
        seed = int(dencrypt_seed(a, p, received_seed[:-64]))
        with open("output.txt", "wb") as f:
            while True:
                encrypted_data=receive_binary(sender)
                if(encrypted_data is None):
                    is_send=False
                seed = receive_message(f, encrypted_data, seed, mult, c, m)
        sender.close()


main()
