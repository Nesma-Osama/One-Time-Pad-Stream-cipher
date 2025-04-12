import socket
from utils import *
def main():
    sender=socket.socket(socket.AF_INET,socket.SOCK_STREAM)
    sender.connect(('127.0.0.1',9999))
    p,g=read_config()
    b,kb=generate_DF_keys(p,g)
    print(f"Sender private key: {b}, public key: {kb}")
    sender.send(str(kb).encode())
    ka=int(sender.recv(1024).decode())
    print(f"Received receiver's public key: {ka}")
    aes_key,shared_secret=generate_AES_key(ka,b,p)
    cipher_text=AES_encryption(aes_key)
    sender.send(cipher_text)
main()   