import socket
from utils import *
def main():
    receiver=socket.socket(socket.AF_INET,socket.SOCK_STREAM)
    receiver.bind(('127.0.0.1',9999))
    receiver.listen(1)
    print("Receiver is listening on port 9999")
    p,g=read_config()
    a,ka=generate_DF_keys(p,g)
    print(f"Receiver's private key: {a}, public key: {ka}")
    while True:
        sender,_=receiver.accept()
        kb=int(sender.recv(1024).decode())
        print(f"Received sender's public key: {kb}")
        sender.send(str(ka).encode())
        aes_key,shared_secret=generate_AES_key(kb,a,p)
        cipher_text=sender.recv(1024)
        AES_dencryption(aes_key,cipher_text)
        sender.close()
main()   