import json
import random
import hashlib
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad,unpad
def read_config():
    with open("config.json") as f:
        config = json.load(f)
    p,g=config['Encryption']['p'],config['Encryption']['g']
    return p,g

def generate_DF_keys(p,g):
    private_key = random.randint(2, p - 2)
    return private_key,((g** private_key)%p)
def generate_AES_key(ka,b,p):
    print(f"key parameters public key of the other side {ka} private key {b} prime number {p}" )
    shared_secret=(ka**b)%p
    aes_key = hashlib.sha256(str(shared_secret).encode()).digest()  
    print(f"Shared key {shared_secret} AES key {aes_key}")
    return aes_key,shared_secret

def AES_encryption(key):
    ##get seed todo
    print(f"Encryption Key {key}")
    data=b"hello secret world"
    cipher=AES.new(key,AES.MODE_CBC)
    ciphered_data=cipher.encrypt(pad(data,AES.block_size))
    ciphertext = cipher.iv +ciphered_data
    print(f"Cipher Data is {ciphertext}")
    return ciphertext


def AES_dencryption(key,cipher_text):
    print(f"Dencryption Key {key} Cipher Text {cipher_text}")
    iv = cipher_text[:16]
    cipher_data = cipher_text[16:]
    cipher=AES.new(key,AES.MODE_CBC,iv)
    plain_text = unpad(cipher.decrypt(cipher_data), AES.block_size).decode()
    print(f"Plain Data is {plain_text}")
    return plain_text
    
    
    
    
