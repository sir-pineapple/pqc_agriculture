import oqs
import time

def generate_kem_keypair():
    kem = oqs.KeyEncapsulation("ML-KEM-768")
    start = time.time()
    public_key = kem.generate_keypair()
    secret_key = kem.export_secret_key()
    end = time.time()
    print("Key Generation Time (ms):", (end-start)*1000)
    return public_key, secret_key

def decapsulate(ciphertext, secret_key):
    kem = oqs.KeyEncapsulation("ML-KEM-768", secret_key)
    start = time.time()
    secret = kem.decap_secret(ciphertext)
    end = time.time()
    print("Key Decapsulation time (ms):", (end-start)*1000)
    return secret
