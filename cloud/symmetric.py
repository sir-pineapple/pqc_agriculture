from cryptography.hazmat.primitives.ciphers.aead import AESGCM
import os

def aes_encrypt(key, plaintext):
    iv = os.urandom(12)
    aesgcm = AESGCM(key)
    ciphertext = aesgcm.encrypt(iv, plaintext, None)
    return iv, ciphertext

def aes_decrypt(key, iv, ciphertext):
    aesgcm = AESGCM(key)
    return aesgcm.decrypt(iv, ciphertext, None)

