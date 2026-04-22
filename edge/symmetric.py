from cryptography.hazmat.primitives.ciphers.aead import AESGCM
import os

def aes_encrypt(key, plaintext):
    iv = os.urandom(12)
    aes = AESGCM(key)
    ciphertext = aes.encrypt(iv, plaintext, None)
    return iv, ciphertext

def aes_decrypt(key, iv, ciphertext):
    aes = AESGCM(key)
    return aes.decrypt(iv, ciphertext, None)
