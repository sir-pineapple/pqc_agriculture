from symmetric import aes_encrypt, aes_decrypt
from hkdf_util import derive_key
import os

shared_secret = os.urandom(32)

key = derive_key(shared_secret)

message = b"hello smart agriculture"

iv, ciphertext = aes_encrypt(key, message)

plaintext = aes_decrypt(key, iv, ciphertext)

print("Decrypted:", plaintext.decode())
