import oqs

ALG = "ML-KEM-512"

def decapsulate(ciphertext, secret_key):
    kem = oqs.KeyEncapsulation(ALG, secret_key)
    return kem.decap_secret(ciphertext)

