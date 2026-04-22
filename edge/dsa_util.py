import oqs

ALG = "ML-DSA-65"

def generate_keypair():
    sig = oqs.Signature(ALG)
    public_key = sig.generate_keypair()
    secret_key = sig.export_secret_key()
    return public_key, secret_key

def sign_message(message, secret_key):
    sig = oqs.Signature(ALG, secret_key)
    return sig.sign(message)

def verify_signature(message, signature, public_key):
    sig = oqs.Signature(ALG)
    return sig.verify(message, signature, public_key)
