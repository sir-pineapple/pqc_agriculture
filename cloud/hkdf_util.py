from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes

def derive_key(shared_secret, info=b"transport"):
    hkdf = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=b"agriculture",
            info=info,
    )
    return hkdf.derive(shared_secret)

