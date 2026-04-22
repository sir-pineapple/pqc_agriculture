import oqs

print("Edge encapsulating...")

# load cloud public key
with open("cloud_public.key", "rb") as f:
    pub = f.read()

kem = oqs.KeyEncapsulation("ML-KEM-768")

ciphertext, shared_secret = kem.encap_secret(pub)

print("Shared secret length:", len(shared_secret))

# save ciphertext for cloud
with open("kem_cipher.bin", "wb") as f:
    f.write(ciphertext)

print("Ciphertext saved")
