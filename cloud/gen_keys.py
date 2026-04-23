from pqc import generate_kem_keypair
import pickle

pub, sec = generate_kem_keypair()

with open("cloud_public.key", "wb") as f:
    f.write(pub)

with open("cloud_secret.key", "wb") as f:
    f.write(sec)

print("Cloud keys generated")
