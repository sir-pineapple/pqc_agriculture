import time

from dsa_util import generate_keypair

start = time.time()
pub, sec = generate_keypair()
end = time.time()
print("DSA Key Generation time (ms):", (end-start)*1000)

with open("edge_dsa_public.key", "wb") as f:
    f.write(pub)

with open("edge_dsa_secret.key", "wb") as f:
    f.write(sec)

print("ML-DSA keys generated")
