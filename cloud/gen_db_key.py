import time

from hkdf_util import derive_key

with open("cloud_secret.key", "rb") as f:
    cloud_secret = f.read()

start = time.time()
key = derive_key(cloud_secret, info=b"db_key")
end = time.time()
print("Key Generation time (ms):", (end-start)*1000)

with open("db_key.bin", "wb") as f:
    f.write(key)

