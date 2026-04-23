import socket
import pickle
import oqs
import psycopg2
import json
import time
from hkdf_util import derive_key
from symmetric import aes_decrypt
from symmetric import aes_encrypt
from dsa_util import verify_signature
from net_util import recv_msg

conn = psycopg2.connect(dbname="pqc_agriculture", user="pragya", host="127.0.0.1")
cursor = conn.cursor()

with open("cloud_secret.key", "rb") as f:
    secret_key = f.read()
with open("edge_dsa_public.key", "rb") as f:
    edge_pub = f.read()
with open("db_key.bin", "rb") as f:
    db_key = f.read()

server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server.bind(("0.0.0.0", 5000))
server.listen(1)
print("Cloud starting...")
print("Waiting for edge...")

client_conn, addr = server.accept()
print("Connected:", addr)

data = recv_msg(client_conn)
kem = oqs.KeyEncapsulation("ML-KEM-768", secret_key)
shared_secret = kem.decap_secret(pickle.loads(data)["kem_cipher"])
session_key = derive_key(shared_secret, info=b"transport")
print("Session established")

while True:
    data = recv_msg(client_conn)
    if not data:
        break
    packet = pickle.loads(data)
    iv        = packet["iv"]
    ciphertext = packet["ciphertext"]
    signature  = packet["signature"]
    print("ciphertext size:", len(ciphertext))
    print("signature size:", len(signature))
    plaintext = aes_decrypt(session_key, iv, ciphertext)
    t0 = time.time()
    valid = verify_signature(plaintext, signature, edge_pub)
    print("DSA Verification time (ms):", (time.time() - t0) * 1000)
    if not valid:
        print("[!] Invalid signature — discarding packet")
        continue
    sensor_data = json.loads(plaintext.decode())
    print("End-to-End Latency (ms):", (time.time() - sensor_data["timestamp"]) * 1000)
    sensor_data.pop("timestamp", None)
    plaintext_db = json.dumps(sensor_data).encode()
    iv_db, ciphertext_db = aes_encrypt(db_key, plaintext_db)
    cursor.execute("INSERT INTO sensor_data (iv, ciphertext) VALUES (%s, %s)", (iv_db.hex(), ciphertext_db.hex()))
    conn.commit()
    print("Verified. Stored data:", plaintext_db)

client_conn.close()
