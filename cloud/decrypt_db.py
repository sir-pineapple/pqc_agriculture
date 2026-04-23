import psycopg2
import json

from symmetric import aes_decrypt

conn = psycopg2.connect(
    dbname = "pqc_agriculture",
    user = "pragya",
    host = "/tmp"
)

cursor = conn.cursor()

with open("db_key.bin", "rb") as f:
    db_key = f.read()

cursor.execute('''
               select id, iv, ciphertext
               from sensor_data
               order by id desc;
               ''')
rows = cursor.fetchall()

print("Decrypted data:")

for row in rows:
    _id, iv_hex, ct_hex = row
    iv = bytes.fromhex(iv_hex)
    ciphertext = bytes.fromhex(ct_hex)
    try:
        plaintext = aes_decrypt(db_key, iv, ciphertext)
        data = json.loads(plaintext.decode())
        print(f"[{_id}] ->", data)
    except Exception as e:
        print(f"[{_id}] Decryption failed:", e)

conn.close()
