import socket
import struct
import pickle
import oqs
import json
import time
import threading
from hkdf_util import derive_key
from symmetric import aes_encrypt
from symmetric import aes_decrypt
from dsa_util import sign_message
from net_util import send_msg
from net_util import recv_msg

HOST       = input("Enter Cloud IP: ")
PORT       = 5000
TIER1_PORT = 4000

PK_LEN  = 800
CT_LEN  = 768
IV_LEN  = 12
TAG_LEN = 16

MSG_HANDSHAKE_ACK = 0x02
MSG_DATA          = 0x03

PAYLOAD_FMT_DHT22 = "<ffI"
PAYLOAD_FMT_SOIL  = "<ifI"

with open("edge_public_512.key", "rb") as f:
    edge_public_512 = f.read()
with open("edge_secret_512.key", "rb") as f:
    edge_secret_512 = f.read()
with open("cloud_public.key", "rb") as f:
    pub = f.read()
with open("edge_dsa_secret.key", "rb") as f:
    dsa_secret = f.read()

client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
client.connect((HOST, PORT))

kem = oqs.KeyEncapsulation("ML-KEM-768")
kem_cipher, shared_secret = kem.encap_secret(pub)
session_key = derive_key(shared_secret, info=b"transport")
send_msg(client, pickle.dumps({"kem_cipher": kem_cipher}))
print("Cloud session established")

def recv_exact(sock, n):
    buf = b""
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            raise ConnectionError("disconnected")
        buf += chunk
    return buf

def forward_to_cloud(data):
    plaintext = json.dumps(data).encode()
    t0 = time.perf_counter()
    signature = sign_message(plaintext, dsa_secret)
    print(f"[BENCH] ML-DSA Sign: {(time.perf_counter() - t0) * 1000:.4f} ms")
    iv, ciphertext = aes_encrypt(session_key, plaintext)
    send_msg(client, pickle.dumps({"iv": iv, "ciphertext": ciphertext, "signature": signature}))
    print("Forwarded to cloud:", data)

def handle_sensor(conn, addr):
    print(f"\n[+] Sensor connected from {addr}")
    try:
        conn.sendall(edge_public_512)
        print("[*] Public key sent to ESP32")
        ct = recv_exact(conn, CT_LEN)
        print("[*] KEM ciphertext received — decapsulating...")
        kem_sensor = oqs.KeyEncapsulation("Kyber512", edge_secret_512)
        t0 = time.perf_counter()
        shared_secret_t1 = kem_sensor.decap_secret(ct)
        print(f"[BENCH] Kyber512 Decap: {(time.perf_counter() - t0) * 1000:.4f} ms")
        print(f"[DEBUG] Raw shared secret: {shared_secret_t1[:8].hex()}")
        session_key_t1 = derive_key(shared_secret_t1, info=b"tier1")
        print(f"[+] Session key: {session_key_t1[:8].hex()}...")
        conn.sendall(bytes([MSG_HANDSHAKE_ACK]))
        print("[+] ACK sent — waiting for sensor data...\n")
        expected_seq = 0
        while True:
            msg_type = recv_exact(conn, 1)[0]
            if msg_type != MSG_DATA:
                print(f"[!] Unknown msg type: 0x{msg_type:02X}")
                continue
            seq     = struct.unpack("<I", recv_exact(conn, 4))[0]
            pkt_len = struct.unpack("<H", recv_exact(conn, 2))[0]
            enc_buf = recv_exact(conn, pkt_len)
            if seq != expected_seq:
                print(f"[!] Seq mismatch: got {seq} expected {expected_seq}")
            expected_seq = seq + 1
            iv         = enc_buf[:IV_LEN]
            ciphertext = enc_buf[IV_LEN:-TAG_LEN]
            tag        = enc_buf[-TAG_LEN:]
            from cryptography.hazmat.primitives.ciphers.aead import AESGCM
            plaintext = AESGCM(session_key_t1).decrypt(iv, ciphertext + tag, None)
            recv_timestamp = time.time()
            dht22_size = struct.calcsize(PAYLOAD_FMT_DHT22)
            if len(plaintext) == dht22_size:
                temp, humidity, ts_ms = struct.unpack(PAYLOAD_FMT_DHT22, plaintext)
                data = {"sensor": "dht22", "temperature": round(temp, 1), "humidity": round(humidity, 1), "timestamp": recv_timestamp}
                print(f"[{ts_ms:8d}ms] seq={seq} | Temp: {temp:.1f}C  Humidity: {humidity:.1f}%")
            else:
                raw, voltage, ts_ms = struct.unpack_from(PAYLOAD_FMT_SOIL, plaintext)
                data = {"sensor": "soil", "raw": raw, "voltage": round(voltage, 1), "timestamp": recv_timestamp}
                print(f"[{ts_ms:8d}ms] seq={seq} | Soil raw: {raw}  Voltage: {voltage:.1f}mV")
            forward_to_cloud(data)
    except (ConnectionError, struct.error) as e:
        print(f"[-] {addr} disconnected: {e}")
    finally:
        conn.close()

sensor_server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
sensor_server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
sensor_server.bind(("0.0.0.0", TIER1_PORT))
sensor_server.listen(5)
print(f"[*] Waiting for sensors on port {TIER1_PORT}...")

while True:
    conn, addr = sensor_server.accept()
    print(f"[+] Sensor connected: {addr}")
    threading.Thread(target=handle_sensor, args=(conn, addr), daemon=True).start()
