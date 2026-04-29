# Post-Quantum Cryptography for Smart Agricultural Security

Post-quantum cryptography applied to a real three-tier IoT pipeline for agricultural sensor data.

---

## Overview

Modern agricultural IoT systems transmit sensitive sensor data across multiple network hops with little to no cryptographic protection. This project secures that pipeline end-to-end using NIST-standardized post-quantum algorithms, implemented on real hardware from sensor node to cloud storage.

The threat model accounts for harvest-now-decrypt-later attacks: an adversary who captures encrypted traffic today could break RSA/ECC-based schemes once sufficiently powerful quantum computers exist. ML-KEM and ML-DSA remain secure against both classical and quantum adversaries.

---

## Architecture

<img width="1024" height="302" alt="image" src="https://github.com/user-attachments/assets/94735382-21e1-4460-acfb-5d7b1fa3b3fc" />
&nbsp;

- **Tier 1 — Sensor Node:** ESP32 microcontroller with DHT22 (temperature/humidity) and FC-28 soil moisture sensor with LM393 comparator. Firmware written in ESP-IDF v6.0 with a custom Kyber512 component stack. Data is signed with ML-DSA-65 and encrypted with AES-256-GCM before transmission.
- **Tier 2 — Edge Gateway:** Raspberry Pi 4 running Python. Decapsulates the KEM session key, verifies the ML-DSA signature, re-encrypts under a fresh ML-KEM-768 session for the cloud hop, and forwards the payload.
- **Tier 3 — Cloud Server:** x86 machine running Python + PostgreSQL. Final decapsulation, signature verification, and storage of plaintext sensor readings.

---

## Cryptographic Stack

| Primitive | Algorithm | Purpose |
|---|---|---|
| Key Encapsulation | ML-KEM-512 | Tier 1 → Tier 2 session key |
| Key Encapsulation | ML-KEM-768 | Tier 2 → Tier 3 session key |
| Digital Signature | ML-DSA-65 | Data authenticity and integrity |
| KDF | HKDF-SHA256 | Session key derivation (salt: `agriculture`, info: `tier1`) |
| Symmetric Encryption | AES-256-GCM | Payload encryption and at-rest storage |

All algorithms are NIST FIPS 203/204 compliant. The ESP32 side uses the PSA Crypto API; the Pi and cloud use liboqs-python.

---

## Hardware

- **Sensor node:** ESP32 DevKit + DHT22 + FC-28 soil moisture sensor (LM393 comparator)
- **Edge gateway:** Raspberry Pi 4 Model B (4 GB)
- **Cloud server:** x86 Linux machine (Arch Linux), PostgreSQL

---

## Getting Started

### ESP32 Firmware

Requirements: ESP-IDF v6.0, `idf.py` on PATH.

```bash
cd Sensors
idf.py build
idf.py -p /dev/ttyUSB0 flash monitor   # Linux
# or: idf.py -p COM7 flash monitor     # Windows
```

> **Important:** Do not set `KYBER_90S=1` in `components/kem/CMakeLists.txt`. That flag switches the ESP32 to AES-256-CTR + SHA2 internals while liboqs on the Pi uses SHAKE/SHA3 — the shared secret will not match and the handshake will silently fail. Always do a clean rebuild after changing any component flags (`idf.py fullclean` first).

### Edge Gateway (Raspberry Pi)

```bash
pip install liboqs-python cryptography
python3 edge/client.py
```

The client connects to the cloud server, completes the ML-KEM-768 handshake, then listens for forwarded sensor packets from the ESP32.

### Cloud Server

Start `server.py` before bringing up the edge client. Ensure PostgreSQL is running and accessible via TCP (`localhost:5432`).

---

## Measured Performance

All values from live pipeline runs on real hardware — no simulated benchmarks.

| Metric | Value |
|---|---|
| ML-KEM-512 Decap (Pi) | 0.28 – 0.48 ms |
| ML-DSA-65 Sign (Pi) | ~2.1 ms avg |
| ML-DSA-65 Verify (Pi) | 0.61 – 1.4 ms |
| Total crypto overhead | < 5 ms |
| End-to-end latency | 670 – 1720 ms |
| ML-DSA signature size | 3309 bytes |
| Encrypted payload size | ~100 bytes |
| Total packet size | ~3459 bytes |

End-to-end latency is dominated by WiFi round-trip time. Cryptographic overhead is under 5 ms at every tier, confirming that PQC is viable for real-time agricultural monitoring.

---

## Known Issues / Notes

- DHT22 requires an 18 ms minimum start pulse and at least 2.5 s between reads. Shorter intervals cause ~50% read failures.
- Multiple sensor threads sharing the edge socket require a `threading.Lock()` on `send_msg()` to prevent packet interleaving.
- If PostgreSQL was upgraded via package manager (Arch Linux), the data directory may need to be re-initialized with `initdb`. Use TCP (`localhost`) rather than Unix socket (`/tmp`) to avoid socket path mismatches.
