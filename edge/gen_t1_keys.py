import oqs
import time

ALG = "ML-KEM-512"

def main():
    print("Generating Tier1 ML-KEM-512 keypair...")
    kem = oqs.KeyEncapsulation(ALG)
    start = time.time()
    public_key = kem.generate_keypair()
    secret_key = kem.export_secret_key()
    end = time.time()
    print("Key Generation time (ms):", (end-start)*1000)
    with open("edge_public_512.key", "wb") as f:
        f.write(public_key)
    with open("edge_secret_512.key", "wb") as f:
        f.write(secret_key)
    print("Keys generated successfully!")
    print("Public key: edge_public_512.key")
    print("Secret key: edge_secret_512.key")

if __name__ == "__main__":
    main()

