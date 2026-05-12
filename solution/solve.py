from hashlib import sha256
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad

BLOCK_SIZE = 16
CORRUPTED_ID = "YF4EN5YwjpA"

def xor_bytes(a, b):
    return bytes(x ^ y for x, y in zip(a, b))

def decrypt_cbc(k, iv, c):
    return unpad(AES.new(k, AES.MODE_CBC, iv).decrypt(c), BLOCK_SIZE)

def extract_id(plaintext):
    value = plaintext.split("v=", 1)[1]
    return value.split("}", 1)[0]

if __name__ == "__main__":
    with open("ciphertext.txt", "r", encoding="utf-8") as f:
        lines = [line.strip() for line in f if line.strip()]

    line0 = bytes.fromhex(lines[0])
    k1 = line0[:BLOCK_SIZE]
    delta = line0[BLOCK_SIZE:]
    k2 = xor_bytes(k1, delta)

    line1 = bytes.fromhex(lines[1])
    h1 = line1[:BLOCK_SIZE]
    c1 = line1[BLOCK_SIZE:]

    line2 = bytes.fromhex(lines[2])
    h2 = line2[:BLOCK_SIZE]
    c2 = line2[BLOCK_SIZE:]

    c3 = bytes.fromhex(lines[3])

    p1 = AES.new(k1, AES.MODE_ECB).decrypt(xor_bytes(h1, k1))
    plaintext_1 = decrypt_cbc(k1, p1, c1).decode("utf-8")
    # print("p1:", p1.hex())
    print("Plaintext 1:", plaintext_1)

    k2 = xor_bytes(k1, delta)
    p2 = AES.new(k2, AES.MODE_ECB).decrypt(xor_bytes(h2, k2))
    plaintext_2 = decrypt_cbc(k2, p2, c2).decode("utf-8")
    # print("p2:", p2.hex())
    print("Plaintext 2:", plaintext_2)

    id1 = extract_id(plaintext_1).encode()
    id2 = CORRUPTED_ID.encode()

    key = sha256(id1).digest()[:BLOCK_SIZE]
    iv = sha256(id2).digest()[:BLOCK_SIZE]

    flag = decrypt_cbc(key, iv, c3).decode("utf-8")
    print("Flag:", flag)
