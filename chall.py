import os
from hashlib import sha256
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
from secrets import extract_id, generate_new_key, PLAINTEXT_1, PLAINTEXT_2, FLAG

BLOCK_SIZE = 16

def crhf(k, p):
    block_cipher = AES.new(k, AES.MODE_ECB).encrypt(p)
    return bytes(x ^ y for x, y in zip(block_cipher, k))

def encrypt_plaintext(k, p, plaintext):
    c = AES.new(k, AES.MODE_CBC, p).encrypt(pad(plaintext.encode("utf-8"), BLOCK_SIZE))
    return c

def encrypt_flag():
    id1 = extract_id(PLAINTEXT_1).encode()
    id2 = extract_id(PLAINTEXT_2).encode()

    key = sha256(id1).digest()[:BLOCK_SIZE]
    iv = sha256(id2).digest()[:BLOCK_SIZE]

    return AES.new(key, AES.MODE_CBC, iv).encrypt(pad(FLAG.encode("utf-8"), BLOCK_SIZE))

def main():
    k1 = os.urandom(BLOCK_SIZE)
    p1 = os.urandom(BLOCK_SIZE)
    
    c1 = encrypt_plaintext(k1, p1, PLAINTEXT_1)
    h1 = crhf(k1, p1)

    xor_delta = os.urandom(BLOCK_SIZE)
    k2, p2 = generate_new_key(k1, p1, xor_delta)

    c2 = encrypt_plaintext(k2, p2, PLAINTEXT_2)
    h2 = crhf(k2, p2)

    c3 = encrypt_flag()

    print((k1 + xor_delta).hex())
    print((h1 + c1).hex())
    print((h2 + c2).hex())
    print(c3.hex())

if __name__ == "__main__":
    main()
