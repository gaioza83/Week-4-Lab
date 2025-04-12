import os
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP, AES
from Crypto.Random import get_random_bytes

# STEP 0: Create message.txt
with open("message.txt", "w") as f:
    f.write("This is my secret message for lab 4")

# STEP 1: Generate RSA key pair
key = RSA.generate(2048)
private_key = key.export_key()
public_key = key.publickey().export_key()

with open("private.pem", "wb") as f:
    f.write(private_key)

with open("public.pem", "wb") as f:
    f.write(public_key)

# STEP 2: RSA encryption
with open("message.txt", "rb") as f:
    message = f.read()

public_key_obj = RSA.import_key(open("public.pem").read())
cipher_rsa_enc = PKCS1_OAEP.new(public_key_obj)
rsa_encrypted = cipher_rsa_enc.encrypt(message)

with open("message_rsa_encrypted.bin", "wb") as f:
    f.write(rsa_encrypted)

# STEP 3: RSA decryption
private_key_obj = RSA.import_key(open("private.pem").read())
cipher_rsa_dec = PKCS1_OAEP.new(private_key_obj)
rsa_decrypted = cipher_rsa_dec.decrypt(rsa_encrypted)

with open("message_rsa_decrypted.txt", "wb") as f:
    f.write(rsa_decrypted)

# STEP 4: AES-256 encryption
key_aes = get_random_bytes(32)  # 256-bit key
iv = get_random_bytes(16)       # 128-bit IV
cipher_aes = AES.new(key_aes, AES.MODE_CBC, iv)

# Pad message to AES block size
pad_len = 16 - (len(message) % 16)
message_padded = message + bytes([pad_len] * pad_len)

aes_encrypted = cipher_aes.encrypt(message_padded)

with open("message_aes_encrypted.bin", "wb") as f:
    f.write(aes_encrypted)

with open("aes_key.bin", "wb") as f:
    f.write(key_aes)

with open("aes_iv.bin", "wb") as f:
    f.write(iv)

# STEP 5: AES decryption
cipher_aes_dec = AES.new(key_aes, AES.MODE_CBC, iv)
aes_decrypted_padded = cipher_aes_dec.decrypt(aes_encrypted)

# Remove padding
pad_len = aes_decrypted_padded[-1]
aes_decrypted = aes_decrypted_padded[:-pad_len]

with open("message_aes_decrypted.txt", "wb") as f:
    f.write(aes_decrypted)

# STEP 6: Explanation
explanation = """
RSA vs AES:

RSA is asymmetric and ideal for encrypting small data like keys. It is slower and requires more processing power.
AES is symmetric, much faster, and suited for encrypting large data. In practice, RSA is used to encrypt AES keys,
while AES encrypts the actual data. This hybrid approach combines the benefits of both.

"""

with open("rsa_vs_aes.txt", "w") as f:
    f.write(explanation.strip())


