# 
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes
import os

# Encryption function
def encrypt_file(plaintext_file, ciphertext_file, key, mode, iv):
    cipher = AES.new(key, mode, iv)
    with open(plaintext_file, 'rb') as f_in:
        plaintext = f_in.read()
        ciphertext = cipher.encrypt(pad(plaintext, AES.block_size))
    with open(ciphertext_file, 'wb') as f_out:
        f_out.write(ciphertext)

# Corruption function
def corrupt_bit(ciphertext_file):
    with open(ciphertext_file, 'r+b') as f:
        f.seek(54)  # Assuming the 55th byte is at index 54 (zero-based indexing)
        byte = f.read(1)
        byte = bytes([byte[0] ^ 0x01])  # Flip a single bit
        f.seek(54)
        f.write(byte)

# Decryption function
def decrypt_file(ciphertext_file, decrypted_file, key, mode, iv):
    cipher = AES.new(key, mode, iv)
    with open(ciphertext_file, 'rb') as f_in:
        ciphertext = f_in.read()
        decrypted = cipher.decrypt(ciphertext)
        decrypted = unpad(decrypted, AES.block_size)
    with open(decrypted_file, 'wb') as f_out:
        f_out.write(decrypted)

# Generate a random key and IV
key = get_random_bytes(16)  # 16 bytes (128 bits) key
iv = get_random_bytes(AES.block_size)

# Step 1: Create a plaintext file
plaintext_file = 'plaintext.txt'
with open(plaintext_file, 'wb') as f:
    f.write(os.urandom(1000))  # Generate 1000 random bytes

# Step 2: Encrypt the plaintext file
ciphertext_file = 'ciphertext.bin'
encrypt_file(plaintext_file, ciphertext_file, key, AES.MODE_ECB, iv)

# Step 3: Corrupt a single bit in the ciphertext
corrupt_bit(ciphertext_file)

# Step 4: Decrypt the corrupted ciphertext file using different modes
decrypted_file_ecb = 'decrypted_ecb.txt'
decrypt_file(ciphertext_file, decrypted_file_ecb, key, AES.MODE_ECB, iv)

decrypted_file_cbc = 'decrypted_cbc.txt'
decrypt_file(ciphertext_file, decrypted_file_cbc, key, AES.MODE_CBC, iv)

decrypted_file_cfb = 'decrypted_cfb.txt'
decrypt_file(ciphertext_file, decrypted_file_cfb, key, AES.MODE_CFB, iv)

decrypted_file_ofb = 'decrypted_ofb.txt'
decrypt_file(ciphertext_file, decrypted_file_ofb, key, AES.MODE_OFB, iv)

# Print the contents of the decrypted files
print('Decrypted ECB:', open(decrypted_file_ecb, 'r').read())
print('Decrypted CBC:', open(decrypted_file_cbc, 'r').read())
print('Decrypted CFB:', open(decrypted_file_cfb, 'r').read())
print('Decrypted OFB:', open(decrypted_file_ofb, 'r').read())
