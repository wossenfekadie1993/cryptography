from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes
import os

# Function to encrypt a file using the specified mode
def encrypt_file(input_file, output_file, key, mode, iv=None):
    cipher = AES.new(key, mode, iv)
    with open(input_file, 'rb') as file:
        plaintext = file.read()
        ciphertext = cipher.encrypt(pad(plaintext, AES.block_size))
    with open(output_file, 'wb') as file:
        file.write(ciphertext)

# Function to decrypt a file using the specified mode
def decrypt_file(input_file, output_file, key, mode, iv=None):
    cipher = AES.new(key, mode, iv)
    with open(input_file, 'rb') as file:
        ciphertext = file.read()
        plaintext = unpad(cipher.decrypt(ciphertext), AES.block_size)
    with open(output_file, 'wb') as file:
        file.write(plaintext)

# Step 1: Create a text file that is at least 1000 bytes long
text = 'Lorem ipsum dolor sit amet, consectetur adipiscing elit. ' * 100
with open('plaintext.txt', 'w') as file:
    file.write(text)

# Generate a random key and IV
key = get_random_bytes(AES.block_size)
iv = get_random_bytes(AES.block_size)

# Step 2: Encrypt the file using CBC mode
encrypt_file('plaintext.txt', 'encrypted_cbc.txt', key, AES.MODE_CBC, iv)

# Step 3: Corrupt a single bit of the 55th byte in the encrypted file
with open('encrypted_cbc.txt', 'rb') as file:
    ciphertext = bytearray(file.read())
    ciphertext[54] = ciphertext[54] ^ 1  # Flip a single bit

with open('corrupted_cbc.txt', 'wb') as file:
    file.write(ciphertext)

# Step 4: Decrypt the corrupted CBC ciphertext file using the correct key and IV
decrypt_file('corrupted_cbc.txt', 'decrypted_cbc.txt', key, AES.MODE_CBC, iv)

# Print the decrypted content
with open('decrypted_cbc.txt', 'r') as file:
    decrypted_text = file.read()
    print('Decrypted Content (CBC):')
    print(decrypted_text)

# Step 5: Encrypt the file using CFB mode
encrypt_file('plaintext.txt', 'encrypted_cfb.txt', key, AES.MODE_CFB, iv)

# Step 6: Corrupt a single bit of the 55th byte in the encrypted file
with open('encrypted_cfb.txt', 'rb') as file:
    ciphertext = bytearray(file.read())
    ciphertext[54] = ciphertext[54] ^ 1  # Flip a single bit

with open('corrupted_cfb.txt', 'wb') as file:
    file.write(ciphertext)

# Step 7: Decrypt the corrupted CFB ciphertext file using the correct key and IV
decrypt_file('corrupted_cfb.txt', 'decrypted_cfb.txt', key, AES.MODE_CFB, iv)

# Print the decrypted content
with open('decrypted_cfb.txt', 'r') as file:
    decrypted_text = file.read()
    print('Decrypted Content (CFB):')
    print(decrypted_text)

# Step 8: Encrypt the file using OFB mode
encrypt_file('plaintext.txt', 'encrypted_ofb.txt', key, AES.MODE_OFB, iv)

# Step 9: Corrupt a single bit of the 55th byte in the encrypted file
with open('encrypted_ofb.txt', 'rb') as file:
    ciphertext = bytearray(file.read())
    ciphertext[54] = ciphertext[54] ^ 1  # Flip a single bit

with open('corrupted_ofb.txt', 'wb') as file:
    file.write(ciphertext)

# Step 10: Decrypt the corrupted OFB ciphertext file using the correct key and IV
decrypt_file('corrupted_ofb.txt', 'decrypted_ofb.txt', key, AES.MODE_OFB, iv)

# # Print the decrypted content
# with open('decrypted_ofb.txt', 'r') as file:
#     decrypted_text = file.read()
#     print('Decrypted Content (OFB):')
#     print(decrypted_text)

# Print the decrypted content
with open('decrypted_cbc.txt', 'r', encoding='utf-8') as file:
    decrypted_text = file.read()
    print('Decrypted Content (CBC):')
    print(decrypted_text)

# ...

# Print the decrypted content
with open('decrypted_cfb.txt', 'r', encoding='utf-8') as file:
    decrypted_text = file.read()
    print('Decrypted Content (CFB):')
    print(decrypted_text)

# ...

# Print the decrypted content
with open('decrypted_ofb.txt', 'r', encoding='utf-8') as file:
    decrypted_text = file.read()
    print('Decrypted Content (OFB):')
    print(decrypted_text)
