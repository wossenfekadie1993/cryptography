# Generating a text file with random data
import os

file_path = "plaintext.txt"

# Generate 1000 bytes of random data
data = os.urandom(1000)

# Write the data to a file
with open(file_path, "wb") as file:
    file.write(data)

print("Plaintext file created:", file_path)
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding
import os

def encrypt_AES_CBC(key, iv, plaintext):
    backend = default_backend()
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=backend)
    encryptor = cipher.encryptor()

    padder = padding.PKCS7(128).padder()
    padded_plaintext = padder.update(plaintext) + padder.finalize()

    ciphertext = encryptor.update(padded_plaintext) + encryptor.finalize()
    return ciphertext

# Read the plaintext from the file
with open("plaintext.txt", "rb") as file:
    plaintext = file.read()

# Generate a random 128-bit key
key = os.urandom(16)

# Generate a random 128-bit IV (Initialization Vector)
iv = os.urandom(16)

# Encrypt the plaintext
ciphertext = encrypt_AES_CBC(key, iv, plaintext)

# Write the ciphertext to a file
with open("encrypted_file.bin", "wb") as file:
    file.write(ciphertext)

print("File encrypted successfully!")


def decrypt_AES_CBC(key, iv, ciphertext):
    backend = default_backend()
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=backend)
    decryptor = cipher.decryptor()

    decrypted_padded = decryptor.update(ciphertext) + decryptor.finalize()
    unpadder = padding.PKCS7(128).unpadder()
    decrypted_data = unpadder.update(decrypted_padded) + unpadder.finalize()

    return decrypted_data

# Read the corrupted ciphertext from the file
with open("encrypted_file.bin", "rb") as file:
    corrupted_ciphertext = file.read()

# Decrypt the corrupted ciphertext
decrypted_text = decrypt_AES_CBC(key, iv, corrupted_ciphertext)

# Write the decrypted plaintext to a file
with open("decrypted_file.txt", "wb") as file:
    file.write(decrypted_text)

print("File decrypted successfully!")
