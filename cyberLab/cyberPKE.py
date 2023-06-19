import os
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

def encrypt_file(input_file, output_file, key, iv):
    backend = default_backend()
    cipher = Cipher(algorithms.AES(key), modes.OFB(iv), backend=backend)
    encryptor = cipher.encryptor()
    with open(input_file, 'rb') as file_in, open(output_file, 'wb') as file_out:
        while True:
            chunk = file_in.read(16)
            if len(chunk) == 0:
                break
            elif len(chunk) % 16 != 0:
                chunk += b' ' * (16 - (len(chunk) % 16))  # Padding with spaces
            ciphertext = encryptor.update(chunk)
            file_out.write(ciphertext)

def decrypt_file(input_file, output_file, key, iv):
    backend = default_backend()
    cipher = Cipher(algorithms.AES(key), modes.OFB(iv), backend=backend)
    decryptor = cipher.decryptor()
    with open(input_file, 'rb') as file_in, open(output_file, 'wb') as file_out:
        while True:
            chunk = file_in.read(16)
            if len(chunk) == 0:
                break
            decrypted_chunk = decryptor.update(chunk)
            file_out.write(decrypted_chunk)


# Step 1: Create a text file of at least 1000 bytes
content = "Lorem ipsum dolor sit amet, consectetur adipiscing elit. " * 50  # 1600 bytes
with open('plaintext.txt', 'w') as file:
    file.write(content)

# Step 2: Encrypt the file using AES-128 cipher
key = os.urandom(16)
iv = os.urandom(16)
encrypt_file('plaintext.txt', 'ciphertext.txt', key, iv)

# Step 3: Corrupt a single bit in the 55th byte of the encrypted file
with open('ciphertext.txt', 'r+b') as file:
    file.seek(54)
    byte = file.read(1)
    corrupted_byte = bytes([byte[0] ^ 0x01])  # Flip the least significant bit
    file.seek(54)
    file.write(corrupted_byte)

# Step 4: Decrypt the corrupted ciphertext file
decrypt_file('ciphertext.txt', 'decrypted.txt', key, iv)

# Check the recovered information
with open('decrypted.txt', 'r') as file:
    recovered_content = file.read()
    print(recovered_content)
