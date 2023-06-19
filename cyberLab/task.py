from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Util import Counter
import base64
import os

# Step 1: Create a text file that is at least 1000 bytes long
file_name = "plaintext.txt"
text = "This is a sample plaintext file with more than 1000 bytes. " \
       "It is used for the Secret-Key Encryption Lab."
with open(file_name, "w") as file:
    file.write(text * 50)

# Step 2: Encrypt the file using AES-128 cipher
key = os.urandom(16)  # Generate a random key
iv = os.urandom(16)  # Generate a random IV

# ECB encryption
ecb_cipher = AES.new(key, AES.MODE_ECB)
with open(file_name, "rb") as file:
    plaintext = file.read()
ciphertext_ecb = ecb_cipher.encrypt(pad(plaintext, AES.block_size))

# CBC encryption
cbc_cipher = AES.new(key, AES.MODE_CBC, iv)
ciphertext_cbc = cbc_cipher.encrypt(pad(plaintext, AES.block_size))

# CFB encryption
cfb_cipher = AES.new(key, AES.MODE_CFB, iv)
ciphertext_cfb = cfb_cipher.encrypt(plaintext)

# OFB encryption
ofb_cipher = AES.new(key, AES.MODE_OFB, iv)
ciphertext_ofb = ofb_cipher.encrypt(plaintext)

# Step 3: Corrupt a single bit in the 55th byte of the ciphertext
corrupted_byte_position = 54  # Zero-based index
corrupted_bit_position = 2  # Zero-based index
ciphertext_ecb = bytearray(ciphertext_ecb)
ciphertext_cbc = bytearray(ciphertext_cbc)
ciphertext_cfb = bytearray(ciphertext_cfb)
ciphertext_ofb = bytearray(ciphertext_ofb)

# Flip the corrupted bit
ciphertext_ecb[corrupted_byte_position] ^= (1 << corrupted_bit_position)
ciphertext_cbc[corrupted_byte_position] ^= (1 << corrupted_bit_position)
ciphertext_cfb[corrupted_byte_position] ^= (1 << corrupted_bit_position)
ciphertext_ofb[corrupted_byte_position] ^= (1 << corrupted_bit_position)

# Step 4: Decrypt the corrupted ciphertext files
decipher_ecb = AES.new(key, AES.MODE_ECB)
decipher_cbc = AES.new(key, AES.MODE_CBC, iv)
decipher_cfb = AES.new(key, AES.MODE_CFB, iv)
decipher_ofb = AES.new(key, AES.MODE_OFB, iv)

decrypted_ecb = unpad(decipher_ecb.decrypt(ciphertext_ecb), AES.block_size)
decrypted_cbc = unpad(decipher_cbc.decrypt(ciphertext_cbc), AES.block_size)
decrypted_cfb = decipher_cfb.decrypt(ciphertext_cfb)
decrypted_ofb = decipher_ofb.decrypt(ciphertext_ofb)

# Decode the decrypted outputs from base64
decrypted_ecb = base64.b64encode(decrypted_ecb).decode()
decrypted_cbc = base64.b64encode(decrypted_cbc).decode()
decrypted_cfb = base64.b64encode(decrypted_cfb).decode()
decrypted_ofb = base64.b64encode(decrypted_ofb).decode()

# Print the decrypted outputs
print("ECB Decryption:")
print(decrypted_ecb)
print("\nCBC Decryption:")
print(decrypted_cbc)
print("\nCFB Decryption:")
print(decrypted_cfb)
print("\nOFB Decryption:")
print(decrypted_ofb)



# ECB: Most of the information can be recovered, except for the block that contains the corrupted bit.
# CBC: The corrupted bit affects the decrypted output of the corresponding block and all subsequent blocks, resulting in a loss of information.
# CFB: The corrupted bit affects the decrypted output of the corresponding block only, while the rest of the information can be recovered.
# OFB: Similar to CFB, the corrupted bit only affects the decrypted output of the corresponding block, allowing the recovery of information in subsequent blocks.