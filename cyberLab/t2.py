import subprocess

def encrypt_file(ciphertype, key, iv, input_file, output_file):
    command = [
        'openssl', 'enc', ciphertype, '-e',
        '-in', input_file,
        '-out', output_file,
        '-K', key,
        '-iv', iv
    ]
    subprocess.run(command)

# Example usage
ciphertype = '-aes-128-cbc'
key = '00112233445566778889aabbccddeeff'
iv = '0102030405060708'
input_file = 'plaintext.txt'
output_file = 'cipher.bin'

encrypt_file(ciphertype, key, iv, input_file, output_file)
