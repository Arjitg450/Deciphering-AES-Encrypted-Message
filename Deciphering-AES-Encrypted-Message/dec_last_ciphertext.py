import os
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

# Set up iv and cipher
iv = b'\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0'

# Convert the key to bytes
key_hex = "8e94635ae87bde371e30e71d3b6b516e"
key = bytes.fromhex(key_hex)

cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
long_decryptor = cipher.decryptor()

# Provide a valid ciphertext for the chosen key size
ciphertext_to_decrypt = bytes.fromhex("ca6889853e3ddfaf621b87ee4966e274")

# Decrypt the ciphertext using the long key
decrypted_with_long_key = long_decryptor.update(ciphertext_to_decrypt) + long_decryptor.finalize()

# Print the result
print("Decrypted with long key:", decrypted_with_long_key.decode('UTF-8', errors='replace'))