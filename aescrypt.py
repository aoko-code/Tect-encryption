from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Util.Padding import pad, unpad
import binascii
import getpass

# mode = input("Enter the mode(encrypt/ decrypt): ")
# password = getpass.getpass("Enter the password: ")

def derive_key(password, salt):
    return PBKDF2(password, salt, dkLen=32)

def encrypt(message, password):
    salt = get_random_bytes(16)
    key = derive_key(password, salt)
    init_vector = get_random_bytes(16)
    cipher = AES.new(key, AES.MODE_CBC, init_vector)
    cipher_text = cipher.encrypt(pad(message.encode(), AES.block_size))
    return salt + init_vector + cipher_text

def decrypt(encrypted_hex, password):
    encrypted_bytes = binascii.unhexlify(encrypted_hex)
    salt = encrypted_bytes[:16]
    init_vector = encrypted_bytes[16:32]
    key = derive_key(password, salt)

    cipher = AES.new(key, AES.MODE_CBC, init_vector)
    decrypted = unpad(cipher.decrypt(encrypted_bytes[32:]), AES.block_size)

    return decrypted.decode()


# if mode.lower() == 'encrypt':
#     message = input("Enter the message to encrypt: ")
#     encrypted = encrypt(message, password)
#     print(f"message: {message}")
#     print(f"Encrypted (hex): {encrypted.hex()}")
# elif mode.lower() == 'decrypt':
#     encrypted_hex = input("Enter the encrypted message to decrypt: ")
#     try:
#         decrypted = decrypt(encrypted_hex, password)
#         print(f"Decrypted message: {decrypted}")
#     except(ValueError, KeyError):
#         print("Failed! Incorrect password or corrupt ciphertext")
# else:
#     print("please enter the correct mode")
