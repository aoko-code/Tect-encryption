from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Util.Padding import pad, unpad

def derive_key(password, salt):
    # Use PBKDF2 to derive a 32-byte (256-bit) key from the password
    return PBKDF2(password, salt, dkLen=32)

def encrypt(plaintext, password):
    # Generate a random 16-byte salt
    salt = get_random_bytes(16)
    
    # Derive the key from the password and salt
    key = derive_key(password, salt)
    
    # Generate a random 16-byte IV (Initialization Vector)
    iv = get_random_bytes(16)
    
    # Create the cipher object and encrypt
    cipher = AES.new(key, AES.MODE_CBC, iv)
    ciphertext = cipher.encrypt(pad(plaintext.encode(), AES.block_size))
    
    # Return the salt, IV, and ciphertext
    return salt + iv + ciphertext

def decrypt(ciphertext, password):
    # Extract the salt (first 16 bytes)
    salt = ciphertext[:16]
    
    # Extract the IV (next 16 bytes)
    iv = ciphertext[16:32]
    
    # Derive the key from the password and salt
    key = derive_key(password, salt)
    
    # Create the cipher object and decrypt
    cipher = AES.new(key, AES.MODE_CBC, iv)
    decrypted = unpad(cipher.decrypt(ciphertext[32:]), AES.block_size)
    
    return decrypted.decode()

# Example usage
password = "mysecretpassword"
plaintext = "This is a secret message."

# Encrypt the message
encrypted = encrypt(plaintext, password)
print(f"Encrypted (hex): {encrypted.hex()}")

# Decrypt the message
decrypted = decrypt(encrypted, password)
print(f"Decrypted: {decrypted}")