from flask import Flask, render_template, request, flash
import getpass
from Crypto.Random import get_random_bytes
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import binascii

app = Flask(__name__)
app.secret_key = get_random_bytes(16)


def derive_key(password, salt):
    # Use PBKDF2 to derive a 32-byte (256-bit) key from the password
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

@app.route('/', methods=['GET', 'POST'])
def home():
    if request.method == 'POST':
        mode = request.form['mode']
        password = request.form['password']
        
        if mode.lower() == 'encrypt':
            message = request.form['message']
            encrypted = encrypt(message, password)
            return render_template('result.html', original=message, result=encrypted.hex(), mode=mode)
        
        elif mode == 'decrypt':
            encrypted_hex = request.form['encrypted']
            try:
                decrypted = decrypt(encrypted_hex, password)
                return render_template('result.html', original=encrypted_hex, result=decrypted, mode=mode)
            except (ValueError, KeyError):
                flash("Decryption failed. This could be due to an incorrect password or corrupted ciphertext.")
                return render_template('index.html')
    
    return render_template('index.html')

if __name__ == '__main__':
    app.run(debug=True)



