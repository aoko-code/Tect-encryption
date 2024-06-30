#create a function
def caesar_cipher(text, shift, mode='encrypt'):
    result = ""
    for char in text:
        if char.isalpha():
            ascii_offset = 65
            if mode == "encrypt":
                shifted = (ord(char) - ascii_offset + shift) % 26
            else:
                shifted = (ord(char) - ascii_offset - shift) % 26
            result += chr(shifted + ascii_offset)
        else:
            result += char
    return result
plaintext = "HELLO WORLD!"
shift = 3

encrypted = caesar_cipher(plaintext, shift, 'encrypt')
print(f"Encrypted: {encrypted}")

decrypted = caesar_cipher(encrypted, shift, 'dencrypt')
print(f"Dencrypted: {decrypted}")

